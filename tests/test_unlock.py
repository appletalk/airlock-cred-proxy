"""Unlock: a credential delivered over the admin socket, held until its deadline. docs/unlock.md"""
import contextlib
import datetime as dt
import io
import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from airlock_cred_proxy import cli, client, config, server, unlock

from . import fakegithub


def pem():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode()


def base_cfg(**over):
    d = {"server": {"socket": "/tmp/x.sock"},
         "identity": {"kind": "token", "token": {"pass": "github/gh_token"}},
         "policy": {"repos": ["*"]},
         "unlock": {"max_lifetime": "10h"}}
    for k, v in over.items():
        if v is None:
            d.pop(k, None)
        else:
            d[k] = v
    return d


class Config(unittest.TestCase):
    def test_pass_source_needs_unlock_and_unlock_needs_pass(self):
        with self.assertRaisesRegex(config.ConfigError, "needs an \\[unlock\\]"):
            config.parse(base_cfg(unlock=None))
        with self.assertRaisesRegex(config.ConfigError, "pass source"):
            config.parse(base_cfg(identity={"kind": "token", "token": {"command": ["true"]}}))

    def test_bad_entry_names_refused(self):
        for e in ["-rf", "a/../b", "../b", ".hidden", "a/.b", "a//b", "a/", "/abs", "a b", "", "a\nb"]:
            with self.assertRaises(config.ConfigError, msg=e):
                config.parse(base_cfg(identity={"kind": "token", "token": {"pass": e}}))
        config.parse(base_cfg(identity={"kind": "token", "token": {"pass": "github/otto-app.pem"}}))

    def test_tier_lifetime_expire_at_and_admin_socket_rules(self):
        with self.assertRaisesRegex(config.ConfigError, "tier"):
            config.parse(base_cfg(identity={"kind": "token", "token": {"pass": "x"}, "tier": "elevated"}))
        with self.assertRaisesRegex(config.ConfigError, "24h"):
            config.parse(base_cfg(unlock={"max_lifetime": "25h"}))
        for bad in ["18", "24:00", "6:00", "18:60", 1800]:
            with self.assertRaisesRegex(config.ConfigError, "HH:MM", msg=bad):
                config.parse(base_cfg(unlock={"max_lifetime": "10h", "expire_at": bad}))
        for bad in ["0h", "10", "h", "-1h", 36000]:
            with self.assertRaises(config.ConfigError, msg=bad):
                config.parse(base_cfg(unlock={"max_lifetime": bad}))
        with self.assertRaisesRegex(config.ConfigError, "unknown keys"):
            config.parse(base_cfg(unlock={"max_lifetime": "10h", "renew": True}))
        with self.assertRaisesRegex(config.ConfigError, "must differ"):
            config.parse(base_cfg(server={"socket": "/tmp/x.sock", "admin_socket": "/tmp/x.sock"}))
        cfg = config.parse(base_cfg(unlock={"max_lifetime": "1h30m", "expire_at": "18:00", "idle": "2h"}))
        self.assertEqual((cfg.unlock.max_lifetime, cfg.unlock.expire_at, cfg.unlock.idle), (5400, (18, 0), 7200))
        self.assertEqual(cfg.admin_socket, "/tmp/x.admin.sock")

    def test_proxy_never_reads_a_pass_source_itself(self):
        cfg = config.parse(base_cfg())
        with self.assertRaisesRegex(config.ConfigError, "delivered by"):
            config.read_source(cfg.token_source)


class Deadline(unittest.TestCase):
    def setUp(self):
        self._tz = os.environ.get("TZ")
        os.environ["TZ"] = "America/Vancouver"
        time.tzset()

    def tearDown(self):
        if self._tz is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = self._tz
        time.tzset()

    def cfg(self, **u):
        return config.parse(base_cfg(unlock={"max_lifetime": "10h", **u}))

    @staticmethod
    def at(y, mo, d, h, mi=0):
        return time.mktime((y, mo, d, h, mi, 0, 0, 0, -1))

    @staticmethod
    def local(ts):
        return time.localtime(ts)[:5]

    def test_max_lifetime(self):
        t = self.at(2026, 9, 30, 8)
        self.assertEqual(unlock.deadline(t, self.cfg()), t + 36000)

    def test_expire_at_later_today_wins(self):
        self.assertEqual(self.local(unlock.deadline(self.at(2026, 9, 30, 9), self.cfg(expire_at="18:00"))),
                         (2026, 9, 30, 18, 0))

    def test_out_of_hours_unlock_falls_back_to_lifetime(self):
        # 19:00 with expire_at 18:00: the next 18:00 is tomorrow, so ten hours wins (05:00).
        self.assertEqual(self.local(unlock.deadline(self.at(2026, 9, 30, 19), self.cfg(expire_at="18:00"))),
                         (2026, 10, 1, 5, 0))

    def test_expire_at_exactly_now_means_tomorrow(self):
        t = self.at(2026, 9, 30, 18)
        self.assertEqual(unlock.deadline(t, self.cfg(expire_at="18:00")), t + 36000)

    def test_expire_at_across_dst_stays_at_local_time(self):
        # 2026-11-01 02:00 PDT -> 01:00 PST. Unlock the evening before with a 24h lifetime.
        cfg = config.parse(base_cfg(unlock={"max_lifetime": "24h", "expire_at": "18:00"}))
        d = unlock.deadline(self.at(2026, 10, 31, 20), cfg)
        self.assertEqual(self.local(d), (2026, 11, 1, 18, 0))

    def test_for_shortens_and_cannot_lengthen(self):
        t = self.at(2026, 9, 30, 8)
        self.assertEqual(unlock.deadline(t, self.cfg(), 7200), t + 7200)
        self.assertEqual(unlock.deadline(t, self.cfg(), 86400), t + 36000)


class FakeCred:
    built = 0

    def __init__(self, cfg, secret):
        if secret != "good":
            raise ValueError("bad secret")
        FakeCred.built += 1
        self.identity = {"login": f"user{FakeCred.built}"}


class Gate(unittest.TestCase):
    def setUp(self):
        self.now = 1_000_000.0
        self.cfg = config.parse(base_cfg(unlock={"max_lifetime": "1h", "idle": "10m"}))
        self.gate = unlock.UnlockGate(self.cfg, clock=lambda: self.now, build=FakeCred)

    def test_locked_at_start(self):
        with self.assertRaises(unlock.Locked):
            self.gate.current()
        self.assertEqual(self.gate.status()["state"], "locked")
        self.assertIsNone(self.gate.identity)

    def test_unlock_then_expiry(self):
        self.gate.unlock("good")
        self.gate.current()
        self.now += 3599
        self.gate.touch()
        self.gate.current()
        self.now += 1
        with self.assertRaisesRegex(unlock.Locked, "expired"):
            self.gate.current()

    def test_idle_lock(self):
        self.gate.unlock("good")
        self.now += 599
        self.gate.current()
        self.now += 1
        with self.assertRaisesRegex(unlock.Locked, "idle"):
            self.gate.current()

    def test_touch_resets_idle(self):
        self.gate.unlock("good")
        self.now += 500
        self.gate.touch()
        self.now += 500
        self.gate.current()

    def test_bad_secret_leaves_state_unchanged(self):
        with self.assertRaises(ValueError):
            self.gate.unlock("bad")
        self.assertEqual(self.gate.status()["state"], "locked")
        self.gate.unlock("good")
        cred = self.gate.current()
        with self.assertRaises(ValueError):
            self.gate.unlock("bad")
        self.assertIs(self.gate.current(), cred)

    def test_lock_drops_the_credential_and_keeps_identity(self):
        self.gate.unlock("good")
        who = self.gate.identity
        self.gate.lock()
        with self.assertRaisesRegex(unlock.Locked, "operator"):
            self.gate.current()
        self.assertEqual(self.gate.identity, who)

    def test_lock_during_unlock_check_wins(self):
        gate = self.gate

        def slow_build(cfg, secret):
            gate.lock("operator locked meanwhile")      # lands while GitHub is being asked
            return FakeCred(cfg, secret)
        gate._build = slow_build
        with self.assertRaisesRegex(unlock.Locked, "while the unlock"):
            gate.unlock("good")
        self.assertEqual(gate.status()["state"], "locked")

    def test_wall_clock_set_back_does_not_extend(self):
        boot = [0.0]
        gate = unlock.UnlockGate(self.cfg, clock=lambda: self.now, build=FakeCred, boot=lambda: boot[0])
        gate.unlock("good")
        self.now -= 86400          # wall clock stepped back a day
        boot[0] += 3600            # an hour really passed
        with self.assertRaisesRegex(unlock.Locked, "expired"):
            gate.current()

    def test_wall_clock_jump_forward_locks_on_next_use(self):
        # Suspend: the boot clock may lag (WSL), the wall clock is checked on every use.
        self.gate.unlock("good")
        self.now += 3600
        with self.assertRaisesRegex(unlock.Locked, "expired"):
            self.gate.current()

    def test_timer_locks_without_traffic(self):
        cfg = config.parse(base_cfg(unlock={"max_lifetime": "1h"}))
        gate = unlock.UnlockGate(cfg, build=FakeCred)
        stop = threading.Event()
        threading.Thread(target=gate.run_timer, args=(stop,), daemon=True).start()
        try:
            gate.unlock("good", for_seconds=1)
            self.assertIsNotNone(gate._cred)
            time.sleep(1.6)
            self.assertIsNone(gate._cred)     # read the field: status() or current() would lock it themselves
        finally:
            stop.set()
            gate._wake.set()


class EndToEnd(unittest.TestCase):
    """Real proxy, real admin socket, real git; a github-app identity whose key arrives at unlock."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="gcpu.", dir="/tmp")
        cls.git_root = os.path.join(cls.tmp, "git")
        bare = os.path.join(cls.git_root, "acme", "app.git")
        os.makedirs(bare)
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": cls.tmp}
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", bare], check=True, env=env)
        cls.fake = fakegithub.start(cls.git_root)
        base = f"http://127.0.0.1:{cls.fake.server_port}"
        cls.key = pem()
        cls.sock = os.path.join(cls.tmp, "p.sock")
        cls.admin = os.path.join(cls.tmp, "p.admin.sock")
        cls.audit_path = os.path.join(cls.tmp, "audit.jsonl")
        cls.cfg = config.parse({
            "server": {"socket": cls.sock, "audit_log": cls.audit_path, "api_url": base, "git_url": base,
                       "api_host": "api.github.com", "git_host": "github.com"},
            "identity": {"kind": "github-app", "app_id": 99, "owner": "acme", "key": {"pass": "github/app.pem"}},
            "policy": {"repos": ["acme/app"], "push_branches": ["agent/*"], "merge_denied_bases": ["main"]},
            "unlock": {"max_lifetime": "1h"},
        })
        audit = server.AuditLog(cls.audit_path)
        cls.gate = unlock.UnlockGate(cls.cfg, audit)
        cls.srv = server.bind(cls.cfg, server.Proxy(cls.cfg, cls.gate, audit))
        cls.adm = server.bind_admin(cls.cfg, cls.gate)
        for s in (cls.srv, cls.adm):
            threading.Thread(target=s.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.adm.shutdown()
        cls.fake.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def setUp(self):
        self.gate.lock("test reset")
        # The test server runs as the test user in a temp dir, which the client's checks
        # rightly refuse; they have their own tests below.
        for name in ("check_admin_path", "check_admin_peer"):
            p = mock.patch.object(client, name, lambda *a: None)
            p.start()
            self.addCleanup(p.stop)

    def do_unlock(self, secret=None):
        return client.admin_call(self.admin, "POST", "/unlock", {"secrets": {"github/app.pem": secret or self.key}})

    def api(self, method, path, body=None, host="api.github.com"):
        c = client.UnixHTTPConnection(self.sock)
        try:
            c.request(method, path, body=body, headers={"Host": host})
            r = c.getresponse()
            return r.status, dict(r.getheaders()), r.read()
        finally:
            c.close()

    def git(self, *args):
        env = {"PATH": os.environ["PATH"], "HOME": self.tmp, "GIT_CONFIG_NOSYSTEM": "1",
               **client.environment(self.sock, os.path.join(self.tmp, "gh"))}
        return subprocess.run(["git", *args], cwd=self.tmp, env=env, capture_output=True, text=True, timeout=60)

    def audit_tail(self):
        with open(self.audit_path) as f:
            return [json.loads(line) for line in f][-1]

    def test_locked_requests_get_423_with_marker(self):
        st, h, body = self.api("GET", "/repos/acme/app/pulls")
        self.assertEqual(st, 423)
        self.assertEqual(h.get("X-Airlock-Cred-Proxy"), "locked")
        self.assertIn(b"airlock-cred-proxy unlock", body)
        self.assertEqual(self.audit_tail()["decision"], "locked")
        st, h, _ = self.api("POST", "/graphql", body=b'{"query":"{viewer{login}}"}')
        self.assertEqual(st, 423)

    def test_locked_wins_over_a_policy_refusal(self):
        # Checked before anything else about the request, so the agent is told to wait, not that it was wrong.
        st, _, _ = self.api("GET", "/repos/acme/elsewhere/pulls")
        self.assertEqual(st, 423)

    def test_health_reports_state_and_identity_waits_for_first_unlock(self):
        self.assertEqual(client.local_get(self.sock, server.HEALTH_PATH)["state"], "locked")
        saved, self.gate.identity = self.gate.identity, None     # as at start: never unlocked
        try:
            with self.assertRaises(client.LockedError):
                client.local_get(self.sock, server.IDENTITY_PATH)
        finally:
            self.gate.identity = saved
        self.assertEqual(self.do_unlock()[0], 200)
        h = client.local_get(self.sock, server.HEALTH_PATH)
        self.assertEqual(h["state"], "unlocked")
        self.assertGreater(h["expires_in"], 3500)
        self.gate.lock()
        self.assertEqual(client.local_get(self.sock, server.IDENTITY_PATH)["login"], "test-agent[bot]")

    def test_unlock_works_and_git_sees_423_when_locked(self):
        r = self.git("ls-remote", "https://github.com/acme/app.git")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("423", r.stderr)
        self.assertIn("remote: airlock-cred-proxy: credential locked", r.stderr)
        st, reply = self.do_unlock()
        self.assertEqual(st, 200, reply)
        self.assertEqual(reply["identity"], "test-agent[bot]")
        self.assertEqual(self.api("GET", "/repos/acme/app/pulls")[0], 200)
        self.assertEqual(self.git("ls-remote", "https://github.com/acme/app.git").returncode, 0)

    def test_wrong_secret_stays_locked(self):
        st, reply = self.do_unlock("not a key")
        self.assertEqual(st, 422, reply)
        self.assertEqual(reply["state"], "locked")
        self.assertEqual(self.api("GET", "/repos/acme/app/pulls")[0], 423)

    def test_no_admin_verb_unlocks_without_the_secret(self):
        for method, path, body in [("POST", "/extend", {}), ("POST", "/renew", {}), ("POST", "/refresh", {}),
                                   ("GET", "/unlock", None), ("PUT", "/unlock", {}),
                                   ("POST", "/unlock", {}), ("POST", "/unlock", {"secrets": {}}),
                                   ("POST", "/unlock", {"secrets": {"github/app.pem": ""}}),
                                   ("POST", "/unlock", {"secrets": {"other": self.key}}),
                                   ("POST", "/unlock", {"for_seconds": 3600})]:
            st, _ = client.admin_call(self.admin, method, path, body)
            self.assertNotEqual(st, 200, (method, path))
            self.assertEqual(self.gate.status()["state"], "locked", (method, path))

    def test_data_socket_has_no_admin_paths(self):
        for host in ("airlock-cred-proxy-admin", "localhost", "api.github.com"):
            for method, path in [("POST", "/unlock"), ("POST", "/lock"), ("GET", "/status")]:
                body = json.dumps({"secrets": {"github/app.pem": self.key}}).encode() if path == "/unlock" else None
                st, _, _ = self.api(method, path, body=body, host=host)
                self.assertNotEqual(st, 200, (host, method, path))
        self.assertEqual(self.gate.status()["state"], "locked")

    def test_lock_drops_minted_tokens(self):
        self.do_unlock()
        self.api("GET", "/repos/acme/app/pulls")
        n = len(self.fake.state.minted)
        self.api("GET", "/repos/acme/app/pulls")
        self.assertEqual(len(self.fake.state.minted), n)       # cached
        client.admin_call(self.admin, "POST", "/lock")
        self.do_unlock()
        self.api("GET", "/repos/acme/app/pulls")
        self.assertGreater(len(self.fake.state.minted), n)     # fresh credential, fresh mint

    def test_in_flight_request_completes_across_a_lock(self):
        self.do_unlock()
        self.fake.state.delay = 1.0
        out = {}
        t = threading.Thread(target=lambda: out.update(r=self.api("GET", "/repos/acme/app/slow")))
        t.start()
        try:
            time.sleep(0.4)
            client.admin_call(self.admin, "POST", "/lock")
            t.join(10)
        finally:
            self.fake.state.delay = 0
        self.assertEqual(out["r"][0], 200)
        self.assertEqual(self.api("GET", "/repos/acme/app/pulls")[0], 423)

    def test_admin_refuses_other_uids(self):
        with mock.patch.object(unlock.AdminHandler, "_peer_uid", return_value=os.getuid() + 1):
            st, reply = self.do_unlock()
        self.assertEqual(st, 403)
        self.assertIn("owner", reply["error"])
        self.assertEqual(self.gate.status()["state"], "locked")

    def test_admin_refuses_a_loose_socket_mode(self):
        os.chmod(self.admin, 0o660)
        try:
            st, reply = self.do_unlock()
        finally:
            os.chmod(self.admin, 0o600)
        self.assertEqual(st, 403)
        self.assertIn("0600", reply["error"])

    def test_upstream_cannot_forge_the_lock_marker(self):
        self.do_unlock()
        st, h, _ = self.api("GET", "/repos/acme/app/marker")
        self.assertEqual(st, 200)
        self.assertNotIn("X-Airlock-Cred-Proxy", h)

    def test_admin_socket_not_bound_by_a_system_account(self):
        with mock.patch.object(os, "getuid", return_value=500), mock.patch.object(client, "login_uid_min",
                                                                                  return_value=1000):
            with self.assertRaisesRegex(SystemExit, "systemd"):
                server.bind_admin(self.cfg, self.gate)

    def test_admin_socket_is_created_0600(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.admin).st_mode), 0o600)

    def test_cli_unlock_reads_only_the_named_entry(self):
        bindir = os.path.join(self.tmp, "bin")
        os.makedirs(bindir, exist_ok=True)
        log = os.path.join(self.tmp, "pass.log")
        keyfile = os.path.join(self.tmp, "key.pem")
        with open(keyfile, "w") as f:
            f.write(self.key)
        with open(os.path.join(bindir, "pass"), "w") as f:
            f.write(f'#!/bin/sh\necho "$*" >> {log}\ncat {keyfile}\n')
        os.chmod(os.path.join(bindir, "pass"), 0o755)
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.dict(os.environ, {"PATH": f"{bindir}:{os.environ['PATH']}"}), \
                contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["unlock", "--socket", self.admin, "--for", "30m"])
        self.assertEqual(rc, 0, err.getvalue())
        self.assertIn("unlocked as test-agent[bot]", out.getvalue())
        with open(log) as f:
            self.assertEqual(f.read(), "show github/app.pem\n")
        self.assertLessEqual(self.gate.status()["expires_in"], 1800)

    def test_cli_refuses_an_operator_owned_admin_socket(self):
        # A box runs as the operator: a socket it serves from a shared dir must not get secrets.
        mock.patch.stopall()
        fake = os.path.join(self.tmp, "fake.admin.sock")
        s = socket.socket(socket.AF_UNIX)
        s.bind(fake)
        s.listen(1)
        try:
            with mock.patch.object(subprocess, "run") as run, contextlib.redirect_stderr(io.StringIO()) as err:
                rc = cli.main(["unlock", "--socket", fake])
            self.assertEqual(rc, 1)
            run.assert_not_called()
            self.assertIn("not owned by root", err.getvalue())
            # The path check alone is not the only guard: the peer check refuses the same socket.
            c = socket.socket(socket.AF_UNIX)
            c.connect(fake)
            with self.assertRaisesRegex(RuntimeError, "not by root or a system account"):
                client.check_admin_peer(c)
            c.close()
        finally:
            s.close()
            os.unlink(fake)

    def test_cli_refuses_a_symlinked_admin_socket(self):
        mock.patch.stopall()
        link = os.path.join(self.tmp, "link.admin.sock")
        os.symlink(self.admin, link)
        try:
            with self.assertRaisesRegex(RuntimeError, "symlink"):
                client.check_admin_path(link)
        finally:
            os.unlink(link)

    def test_cli_refuses_an_invalid_entry_from_the_proxy(self):
        with mock.patch.object(client, "admin_call", return_value=(200, {"entries": ["--help"]})), \
                mock.patch.object(subprocess, "run") as run, \
                contextlib.redirect_stderr(io.StringIO()) as err:
            rc = cli.main(["unlock", "--socket", self.admin])
        self.assertEqual(rc, 1)
        run.assert_not_called()
        self.assertIn("invalid pass entry", err.getvalue())

    def test_env_before_first_unlock_routes_and_refuses_commits(self):
        saved, self.gate.identity = self.gate.identity, None
        try:
            env = client.environment(self.sock, os.path.join(self.tmp, "gh3"))
            with contextlib.redirect_stdout(io.StringIO()) as out:
                self.assertEqual(cli.main(["status", "--socket", self.sock]), 3)
            self.assertIn("no identity yet", out.getvalue())
        finally:
            self.gate.identity = saved
        self.assertIn(self.sock, env["GIT_CONFIG_VALUE_3"])
        self.assertEqual(env["GIT_AUTHOR_NAME"], "")
        repo = os.path.join(self.tmp, "commit-test")
        subprocess.run(["git", "init", "-q", repo], check=True)
        r = subprocess.run(["git", "-C", repo, "-c", "user.name=Someone", "-c", "user.email=s@example.com",
                            "commit", "--allow-empty", "-m", "x"],
                           env={"PATH": os.environ["PATH"], "HOME": self.tmp, **env}, capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("empty ident", r.stderr)

    def test_status_exits_3_when_locked_and_env_still_works(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.main(["status", "--socket", self.sock]), 3)
        self.assertIn("locked", out.getvalue())
        self.do_unlock()
        self.gate.lock()
        with contextlib.redirect_stderr(io.StringIO()) as err, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(cli.main(["env", "--socket", self.sock, "--gh-config-dir",
                                       os.path.join(self.tmp, "gh2")]), 0)
        # env only needs the identity, which outlives a lock; a request is what gets 423.
        self.assertEqual(err.getvalue(), "")


class Dumpable(unittest.TestCase):
    def test_not_dumpable(self):
        code = ("import ctypes; from airlock_cred_proxy import server; server.not_dumpable(); "
                "print(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0))")     # PR_GET_DUMPABLE
        r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=30,
                           env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
        self.assertEqual(r.stdout.strip(), "0", r.stderr)


class Activation(unittest.TestCase):
    CHILD = r'''
import os, socket, sys
from airlock_cred_proxy import config, server
d = sys.argv[1]
names = sys.argv[2]
socks = []
for n in ("a.sock", "b.sock"):
    s = socket.socket(socket.AF_UNIX); s.bind(os.path.join(d, n)); s.listen(4); socks.append(s)
os.dup2(socks[0].fileno(), 3); os.dup2(socks[1].fileno(), 4)
os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS="2", LISTEN_FDNAMES=names)
got = server._systemd_sockets()
print({k: v.getsockname().rsplit("/", 1)[1] for k, v in sorted(got.items())})
'''

    def run_child(self, names):
        d = tempfile.mkdtemp(prefix="gcpa.", dir="/tmp")
        try:
            return subprocess.run([sys.executable, "-c", self.CHILD, d, names], capture_output=True, text=True,
                                  timeout=30, env={**os.environ, "PYTHONPATH": os.path.join(
                                      os.path.dirname(__file__), "..", "src")})
        finally:
            shutil.rmtree(d, ignore_errors=True)

    def test_two_sockets_by_name(self):
        r = self.run_child("admin:data")
        self.assertEqual(r.stdout.strip(), "{'admin': 'a.sock', 'data': 'b.sock'}", r.stderr)

    def test_two_sockets_need_both_names(self):
        r = self.run_child("data:other")
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("FileDescriptorName", r.stderr)


if __name__ == "__main__":
    unittest.main()
