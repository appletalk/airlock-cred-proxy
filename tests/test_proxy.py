"""End-to-end: real proxy, real git over SOCKS5 on the socket, fake GitHub."""
import base64
import json
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import socketserver
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from airlock_cred_proxy import client, config, credentials, server

from . import fakegithub


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="gcp.", dir="/tmp")
        cls.git_root = os.path.join(cls.tmp, "git")
        bare = os.path.join(cls.git_root, "acme", "app.git")
        os.makedirs(bare)
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": cls.tmp}
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", bare], check=True, env=env)
        subprocess.run(["git", "-C", bare, "config", "http.receivepack", "true"], check=True, env=env)
        seed = os.path.join(cls.tmp, "seed")
        subprocess.run(["git", "init", "-q", "-b", "main", seed], check=True, env=env)
        cls.git(seed, "commit", "-q", "--allow-empty", "-m", "seed")
        cls.git(seed, "push", "-q", bare, "main")

        cls.fake = fakegithub.start(cls.git_root)
        base = f"http://127.0.0.1:{cls.fake.server_port}"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        key_path = os.path.join(cls.tmp, "app.pem")
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        cls.sock = os.path.join(cls.tmp, "p.sock")
        cls.audit_path = os.path.join(cls.tmp, "audit.jsonl")
        cls.cfg = config.parse({
            "server": {"socket": cls.sock, "audit_log": cls.audit_path, "api_url": base, "git_url": base,
                       "api_host": "api.github.com", "git_host": "github.com"},
            "identity": {"kind": "github-app", "app_id": 99, "owner": "acme", "key": {"file": key_path}},
            "policy": {"repos": ["acme/app", "acme/other"], "push_branches": ["agent/*"],
                       "merge_denied_bases": ["main"]},
        })
        audit = server.AuditLog(cls.audit_path)
        cred = credentials.build(cls.cfg)
        cls.srv = server.bind(cls.cfg, server.Proxy(cls.cfg, cred, audit))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

        cls.env = client.environment(cls.sock, os.path.join(cls.tmp, "gh"))

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.fake.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def git(cls, cwd, *args, env=None, check=True):
        base = {"PATH": os.environ["PATH"], "HOME": cls.tmp, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        r = subprocess.run(["git", *args], cwd=cwd, env={**base, **(env or {})}, capture_output=True, text=True)
        if check and r.returncode:
            raise AssertionError(f"git {args} failed: {r.stderr}")
        return r

    def api(self, method, path, body=None, headers=None, host="api.github.com"):
        c = client.UnixHTTPConnection(self.sock)
        h = {"Host": host, "Authorization": "token LEAKED-CLIENT-TOKEN", **(headers or {})}
        data = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        out = r.status, r.read()
        c.close()
        return out

    def seen_since(self, n):
        return self.fake.state.seen[n:]

    # ------------------------------------------------------------ identity and credentials

    def test_identity_endpoint(self):
        i = client.local_get(self.sock, "/_airlock-cred-proxy/identity")
        self.assertEqual(i["login"], "test-agent[bot]")
        self.assertEqual(i["email"], "4242+test-agent[bot]@users.noreply.github.com")

    def test_client_authorization_never_reaches_upstream(self):
        n = len(self.fake.state.seen)
        status, _ = self.api("GET", "/repos/acme/app/issues")
        self.assertEqual(status, 200)
        auths = [a for _, _, a in self.seen_since(n)]
        self.assertTrue(auths and all("LEAKED" not in a for a in auths))
        self.assertTrue(all(a.startswith("token ghs_test") for a in auths))

    def test_lowercase_client_authorization_stripped(self):
        n = len(self.fake.state.seen)
        s = socket.socket(socket.AF_UNIX)
        s.connect(self.sock)
        s.sendall(b"GET /repos/acme/app/issues HTTP/1.1\r\nHost: api.github.com\r\n"
                  b"authorization: token LEAKED-LOWER\r\nx-extra: 1\r\n\r\n")
        resp = b""
        while chunk := s.recv(65536):
            resp += chunk
        s.close()
        self.assertTrue(resp.startswith(b"HTTP/1.1 200"), resp[:80])
        auths = [a for _, _, a in self.seen_since(n)]
        self.assertTrue(auths and all("LEAKED" not in a for a in auths), auths)

    def test_read_mints_repo_scoped_read_token(self):
        self.api("GET", "/repos/acme/other/pulls")
        last = self.fake.state.minted[-1]
        self.assertEqual(last["repositories"], ["other"])
        self.assertTrue(all(v == "read" for v in last["permissions"].values()))

    def test_tokens_are_cached(self):
        self.api("GET", "/repos/acme/app/labels")
        n = len(self.fake.state.minted)
        self.api("GET", "/repos/acme/app/labels")
        self.assertEqual(len(self.fake.state.minted), n)

    # ------------------------------------------------------------ REST policy

    def test_repo_outside_policy_is_refused_before_upstream(self):
        n = len(self.fake.state.seen)
        status, body = self.api("GET", "/repos/acme/secret/contents/x")
        self.assertEqual(status, 403)
        self.assertIn(b"repo not in policy", body)
        self.assertEqual(self.seen_since(n), [])

    def test_approval_refused_comment_allowed(self):
        status, body = self.api("POST", "/repos/acme/app/pulls/1/reviews", {"event": "APPROVE"})
        self.assertEqual(status, 403, body)
        status, _ = self.api("POST", "/repos/acme/app/pulls/1/reviews", {"event": "COMMENT", "body": "x"})
        self.assertEqual(status, 200)
        self.assertEqual(self.fake.state.minted[-1]["permissions"]["pull_requests"], "write")

    def test_merge_checks_real_base(self):
        self.fake.state.pulls[("acme/app", 5)] = {"base": "main", "head": "agent/x"}
        self.fake.state.pulls[("acme/app", 6)] = {"base": "agent/base", "head": "agent/y"}
        status, body = self.api("PUT", "/repos/acme/app/pulls/5/merge", {})
        self.assertEqual(status, 403, body)
        self.assertIn(b"protected base", body)
        status, _ = self.api("PUT", "/repos/acme/app/pulls/6/merge", {})
        self.assertEqual(status, 200)

    def test_refusals_reach_a_client_still_sending_its_body(self):
        # 600 KB the proxy has not read when it refuses: without reading it first, the
        # client's write fails with a broken pipe instead of seeing the refusal.
        big = {"config": {"x": "y" * 600000}}
        for _ in range(3):
            self.assertEqual(self.api("POST", "/repos/acme/app/hooks", big)[0], 403)          # policy, after the body reader opened
            self.assertEqual(self.api("POST", "/repos/acme/app/issues", big,
                                      headers={"X-HTTP-Method-Override": "DELETE"})[0], 400)  # before it

    def test_unknown_write_refused(self):
        status, _ = self.api("DELETE", "/repos/acme/app")
        self.assertEqual(status, 403)
        status, _ = self.api("POST", "/repos/acme/app/hooks", {"config": {}})
        self.assertEqual(status, 403)

    def test_non_canonical_paths_refused(self):
        for p in ("/repos/acme/app/../secret/pulls", "/repos/acme/app%2f..%2fsecret", "/repos//acme/app"):
            status, _ = self.api("GET", p)
            self.assertEqual(status, 400, p)

    def test_unknown_host_refused(self):
        status, _ = self.api("GET", "/repos/acme/app", host="uploads.github.com")
        self.assertEqual(status, 403)

    def test_request_smuggling_framing_refused(self):
        s = socket.socket(socket.AF_UNIX)
        s.connect(self.sock)
        s.sendall(b"POST /repos/acme/app/issues HTTP/1.1\r\nHost: api.github.com\r\n"
                  b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
        resp = s.recv(4096)
        s.close()
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:60])

    # ------------------------------------------------------------ GraphQL policy

    def gql(self, query, variables=None):
        return self.api("POST", "/graphql", {"query": query, "variables": variables or {}})

    def test_graphql_query_allowed_with_read_token(self):
        status, _ = self.gql("query { viewer { login } }")
        self.assertEqual(status, 200)
        last = self.fake.state.minted[-1]
        self.assertEqual(sorted(last["repositories"]), ["app", "other"])

    def test_graphql_unlisted_mutation_refused(self):
        status, body = self.gql("mutation { deleteRepository(input:{repositoryId:\"x\"}) { clientMutationId } }")
        self.assertEqual(status, 403)
        self.assertIn(b"deleteRepository", body)

    def test_graphql_approval_via_variable_default_refused(self):
        q = ("mutation($e: PullRequestReviewEvent = APPROVE) "
             "{ addPullRequestReview(input:{pullRequestId:\"P\", event:$e}) { clientMutationId } }")
        status, _ = self.gql(q)
        self.assertEqual(status, 403)

    def test_graphql_non_approval_default_allowed(self):
        q = ("mutation($e: PullRequestReviewEvent = COMMENT) "
             "{ addPullRequestReview(input:{pullRequestId:\"P\", event:$e}) { clientMutationId } }")
        self.assertEqual(self.gql(q)[0], 200)

    def test_graphql_approval_via_aliased_variable_input_refused(self):
        q = "mutation($i: AddPullRequestReviewInput!) { ok: addPullRequestReview(input:$i) { clientMutationId } }"
        status, _ = self.gql(q, {"i": {"pullRequestId": "P", "event": "approve"}})
        self.assertEqual(status, 403)

    def test_graphql_merge_checks_real_base(self):
        self.fake.state.nodes["PR_main"] = {"baseRefName": "main", "nameWithOwner": "acme/app"}
        self.fake.state.nodes["PR_dev"] = {"baseRefName": "dev", "nameWithOwner": "acme/app"}
        q = "mutation($id: ID!) { mergePullRequest(input:{pullRequestId:$id}) { clientMutationId } }"
        self.assertEqual(self.gql(q, {"id": "PR_main"})[0], 403)
        self.assertEqual(self.gql(q, {"id": "PR_dev"})[0], 200)
        self.assertEqual(self.gql(q, {"id": "PR_missing"})[0], 403)

    def test_graphql_subscription_and_duplicate_keys_refused(self):
        self.assertEqual(self.gql("subscription { x }")[0], 403)
        # A parser that keeps the last key sees only the harmless query; one that keeps the first sees the mutation.
        raw = b'{"query": "mutation { deleteRepository(input:{}) { x } }", "query": "query { viewer { login } }"}'
        self.assertEqual(self.api("POST", "/graphql", raw)[0], 403)

    # ------------------------------------------------------------ git over SOCKS5

    def clone(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        self.git(self.tmp, "clone", "-q", "git@github.com:acme/app.git", d, env=self.env)
        return d

    def test_git_clone_and_push_allowed_branch(self):
        d = self.clone()
        self.git(d, "commit", "-q", "--allow-empty", "-m", "work", env=self.env)
        self.git(d, "push", "-q", "origin", "HEAD:refs/heads/agent/test", env=self.env)
        bare = os.path.join(self.git_root, "acme", "app.git")
        refs = self.git(bare, "for-each-ref", "--format=%(refname)").stdout.split()
        self.assertIn("refs/heads/agent/test", refs)
        author = self.git(bare, "log", "-1", "--format=%an <%ae>", "refs/heads/agent/test").stdout.strip()
        self.assertEqual(author, "test-agent[bot] <4242+test-agent[bot]@users.noreply.github.com>")
        push_auth = [a for m, p, a in self.fake.state.seen if m == "POST" and p.endswith("/git-receive-pack")][-1]
        tok = base64.b64decode(push_auth[6:]).decode().split(":", 1)[1]
        self.assertEqual(self.fake.state.tokens[tok]["permissions"]["contents"], "write")
        self.assertEqual(self.fake.state.tokens[tok]["repositories"], ["app"])
        with open(self.audit_path) as f:
            pushes = [json.loads(l) for l in f if "git-receive-pack" in l]
        self.assertTrue(pushes and all(r.get("socks") for r in pushes if r.get("method") == "POST"))

    def test_git_push_to_main_and_tags_refused(self):
        d = self.clone()
        self.git(d, "commit", "-q", "--allow-empty", "-m", "sneak", env=self.env)
        r = self.git(d, "push", "origin", "HEAD:refs/heads/main", env=self.env, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("403", r.stderr)
        r = self.git(d, "push", "origin", "HEAD:refs/tags/v1", env=self.env, check=False)
        self.assertNotEqual(r.returncode, 0)
        bare = os.path.join(self.git_root, "acme", "app.git")
        main = self.git(bare, "rev-parse", "main").stdout.strip()
        self.assertNotEqual(main, self.git(d, "rev-parse", "HEAD").stdout.strip())

    def test_git_mixed_push_refused_whole(self):
        d = self.clone()
        self.git(d, "commit", "-q", "--allow-empty", "-m", "mixed", env=self.env)
        r = self.git(d, "push", "origin", "HEAD:refs/heads/agent/ok2", "HEAD:refs/heads/main",
                     env=self.env, check=False)
        self.assertNotEqual(r.returncode, 0)
        bare = os.path.join(self.git_root, "acme", "app.git")
        refs = self.git(bare, "for-each-ref", "--format=%(refname)").stdout.split()
        self.assertNotIn("refs/heads/agent/ok2", refs)

    def socks(self, host, port=80):
        c = socket.socket(socket.AF_UNIX)
        c.connect(self.sock)
        c.sendall(b"\x05\x01\x00")
        self.assertEqual(c.recv(2), b"\x05\x00")
        h = host.encode()
        c.sendall(b"\x05\x01\x00\x03" + bytes([len(h)]) + h + port.to_bytes(2, "big"))
        return c, c.recv(10)

    def test_socks_refuses_other_hosts_and_tls_port(self):
        for host, port in (("evil.example", 80), ("github.com", 443)):
            c, rep = self.socks(host, port)
            self.assertNotEqual(rep[1], 0, (host, port))
            c.close()

    def test_socks_host_header_must_match_target(self):
        c, rep = self.socks("github.com")
        self.assertEqual(rep[1], 0)
        c.sendall(b"GET /repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        self.assertTrue(c.recv(4096).startswith(b"HTTP/1.1 400"))
        c.close()

    # ------------------------------------------------------------ review round 1 regressions

    def test_graphql_retarget_to_protected_base_refused(self):
        self.fake.state.nodes["PR_x"] = {"baseRefName": "agent/x", "nameWithOwner": "acme/app"}
        q = "mutation($id: ID!, $b: String!) { updatePullRequest(input:{pullRequestId:$id, baseRefName:$b}) { clientMutationId } }"
        self.assertEqual(self.gql(q, {"id": "PR_x", "b": "main"})[0], 403)
        self.assertEqual(self.gql(q, {"id": "PR_x", "b": "refs/heads/main"})[0], 403)
        self.assertEqual(self.gql(q, {"id": "PR_x", "b": "agent/y"})[0], 200)
        q2 = "mutation { updatePullRequest(input:{pullRequestId:\"PR_x\", title:\"t\"}) { clientMutationId } }"
        self.assertEqual(self.gql(q2)[0], 200)

    def test_graphql_auto_merge_refused(self):
        q = "mutation { enablePullRequestAutoMerge(input:{pullRequestId:\"PR_x\"}) { clientMutationId } }"
        self.assertEqual(self.gql(q)[0], 403)

    def test_graphql_duplicate_fields_and_undeclared_variables_refused(self):
        q = "mutation { addPullRequestReview(input:{pullRequestId:\"P\", event:APPROVE, event:COMMENT}) { clientMutationId } }"
        self.assertEqual(self.gql(q)[0], 403)
        q = "mutation { addPullRequestReview(input:{pullRequestId:\"P\", event:$e}) { clientMutationId } }"
        self.assertEqual(self.gql(q, {"e": "APPROVE"})[0], 403)
        self.assertEqual(self.gql(q, {"e": "COMMENT"})[0], 403)

    def test_graphql_deep_nesting_refused_cleanly(self):
        status, body = self.gql("query {" + "a{" * 3000 + "b" + "}" * 3000 + "}")
        self.assertEqual(status, 403, body[:200])

    def test_graphql_lookup_null_data_refused(self):
        q = "mutation($id: ID!) { mergePullRequest(input:{pullRequestId:$id}) { clientMutationId } }"
        self.fake.state.nodes_null = True
        try:
            self.assertEqual(self.gql(q, {"id": "PR_main"})[0], 403)
        finally:
            self.fake.state.nodes_null = False

    def test_query_string_and_method_override_on_writes_refused(self):
        self.assertEqual(self.api("POST", "/repos/acme/app/pulls/1/reviews?event=APPROVE", {})[0], 400)
        self.assertEqual(self.api("POST", "/repos/acme/app/issues", {"title": "t"},
                                  headers={"X-HTTP-Method-Override": "DELETE"})[0], 400)
        self.assertEqual(self.api("GET", "/repos/acme/app/pulls?state=open")[0], 200)

    def test_archive_downloads_refused(self):
        self.assertEqual(self.api("GET", "/repos/acme/app/tarball/main")[0], 403)
        self.assertEqual(self.api("GET", "/repos/acme/app/zipball")[0], 403)

    def raw(self, data, read=True):
        c = socket.socket(socket.AF_UNIX)
        c.connect(self.sock)
        c.sendall(data)
        out = b""
        if read:
            c.settimeout(10)
            try:
                while chunk := c.recv(65536):
                    out += chunk
            except (ConnectionResetError, BrokenPipeError):
                pass
        c.close()
        return out

    def test_malformed_framing_answered(self):
        for req in (
            "POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: \u00b2\r\n\r\n".encode("utf-8"),
            b"POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nTransfer-Encoding: chunked\r\n\r\n7fffffffffffffff\r\n",
            b"GET /repos/acme/app/\xc2\x9b HTTP/1.1\r\nHost: api.github.com\r\n\r\n",
        ):
            resp = self.raw(req)
            self.assertTrue(resp.startswith(b"HTTP/1.1 4"), (req[:60], resp[:80]))

    def test_oversized_chunk_refused_without_buffering_it(self):
        c = socket.socket(socket.AF_UNIX)
        c.connect(self.sock)
        c.sendall(b"POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nTransfer-Encoding: chunked\r\n\r\n"
                  b"8000000\r\n")
        c.settimeout(10)
        sent = 0
        try:
            while sent < 4 << 20:
                c.sendall(b"x" * 65536)
                sent += 65536
        except (BrokenPipeError, ConnectionResetError):
            pass
        resp = b""
        try:
            resp = c.recv(4096)
        except OSError:
            pass
        c.close()
        self.assertTrue(resp.startswith(b"HTTP/1.1 413"), resp[:80])

    def hold(self, n):
        held = []
        for _ in range(n):
            c = socket.socket(socket.AF_UNIX)
            c.connect(self.sock)
            held.append(c)
        time.sleep(0.3)
        return held

    def busy_reply(self):
        extra = socket.socket(socket.AF_UNIX)
        extra.connect(self.sock)
        extra.settimeout(5)
        try:
            return extra.recv(64)
        finally:
            extra.close()

    def test_per_uid_cap_answers_busy(self):
        held = self.hold(server.MAX_PER_PEER)
        try:
            self.assertTrue(self.busy_reply().startswith(b"HTTP/1.1 503"))
        finally:
            for c in held:
                c.close()
        time.sleep(0.3)
        self.assertEqual(self.api("GET", "/repos/acme/app")[0], 200)
        with open(self.audit_path) as f:
            self.assertIn("too many connections from this uid", f.read())

    def test_global_cap_answers_busy(self):
        old = server.MAX_PER_PEER
        server.MAX_PER_PEER = 10 ** 6
        held = []
        try:
            held = self.hold(server.MAX_CONNECTIONS)
            self.assertTrue(self.busy_reply().startswith(b"HTTP/1.1 503"))
        finally:
            server.MAX_PER_PEER = old
            for c in held:
                c.close()
        time.sleep(0.3)
        self.assertEqual(self.api("GET", "/repos/acme/app")[0], 200)

    def test_dripping_client_loses_its_slot(self):
        old = server.REQUEST_DEADLINE
        server.REQUEST_DEADLINE = 1.5
        try:
            c = socket.socket(socket.AF_UNIX)
            c.connect(self.sock)
            t0 = time.monotonic()
            closed = False
            for b in b"GET /repos/acme/app HTTP/1.1\r\nX-Slow: " + b"a" * 100:
                try:
                    c.sendall(bytes([b]))
                except (BrokenPipeError, ConnectionResetError):
                    closed = True
                    break
                time.sleep(0.2)
                if time.monotonic() - t0 > 6:
                    break
            if not closed:
                c.settimeout(2)
                try:
                    closed = c.recv(1) == b""
                except (ConnectionResetError, TimeoutError, OSError):
                    closed = True
            c.close()
            self.assertTrue(closed)
            self.assertLess(time.monotonic() - t0, 5)
        finally:
            server.REQUEST_DEADLINE = old

    def test_inspection_slots_bounded(self):
        taken = []
        try:
            for _ in range(server.INSPECT_SLOTS):
                self.assertTrue(server._inspect_slots.acquire(blocking=False))
                taken.append(1)
            old = server.INSPECT_WAIT
            server.INSPECT_WAIT = 0.5
            try:
                self.assertEqual(self.gql("query { viewer { login } }")[0], 503)
            finally:
                server.INSPECT_WAIT = old
        finally:
            for _ in taken:
                server._inspect_slots.release()
        self.assertEqual(self.gql("query { viewer { login } }")[0], 200)

    def test_header_names_must_be_tokens(self):
        resp = self.raw(b"POST /repos/acme/app/issues HTTP/1.1\r\nHost: api.github.com\r\n"
                        b"X-HTTP-Method-Override : DELETE\r\nContent-Length: 2\r\n\r\n{}")
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])
        resp = self.raw(b"GET /repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\n X-Folded: x\r\n\r\n")
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])

    # ------------------------------------------------------------ review round 3 regressions

    def test_refused_handshakes_leave_no_threads(self):
        time.sleep(0.3)
        before = threading.active_count()
        for _ in range(40):
            c = socket.socket(socket.AF_UNIX)
            c.connect(self.sock)
            c.sendall(b"\x05\x01\x00\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x50")
            c.settimeout(2)
            try:
                c.recv(64)
            except OSError:
                pass
            c.close()
        time.sleep(0.5)
        self.assertLessEqual(threading.active_count(), before + 1)

    def test_thread_start_failure_releases_slots(self):
        with mock.patch.object(socketserver.ThreadingMixIn, "process_request", side_effect=RuntimeError("no thread")):
            for _ in range(3):
                c = socket.socket(socket.AF_UNIX)
                c.connect(self.sock)
                c.settimeout(2)
                try:
                    c.recv(64)
                except OSError:
                    pass
                c.close()
            time.sleep(0.3)
        self.assertEqual(self.srv._per_peer, {})
        self.assertEqual(self.srv._slots._value, server.MAX_CONNECTIONS)
        self.assertEqual(self.api("GET", "/repos/acme/app")[0], 200)

    def test_slow_uploads_do_not_hold_parse_slots(self):
        slow = []
        old = server.INSPECT_WAIT
        server.INSPECT_WAIT = 1
        try:
            for _ in range(server.INSPECT_SLOTS + 2):
                c = socket.socket(socket.AF_UNIX)
                c.connect(self.sock)
                c.sendall(b"POST /graphql HTTP/1.1\r\nHost: api.github.com\r\nContent-Length: 100\r\n\r\n{")
                slow.append(c)
            time.sleep(0.3)
            self.assertEqual(self.gql("query { viewer { login } }")[0], 200)
        finally:
            server.INSPECT_WAIT = old
            for c in slow:
                c.close()

    def test_header_control_characters_refused(self):
        resp = self.raw(b"GET /repos/acme/app HTTP/1.1\r\nHost: api.github.com\r\nX-Foo: a\x00b\x0bc\r\n\r\n")
        self.assertTrue(resp.startswith(b"HTTP/1.1 400"), resp[:80])

    def test_encoded_inspected_body_refused(self):
        status, _ = self.api("POST", "/graphql", {"query": "query { viewer { login } }"},
                             headers={"Content-Encoding": "br"})
        self.assertEqual(status, 400)

    def test_trailing_slash_refused(self):
        self.assertEqual(self.api("GET", "/repos/acme/app/releases/assets/1/")[0], 400)
        self.assertEqual(self.api("GET", "/repos/acme/app/issues/")[0], 400)

    def test_response_not_sent_under_residual_deadline(self):
        seen = []
        real = server.Proxy.forward

        def spy(px, handler, *a, **kw):
            seen.append(handler.connection.gettimeout())
            return real(px, handler, *a, **kw)

        old = server.REQUEST_DEADLINE
        server.REQUEST_DEADLINE = 3
        try:
            with mock.patch.object(server.Proxy, "forward", spy):
                self.assertEqual(self.api("GET", "/repos/acme/app")[0], 200)
        finally:
            server.REQUEST_DEADLINE = old
        self.assertEqual(seen, [server.CLIENT_TIMEOUT])

    def test_release_asset_download_refused(self):
        self.assertEqual(self.api("GET", "/repos/acme/app/releases/assets/12",
                                  headers={"Accept": "application/octet-stream"})[0], 403)

    def test_audit_log_has_no_tokens(self):
        self.api("GET", "/repos/acme/app/issues")
        time.sleep(0.05)
        with open(self.audit_path) as f:
            text = f.read()
        self.assertIn('"decision":"allow"', text)
        self.assertNotIn("ghs_test", text)
        self.assertNotIn("LEAKED", text)


if __name__ == "__main__":
    unittest.main()
