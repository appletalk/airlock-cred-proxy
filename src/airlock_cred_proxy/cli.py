"""airlock-cred-proxy command line."""
import argparse
import collections
import glob
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit

from . import __version__, client, config

UNPRINTABLE = re.compile(r"[^\x20-\x7e]")
ADMIN_GLOB = "/run/airlock-cred-proxy/*.admin.sock"
SHORT_UNLOCK = 30 * 60


def _safe(v) -> str:
    """Audit fields come from clients; never let them drive the terminal."""
    return UNPRINTABLE.sub(lambda m: f"\\x{ord(m.group()):02x}", str(v if v is not None else ""))


def _state_dir():
    return os.path.join(os.environ.get("XDG_STATE_HOME", os.path.expanduser("~/.local/state")), "airlock-cred-proxy")


def cmd_serve(a):
    from . import server
    server.serve(config.load(a.config))


def cmd_check(a):
    cfg = config.load(a.config)
    p = cfg.policy
    print(f"config ok: {a.config}")
    print(f"  identity   {cfg.kind}" + (f" app_id={cfg.app_id} owner={cfg.owner}" if cfg.kind == "github-app" else ""))
    print(f"  socket     {cfg.socket} mode={oct(cfg.socket_mode)} group={cfg.socket_group or '-'}")
    print(f"  hosts      api={cfg.api_host} -> {cfg.api_url}  git={cfg.git_host} -> {cfg.git_url}")
    print(f"  repos      {', '.join(p.repos)}")
    print(f"  perms      {', '.join(f'{k}:{v}' for k, v in sorted(p.permissions.items()))}")
    print(f"  push       branches={p.push_branches or 'none'} tags={p.push_tags}")
    print(f"  approvals  {'denied' if p.deny_approvals else 'allowed'}")
    print(f"  protected  {p.merge_denied_bases or 'none'}" +
          "".join(f"; {r}: {b}" for r, b in p.repo_merge_denied_bases.items()))
    print(f"  mutations  {len(p.mutations)} allowed" + (" (default set)" if p.mutations == config.DEFAULT_MUTATIONS else ""))
    print(f"  projects   {', '.join(sorted(p.projects)) if p.projects is not None else 'any (not pinned)'}")
    print(f"  REST       {'writes allowed by rule' if p.rest_writes else 'reads only'}")
    if cfg.kind == "token":
        print("  note       token identities cannot be narrowed by repo for GraphQL queries; see README")
    if cfg.unlock is not None:
        u = cfg.unlock
        print(f"  unlock     pass entry {cfg.pass_entry}, tier {cfg.tier}, max {u.max_lifetime}s"
              + (f", expires at {u.expire_at[0]:02d}:{u.expire_at[1]:02d}" if u.expire_at else "")
              + (f", idle {u.idle}s" if u.idle else ""))
        print(f"  admin      {cfg.admin_socket}")
        if a.resolve:
            print("credential not resolved: it is delivered by 'airlock-cred-proxy unlock'")
            return
    if a.resolve:
        from . import credentials
        cred = credentials.build(cfg)
        print(f"credential ok: {cred.identity['login']} (id {cred.identity['id']})")
        if cfg.kind == "github-app":
            cred.token(None, p.read_permissions())
            print(f"  installation {cred.installation_id}; read token minted for the policy's repos")


def cmd_explain(a):
    from . import policy        # needs graphql-core; the client commands must not
    cfg = config.load(a.config)
    u = urlsplit(a.url)
    host, path, query = (u.hostname or "").lower(), u.path or "/", u.query
    body = None
    if a.body:
        body = sys.stdin.buffer.read() if a.body == "-" else open(a.body, "rb").read()
    m = a.method.upper()
    if host == cfg.git_host:
        d = policy.git_request(cfg.policy, m, path, query)
        if d.allow and path.endswith("/git-receive-pack") and a.ref:
            d = policy.check_ref_updates(cfg.policy, d.repo, [("0" * 40, "1" * 40, r) for r in a.ref])
    elif host == cfg.api_host:
        d = policy.graphql_request(cfg.policy, body or b"") if (m == "POST" and path == "/graphql") \
            else policy.rest_request(cfg.policy, m, path, body)
    else:
        d = policy.deny(f"host {host!r} is not proxied")
    out = {"allow": d.allow, "reason": d.reason, "repo": d.repo, "access": d.access}
    if d.detail:
        out["detail"] = d.detail
    if d.lookup:
        out["upstream_check"] = d.lookup
    print(json.dumps(out, indent=2))
    return 0 if d.allow else 1


def cmd_status(a):
    try:
        h = client.local_get(a.socket, "/_airlock-cred-proxy/health")
        try:
            i = client.local_get(a.socket, "/_airlock-cred-proxy/identity")
            who = f"{i['login']} (id {i['id']}) api={i['api_host']} git={i['git_host']}"
        except client.LockedError:
            who = "no identity yet"
    except (OSError, RuntimeError) as e:
        print(f"proxy unreachable at {a.socket}: {e}", file=sys.stderr)
        return 1
    state = h.get("state", "static")
    if state == "unlocked":
        state += f" until {h.get('expires_at')} ({h.get('expires_in', 0) // 60} min left)"
    elif state == "locked":
        state += f" ({h.get('reason')}); unlock on the host with 'airlock-cred-proxy unlock'"
    print(f"{h['status']}: {who}\n  credential {state}")
    return 3 if h.get("state") == "locked" else 0


def cmd_env(a):
    try:
        env = client.environment(a.socket, a.gh_config_dir)
    except (OSError, RuntimeError) as e:
        print(f"proxy unreachable at {a.socket}: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(client.shell_exports(env))
    if not env["GIT_AUTHOR_NAME"]:
        print("airlock-cred-proxy: credential locked since the proxy started; git and gh are routed "
              "through it but commits are refused until it is unlocked on the host", file=sys.stderr)


def _admin_sockets(a):
    return a.socket or sorted(glob.glob(ADMIN_GLOB))


def _instance(sock):
    b = os.path.basename(sock)
    return b[:-len(".admin.sock")] if b.endswith(".admin.sock") else b


def _read_pass(entry):
    # The entry name comes from the proxy's config; check it again before it reaches argv.
    if not config.valid_pass_entry(entry):
        raise RuntimeError(f"proxy asked for an invalid pass entry {entry!r}")
    r = subprocess.run(["pass", "show", entry], stdout=subprocess.PIPE, text=True)
    if r.returncode:
        raise RuntimeError(f"'pass show {entry}' exited {r.returncode}")
    return r.stdout


def cmd_unlock(a):
    socks = _admin_sockets(a)
    if not socks:
        print(f"no admin sockets match {ADMIN_GLOB}; name one with --socket", file=sys.stderr)
        return 1
    for_s = config.parse_duration(a.for_, "--for") if a.for_ else None
    read, rc = {}, 0      # entry -> secret, so an entry two instances share is read once
    try:
        for sock in socks:
            name = _instance(sock)
            try:
                st, info = client.admin_call(sock, "GET", "/status")
                if st != 200:
                    raise RuntimeError(info.get("error", f"HTTP {st}"))
                secrets = {}
                for e in info.get("entries") or []:
                    if e not in read:
                        read[e] = _read_pass(e)
                    secrets[e] = read[e]
                body = {"secrets": secrets, **({"for_seconds": for_s} if for_s else {})}
                st, r = client.admin_call(sock, "POST", "/unlock", body)
                if st != 200:
                    raise RuntimeError(r.get("error", f"HTTP {st}"))
                print(f"{name}: unlocked as {_safe(r.get('identity'))} until {_safe(r.get('expires_at'))}")
                if r.get("expires_in", SHORT_UNLOCK) < SHORT_UNLOCK:
                    print(f"{name}: note: that is under {SHORT_UNLOCK // 60} minutes away", file=sys.stderr)
            except (OSError, RuntimeError) as e:
                print(f"{name}: not unlocked: {_safe(e)}", file=sys.stderr)
                rc = 1
    finally:
        read.clear()
    return rc


def cmd_lock(a):
    socks = _admin_sockets(a)
    if not socks:
        print(f"no admin sockets match {ADMIN_GLOB}; name one with --socket", file=sys.stderr)
        return 1
    rc = 0
    for sock in socks:
        try:
            st, r = client.admin_call(sock, "POST", "/lock")
            if st != 200:
                raise RuntimeError(r.get("error", f"HTTP {st}"))
            print(f"{_instance(sock)}: {_safe(r.get('state'))}")
        except (OSError, RuntimeError) as e:
            print(f"{_instance(sock)}: not locked: {_safe(e)}", file=sys.stderr)
            rc = 1
    return rc


def cmd_audit(a):
    counts, shown = collections.Counter(), 0
    with open(a.log) as f:
        for line in f:
            try:
                r = json.loads(line)
            except ValueError:
                continue
            if a.since and r.get("ts", "") < a.since:
                continue
            if a.denied and r.get("decision") not in ("deny", "error"):
                continue
            if not isinstance(r, dict):
                continue
            if a.summary:
                counts[(_safe(r.get("decision")), _safe(r.get("repo")), _safe(r.get("reason")))] += 1
                continue
            print(f"{_safe(r.get('ts'))} {_safe(r.get('decision', r.get('event', '?'))):6} "
                  f"{_safe(r.get('status')):>3} {_safe(r.get('method')):6} "
                  f"{_safe(r.get('host'))}{_safe(r.get('path'))} {_safe(r.get('repo'))} :: {_safe(r.get('reason'))}")
            shown += 1
    if a.summary:
        for (dec, repo, reason), n in counts.most_common():
            print(f"{n:6} {dec or '-':6} {repo or '-':40} {reason}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="airlock-cred-proxy", description=__doc__)
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sd = _state_dir()

    s = sub.add_parser("serve", help="run the proxy (normally under systemd)")
    s.add_argument("--config", required=True)
    s.set_defaults(fn=cmd_serve)

    s = sub.add_parser("check-config", help="validate a config and print the effective policy")
    s.add_argument("--config", required=True)
    s.add_argument("--resolve", action="store_true", help="also load the credential and mint a read token")
    s.set_defaults(fn=cmd_check)

    s = sub.add_parser("explain", help="dry-run the policy for one request (no network)")
    s.add_argument("--config", required=True)
    s.add_argument("method")
    s.add_argument("url", help="e.g. https://api.github.com/repos/o/r/pulls")
    s.add_argument("--body", help="file with the request body, or - for stdin")
    s.add_argument("--ref", action="append", help="for git-receive-pack: a ref being pushed (repeatable)")
    s.set_defaults(fn=cmd_explain)

    s = sub.add_parser("status", help="check a running proxy and show its identity")
    s.add_argument("--socket", required=True)
    s.set_defaults(fn=cmd_status)

    s = sub.add_parser("env", help="print shell exports that route git and gh through the proxy")
    s.add_argument("--socket", required=True)
    s.add_argument("--gh-config-dir", default=os.path.join(sd, "gh"))
    s.set_defaults(fn=cmd_env)

    s = sub.add_parser("unlock", help="on the host: deliver each proxy's pass entries so it can work until its expiry")
    s.add_argument("--socket", action="append", help=f"admin socket (repeatable); default {ADMIN_GLOB}")
    s.add_argument("--for", dest="for_", metavar="DURATION", help="unlock for less than the configured lifetime, e.g. 2h")
    s.set_defaults(fn=cmd_unlock)

    s = sub.add_parser("lock", help="on the host: drop the credential now")
    s.add_argument("--socket", action="append", help=f"admin socket (repeatable); default {ADMIN_GLOB}")
    s.set_defaults(fn=cmd_lock)

    s = sub.add_parser("audit", help="read the audit log")
    s.add_argument("--log", required=True)
    s.add_argument("--denied", action="store_true", help="only refused requests and errors")
    s.add_argument("--since", help="ISO timestamp, e.g. 2030-01-31T00:00:00Z")
    s.add_argument("--summary", action="store_true", help="count by decision, repo and reason")
    s.set_defaults(fn=cmd_audit)

    a = ap.parse_args(argv)
    try:
        return a.fn(a) or 0
    except config.ConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    except ImportError as e:
        print(f"airlock-cred-proxy {a.cmd} needs the full install (pip install -r requirements.lock): {e}",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
