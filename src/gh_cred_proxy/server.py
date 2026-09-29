"""HTTP-over-Unix-socket proxy: authorise each request, attach a scoped credential, stream to GitHub."""
import grp
import http.client
import itertools
import json
import os
import re
import socket
import socketserver
import stat
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlsplit

from . import credentials, policy
from .config import Config

MAX_INSPECT = 1 << 20          # bodies the policy reads are buffered up to this size
MAX_REF_SECTION = 1 << 20      # receive-pack command section
CHUNK = 64 * 1024
CLIENT_TIMEOUT = 300
UPSTREAM_TIMEOUT = 600
IDENTITY_PATH = "/_gh-cred-proxy/identity"
HEALTH_PATH = "/_gh-cred-proxy/health"

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
STRIP_REQUEST = HOP_BY_HOP | {"host", "authorization", "cookie", "expect", "content-length"}
STRIP_RESPONSE = HOP_BY_HOP | {"content-length", "set-cookie"}
BAD_PATH = re.compile(r"%(2e|2f|5c|00)|\\|[\x00-\x1f\x7f]", re.I)


class Refused(Exception):
    def __init__(self, status, reason, repo=None, detail=None):
        super().__init__(reason)
        self.status, self.reason, self.repo, self.detail = status, reason, repo, detail or {}


class AuditLog:
    def __init__(self, target: str):
        self._lock = threading.Lock()
        self._fh = sys.stderr if target == "-" else open(target, "a", buffering=1)
        if target != "-":
            os.chmod(target, 0o640)

    def write(self, rec: dict):
        line = json.dumps(rec, separators=(",", ":"), default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()


def _read_exact(rfile, n):
    buf = rfile.read(n)
    if buf is None or len(buf) != n:
        raise Refused(400, "request body ended early")
    return buf


def body_reader(handler):
    """Yield the request body in chunks. Refuses ambiguous framing (request smuggling)."""
    te = handler.headers.get_all("Transfer-Encoding") or []
    cl = handler.headers.get_all("Content-Length") or []
    if te and cl:
        raise Refused(400, "both Transfer-Encoding and Content-Length")
    if len(cl) > 1 or len(te) > 1:
        raise Refused(400, "repeated framing header")
    if te:
        if te[0].strip().lower() != "chunked":
            raise Refused(400, "unsupported Transfer-Encoding")
        return _chunked(handler.rfile), None
    if cl:
        if not cl[0].strip().isdigit():
            raise Refused(400, "bad Content-Length")
        n = int(cl[0])
        return _fixed(handler.rfile, n), n
    return iter(()), 0


def _fixed(rfile, n):
    while n > 0:
        b = _read_exact(rfile, min(CHUNK, n))
        n -= len(b)
        yield b


def _chunked(rfile):
    while True:
        line = rfile.readline(1024)
        if not line.endswith(b"\n"):
            raise Refused(400, "bad chunk header")
        size_s = line.split(b";", 1)[0].strip()
        if not re.fullmatch(rb"[0-9a-fA-F]{1,16}", size_s):
            raise Refused(400, "bad chunk size")
        size = int(size_s, 16)
        if size == 0:
            while True:
                t = rfile.readline(8192)
                if t in (b"\r\n", b"\n", b""):
                    return
        data = _read_exact(rfile, size)
        if _read_exact(rfile, 2) != b"\r\n":
            raise Refused(400, "bad chunk terminator")
        yield data


def buffer_body(it, limit):
    out = bytearray()
    for b in it:
        out += b
        if len(out) > limit:
            raise Refused(413, f"body larger than {limit} bytes cannot be inspected")
    return bytes(out)


class Proxy:
    def __init__(self, cfg: Config, cred, audit: AuditLog):
        self.cfg, self.cred, self.audit = cfg, cred, audit

    # ------------------------------------------------------------ credentials
    def scope(self, repo):
        """Repo names to scope an App token to. Refuses repos outside the installation owner."""
        if repo is None:
            return None
        owner, name = repo.split("/", 1)
        if self.cfg.kind == "github-app" and owner.lower() != self.cfg.owner.lower():
            raise Refused(403, f"repo owner {owner!r} is not the installation owner", repo)
        return (name,)

    def perms(self, access):
        return self.cfg.policy.permissions if access == "write" else self.cfg.policy.read_permissions()

    # ------------------------------------------------------------ lookups
    def resolve_lookup(self, d: policy.Decision):
        lk, pol = d.lookup, self.cfg.policy
        if "pr_base" in lk or "pr_head" in lk:
            num = lk.get("pr_base") or lk.get("pr_head")
            auth = self.cred.authorization(self.scope(d.repo), self.perms("read"))
            try:
                pr = credentials.api_call(self.cfg.api_url, "GET", f"/repos/{d.repo}/pulls/{num}", auth)
            except credentials.UpstreamError as e:
                raise Refused(403, f"could not look up PR #{num}: {e}", d.repo)
            if "pr_base" in lk:
                base = pr["base"]["ref"]
                if pol.merge_protected(d.repo, base):
                    raise Refused(403, f"merging into protected base {base!r} is not allowed", d.repo)
                d.detail["base"] = base
            else:
                head, head_repo = pr["head"]["ref"], (pr["head"].get("repo") or {}).get("full_name", "")
                if head_repo.lower() != d.repo.lower() or not pol.branch_pushable(head):
                    raise Refused(403, f"updating head branch {head!r} is not allowed", d.repo)
        if lk.get("pr_nodes"):
            q = ("query($ids:[ID!]!){nodes(ids:$ids){... on PullRequest"
                 "{baseRefName repository{nameWithOwner}}}}")
            auth = self.cred.authorization(None, self.perms("read"))
            try:
                r = credentials.api_call(self.cfg.api_url, "POST", "/graphql", auth,
                                         {"query": q, "variables": {"ids": lk["pr_nodes"]}})
            except credentials.UpstreamError as e:
                raise Refused(403, f"could not look up pull request nodes: {e}")
            nodes = (r or {}).get("data", {}).get("nodes") or []
            if len(nodes) != len(lk["pr_nodes"]) or any(not n or "baseRefName" not in n for n in nodes):
                raise Refused(403, "merge target is not a pull request the credential can see")
            for n in nodes:
                repo = n["repository"]["nameWithOwner"]
                if not pol.repo_allowed(repo):
                    raise Refused(403, "merge target repo not in policy", repo)
                if pol.merge_protected(repo, n["baseRefName"]):
                    raise Refused(403, f"merging into protected base {n['baseRefName']!r} is not allowed", repo)

    # ------------------------------------------------------------ upstream
    def forward(self, handler, base_url, path, query, body, length, auth):
        u = urlsplit(base_url)
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.hostname, u.port, timeout=UPSTREAM_TIMEOUT)
        headers = {k: v for k, v in handler.headers.items() if k.lower() not in STRIP_REQUEST}
        headers["Authorization"] = auth
        target = u.path + path + (f"?{query}" if query else "")
        chunked = length is None
        if not chunked:
            headers["Content-Length"] = str(length)
        try:
            conn.request(handler.command, target, body=body if (chunked or length) else None,
                         headers=headers, encode_chunked=chunked)
            resp = conn.getresponse()
        except (OSError, http.client.HTTPException) as e:
            conn.close()
            raise Refused(502, f"upstream error: {e.__class__.__name__}")
        sent = 0
        try:
            handler.send_response_only(resp.status, resp.reason)
            for k, v in resp.getheaders():
                if k.lower() not in STRIP_RESPONSE:
                    handler.send_header(k, v)
            handler.send_header("Connection", "close")
            clen = resp.getheader("Content-Length")
            no_body = handler.command == "HEAD" or resp.status in (204, 304) or 100 <= resp.status < 200
            if no_body:
                handler.end_headers()
            elif clen is not None and clen.isdigit():
                handler.send_header("Content-Length", clen)
                handler.end_headers()
                while b := resp.read(CHUNK):
                    handler.wfile.write(b)
                    sent += len(b)
            else:
                handler.send_header("Transfer-Encoding", "chunked")
                handler.end_headers()
                while b := resp.read1(CHUNK):
                    handler.wfile.write(b"%x\r\n%s\r\n" % (len(b), b))
                    sent += len(b)
                handler.wfile.write(b"0\r\n\r\n")
            return resp.status, sent
        finally:
            conn.close()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "gh-cred-proxy"
    sys_version = ""
    timeout = CLIENT_TIMEOUT

    def log_message(self, fmt, *args):
        pass

    def address_string(self):
        return "unix"

    def _peer(self):
        try:
            pid, uid, gid = struct.unpack("3i", self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            return {"pid": pid, "uid": uid}
        except OSError:
            return {}

    def _refuse(self, status, reason, git):
        msg = f"gh-cred-proxy: {reason}"
        if git:
            data, ctype = (msg + "\n").encode(), "text/plain; charset=utf-8"
        else:
            data, ctype = json.dumps({"message": msg}).encode(), "application/json; charset=utf-8"
        self.send_response_only(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _handle(self):
        px: Proxy = self.server.proxy
        cfg = px.cfg
        t0 = time.monotonic()
        rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "peer": self._peer(),
               "method": self.command, "identity": getattr(px.cred, "identity", {}).get("login")}
        self.close_connection = True
        git = False
        try:
            target = self.path
            if target.startswith(("http://", "https://")):
                u = urlsplit(target)
                host, path, query = (u.hostname or ""), (u.path or "/"), u.query
            else:
                host = (self.headers.get("Host") or "").rsplit(":", 1)[0].strip("[]").lower()
                path, _, query = target.partition("?")
            rec.update(host=host, path=path)
            if not path.startswith("/") or BAD_PATH.search(path) or "//" in path \
                    or any(seg in (".", "..") for seg in path.split("/")):
                raise Refused(400, "path is not canonical")

            if path in (IDENTITY_PATH, HEALTH_PATH):
                if self.command != "GET":
                    raise Refused(405, "GET only")
                payload = dict(px.cred.identity, api_host=cfg.api_host, git_host=cfg.git_host) \
                    if path == IDENTITY_PATH else {"status": "ok"}
                data = json.dumps(payload).encode()
                self.send_response_only(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(data)
                rec.update(decision="local", status=200)
                return

            body, length = body_reader(self)
            pol = cfg.policy
            if host == cfg.git_host:
                git = True
                rec["query"] = query
                d = policy.git_request(pol, self.command, path, query)
                if d.allow and path.endswith("/git-receive-pack"):
                    if self.headers.get("Content-Encoding"):
                        raise Refused(403, "compressed receive-pack bodies are not inspected", d.repo)
                    head, updates = bytearray(), None
                    for b in body:
                        head += b
                        try:
                            updates = policy.parse_ref_updates(bytes(head))
                        except ValueError as e:
                            raise Refused(403, f"receive-pack: {e}", d.repo)
                        if updates is not None:
                            break
                        if len(head) > MAX_REF_SECTION:
                            raise Refused(413, "receive-pack command section too large", d.repo)
                    if updates is None:
                        try:
                            updates = policy.parse_ref_updates(bytes(head) + b"0000")
                        except ValueError as e:
                            raise Refused(403, f"receive-pack: {e}", d.repo)
                        if updates:
                            raise Refused(400, "receive-pack commands without a flush-pkt", d.repo)
                    d = policy.check_ref_updates(pol, d.repo, updates)
                    body = itertools.chain([bytes(head)], body)
                upstream = cfg.git_url
            elif host == cfg.api_host:
                if self.command == "POST" and path == "/graphql":
                    raw = buffer_body(body, MAX_INSPECT)
                    d = policy.graphql_request(pol, raw)
                    body, length = iter([raw]), len(raw)
                elif policy.rest_needs_body(self.command, path):
                    raw = buffer_body(body, MAX_INSPECT)
                    d = policy.rest_request(pol, self.command, path, raw)
                    body, length = iter([raw]), len(raw)
                else:
                    d = policy.rest_request(pol, self.command, path, None)
                upstream = cfg.api_url
            else:
                raise Refused(403, f"host {host!r} is not proxied")

            rec.update(repo=d.repo, reason=d.reason, access=d.access, **({"detail": d.detail} if d.detail else {}))
            if not d.allow:
                raise Refused(403, d.reason, d.repo, d.detail)
            if d.lookup:
                px.resolve_lookup(d)
            scope = px.scope(d.repo)
            perms = px.perms(d.access)
            try:
                auth = px.cred.git_authorization(scope, perms) if git else px.cred.authorization(scope, perms)
            except credentials.UpstreamError as e:
                raise Refused(502, f"could not mint a credential: {e}", d.repo)
            status, sent = px.forward(self, upstream, path, query, body, length, auth)
            rec.update(decision="allow", status=status, bytes_out=sent)
        except Refused as r:
            rec.update(decision="deny", status=r.status, reason=r.reason,
                       **({"repo": r.repo} if r.repo else {}), **({"detail": r.detail} if r.detail else {}))
            try:
                self._refuse(r.status, r.reason, git)
            except OSError:
                pass
        except (ConnectionError, TimeoutError, OSError) as e:
            rec.update(decision="error", reason=e.__class__.__name__)
        finally:
            rec["ms"] = int((time.monotonic() - t0) * 1000)
            px.audit.write(rec)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _handle

    def send_error(self, code, message=None, explain=None):
        # Malformed request lines and oversized headers from BaseHTTPRequestHandler.
        self.server.proxy.audit.write({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                                       "decision": "deny", "status": code, "reason": message or "bad request"})
        self.close_connection = True
        try:
            self._refuse(code, message or "bad request", False)
        except OSError:
            pass


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False


def bind(cfg: Config, proxy: Proxy) -> UnixServer:
    path = cfg.socket
    if os.path.lexists(path):
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket; refusing to replace it")
        os.unlink(path)
    old = os.umask(0o177)
    try:
        srv = UnixServer(path, Handler)
    finally:
        os.umask(old)
    if cfg.socket_group:
        os.chown(path, -1, grp.getgrnam(cfg.socket_group).gr_gid)
    os.chmod(path, cfg.socket_mode)
    srv.proxy = proxy
    return srv


def serve(cfg: Config):
    audit = AuditLog(cfg.audit_log)
    cred = credentials.build(cfg)
    srv = bind(cfg, Proxy(cfg, cred, audit))
    audit.write({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "event": "start",
                 "identity": cred.identity.get("login"), "socket": cfg.socket})
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
        try:
            os.unlink(cfg.socket)
        except OSError:
            pass
