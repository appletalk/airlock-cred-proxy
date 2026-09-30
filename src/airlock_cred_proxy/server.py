"""HTTP-over-Unix-socket proxy: authorise each request, attach a scoped credential, stream to GitHub.

Clients speak plain HTTP on the socket (gh, via http_unix_socket), or open with a SOCKS5
CONNECT and then speak plain HTTP (git and curl, via http.proxy=socks5h://localhost/<socket>).
"""
import grp
import http.client
import io
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

from . import client, credentials, policy, unlock
from .config import Config

MAX_INSPECT = 1 << 20          # bodies the policy reads are buffered up to this size
MAX_DRAIN = 1 << 20            # unread body read and discarded before a refusal is sent
MAX_REF_SECTION = 1 << 20      # receive-pack command section
MAX_CONNECTIONS = 64
MAX_PER_PEER = 16              # connections one uid may hold, so one client cannot starve the rest
INSPECT_SLOTS = 4              # concurrent JSON/GraphQL parses; bounds peak memory
INSPECT_WAIT = 30
REQUEST_DEADLINE = 30          # whole-request budget for the request line, headers and inspected body
CHUNK = 64 * 1024
CLIENT_TIMEOUT = 60
UPSTREAM_TIMEOUT = 600
IDENTITY_PATH = "/_airlock-cred-proxy/identity"
HEALTH_PATH = "/_airlock-cred-proxy/health"
LOCKED_STATUS = 423

HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "te",
              "trailer", "transfer-encoding", "upgrade", "proxy-connection"}
STRIP_REQUEST = HOP_BY_HOP | {"host", "authorization", "cookie", "expect", "content-length"}
STRIP_RESPONSE = HOP_BY_HOP | {"content-length", "set-cookie", "x-airlock-cred-proxy"}
METHOD_OVERRIDE = ("x-http-method-override", "x-http-method", "x-method-override")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+")   # RFC 9110 token
BAD_HEADER_VALUE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")      # controls other than tab
CANONICAL_PATH = re.compile(r"/[\x21-\x7e]*")
BAD_PATH = re.compile(r"%(2e|2f|5c|00)|\\", re.I)


class Refused(Exception):
    def __init__(self, status, reason, repo=None, detail=None):
        super().__init__(reason)
        self.status, self.reason, self.repo, self.detail = status, reason, repo, detail or {}


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class AuditLog:
    def __init__(self, target: str):
        self._lock = threading.Lock()
        if target == "-":
            self._fh = sys.stderr
        else:
            fd = os.open(target, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            self._fh = os.fdopen(fd, "a", buffering=1)

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
    """Yield the request body in pieces of at most CHUNK bytes. Refuses ambiguous framing."""
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
        if not re.fullmatch(r"[0-9]{1,15}", cl[0].strip()):
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
        if not re.fullmatch(rb"[0-9a-fA-F]{1,8}", size_s):
            raise Refused(400, "bad chunk size")
        size = int(size_s, 16)
        if size == 0:
            for _ in range(64):
                t = rfile.readline(8192)
                if t in (b"\r\n", b"\n", b""):
                    return
            raise Refused(400, "too many trailers")
        while size > 0:
            b = _read_exact(rfile, min(CHUNK, size))
            size -= len(b)
            yield b
        if _read_exact(rfile, 2) != b"\r\n":
            raise Refused(400, "bad chunk terminator")


_inspect_slots = threading.BoundedSemaphore(INSPECT_SLOTS)


def inspect(it, limit, decide):
    """Buffer an inspected body, then decide on it with at most INSPECT_SLOTS parsing at once.

    The slot covers only the parse, so a slow upload cannot hold one.
    """
    raw = buffer_body(it, limit)
    if not _inspect_slots.acquire(timeout=INSPECT_WAIT):
        raise Refused(503, "too many requests being inspected")
    try:
        return raw, decide(raw)
    finally:
        _inspect_slots.release()


class DeadlineSocketIO(io.RawIOBase):
    """The raw stream under the handler's rfile. Every recv times out at the handler's deadline.

    A per-recv timeout alone lets a client that drips bytes hold its slot forever, and one
    buffered readline() makes many recvs, so the deadline is applied here, below the buffer.
    No thread per connection.
    """

    def __init__(self, sock, handler):
        super().__init__()
        self._sock, self._h = sock, handler

    def readable(self):
        return True

    def readinto(self, b):
        at = self._h.deadline_at
        if at is None:
            self._sock.settimeout(CLIENT_TIMEOUT)
        else:
            left = at - time.monotonic()
            if left <= 0:
                raise TimeoutError("request deadline passed")
            self._sock.settimeout(min(CLIENT_TIMEOUT, left))
        return self._sock.recv_into(b)


def buffer_body(it, limit):
    out = bytearray()
    for b in it:
        out += b
        if len(out) > limit:
            raise Refused(413, f"body larger than {limit} bytes cannot be inspected")
    return bytes(out)


def locked(reason):
    return Refused(LOCKED_STATUS, f"credential locked ({reason}); unlock on the host with 'airlock-cred-proxy unlock'")


class Proxy:
    def __init__(self, cfg: Config, gate, audit: AuditLog):
        # A bare credential (tests, check-config) is a gate that never locks.
        self.gate = gate if hasattr(gate, "current") else unlock.StaticGate(gate)
        self.cfg, self.audit = cfg, audit

    @property
    def cred(self):
        try:
            return self.gate.current()
        except unlock.Locked as e:
            raise locked(e) from None

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

    def resolve_lookup(self, d: policy.Decision, cred):
        """Checks that need GitHub's view of a pull request. Any failure refuses the request."""
        lk, pol = d.lookup, self.cfg.policy
        if "pr_base" in lk or "pr_head" in lk:
            num = lk.get("pr_base") or lk.get("pr_head")
            auth = cred.authorization(self.scope(d.repo), self.perms("read"))
            try:
                pr = credentials.api_call(self.cfg.api_url, "GET", f"/repos/{d.repo}/pulls/{num}", auth)
                base = pr["base"]["ref"]
                head, head_repo = pr["head"]["ref"], (pr["head"].get("repo") or {}).get("full_name", "")
            except (credentials.UpstreamError, KeyError, TypeError) as e:
                raise Refused(403, f"could not look up PR #{num}: {e.__class__.__name__}", d.repo)
            if "pr_base" in lk:
                if pol.merge_protected(d.repo, base):
                    raise Refused(403, f"merging into protected base {base!r} is not allowed", d.repo)
                d.detail["base"] = base
            elif head_repo.lower() != d.repo.lower() or not pol.branch_pushable(head):
                raise Refused(403, f"updating head branch {head!r} is not allowed", d.repo)
        items = lk.get("pr_nodes") or []
        if items:
            q = ("query($ids:[ID!]!){nodes(ids:$ids){... on PullRequest"
                 "{baseRefName repository{nameWithOwner}}}}")
            auth = cred.authorization(None, self.perms("read"))
            try:
                r = credentials.api_call(self.cfg.api_url, "POST", "/graphql", auth,
                                         {"query": q, "variables": {"ids": [i["id"] for i in items]}})
                nodes = r["data"]["nodes"]
            except (credentials.UpstreamError, KeyError, TypeError) as e:
                raise Refused(403, f"could not look up pull request nodes: {e.__class__.__name__}")
            if not isinstance(nodes, list) or len(nodes) != len(items):
                raise Refused(403, "pull request lookup returned an unexpected shape")
            for item, n in zip(items, nodes):
                if not isinstance(n, dict) or "baseRefName" not in n:
                    raise Refused(403, "target is not a pull request the credential can see")
                repo = n["repository"]["nameWithOwner"]
                if not pol.repo_allowed(repo):
                    raise Refused(403, "pull request repo not in policy", repo)
                target = item["base"] or n["baseRefName"]
                if pol.merge_protected(repo, target):
                    verb = "retargeting to" if item["base"] else "merging into"
                    raise Refused(403, f"{verb} protected base {target!r} is not allowed", repo)

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
        except (OSError, http.client.HTTPException, UnicodeError) as e:
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
            elif clen is not None and clen.isascii() and clen.isdigit():
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
    server_version = "airlock-cred-proxy"
    sys_version = ""
    timeout = CLIENT_TIMEOUT
    socks_target = None
    _body_it = None                # the request body's reader, once _handle has opened it

    def log_message(self, fmt, *args):
        pass

    def address_string(self):
        return "unix"

    def setup(self):
        super().setup()
        # Everything before authorisation must arrive within REQUEST_DEADLINE; cleared
        # (deadline_at = None) once the request is allowed and about to stream upstream.
        self.deadline_at = time.monotonic() + REQUEST_DEADLINE
        self.rfile.close()
        self.rfile = io.BufferedReader(DeadlineSocketIO(self.connection, self), CHUNK)
        try:
            self.connection.settimeout(min(CLIENT_TIMEOUT, REQUEST_DEADLINE))
            if self.request.recv(1, socket.MSG_PEEK) == b"\x05":
                self.socks_target = self._socks()
        except (Refused, OSError, ValueError) as e:
            self.server.proxy.audit.write({"ts": now(), "peer": self._peer(), "decision": "deny",
                                           "reason": f"socks: {getattr(e, 'reason', None) or e}"})
            raise ConnectionAbortedError("socks handshake refused")

    def _socks(self):
        """Minimal SOCKS5 (RFC 1928): no auth, CONNECT by domain name to a proxied host on port 80."""
        r = self.rfile
        ver, n = _read_exact(r, 2)
        methods = _read_exact(r, n)
        if ver != 5 or 0 not in methods:
            self.wfile.write(b"\x05\xff")
            raise ConnectionAbortedError("socks: no acceptable method")
        self.wfile.write(b"\x05\x00")
        ver, cmd, _, atyp = _read_exact(r, 4)
        host = _read_exact(r, _read_exact(r, 1)[0]).decode("ascii", "replace").lower() if atyp == 3 else None
        if atyp == 1:
            _read_exact(r, 4)
        elif atyp == 4:
            _read_exact(r, 16)
        port = struct.unpack("!H", _read_exact(r, 2))[0]
        cfg = self.server.proxy.cfg
        ok = ver == 5 and cmd == 1 and host in (cfg.git_host, cfg.api_host) and port == 80
        self.wfile.write((b"\x05\x00" if ok else b"\x05\x02") + b"\x00\x01" + b"\x00" * 6)
        self.wfile.flush()
        if not ok:
            raise ConnectionAbortedError(f"socks: refused CONNECT {host}:{port}")
        return host

    def _peer(self):
        try:
            pid, uid, gid = struct.unpack("3i", self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))
            return {"pid": pid, "uid": uid}
        except OSError:
            return {}

    def _drain(self):
        """Read the rest of a well-framed request body, up to MAX_DRAIN, and discard it.

        A refusal sent while the client is still writing its body reaches the client as a
        broken pipe, not as the refusal. Bodies with bad framing, or larger than the cap,
        still get the fast close.
        """
        try:
            it = self._body_it
            if it is None:
                it, _ = body_reader(self)
            n = 0
            for b in it:
                n += len(b)
                if n > MAX_DRAIN:
                    return
        except (Refused, OSError, ValueError):
            return

    def _refuse(self, status, reason, git, drain=True):
        if drain:
            self._drain()
        msg = f"airlock-cred-proxy: {reason}"
        if git:
            data, ctype = (msg + "\n").encode(), "text/plain; charset=utf-8"
        else:
            data, ctype = json.dumps({"message": msg}).encode(), "application/json; charset=utf-8"
        self.send_response_only(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        if status == LOCKED_STATUS:
            self.send_header("X-Airlock-Cred-Proxy", "locked")
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _local(self, px, path):
        if self.command != "GET":
            raise Refused(405, "GET only")
        cfg = px.cfg
        if path == IDENTITY_PATH:
            if px.gate.identity is None:
                px.cred        # locked since start: nothing to report, answer 423
            payload = dict(px.gate.identity, api_host=cfg.api_host, git_host=cfg.git_host)
        else:
            payload = {"status": "ok", "api_host": cfg.api_host, "git_host": cfg.git_host, **px.gate.status()}
        data = json.dumps(payload).encode()
        self.send_response_only(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        px: Proxy = self.server.proxy
        cfg, pol = px.cfg, px.cfg.policy
        t0 = time.monotonic()
        rec = {"ts": now(), "peer": self._peer(), "method": self.command,
               "identity": (px.gate.identity or {}).get("login")}
        if self.socks_target:
            rec["socks"] = True
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
            git = host == cfg.git_host     # git shows a text/plain refusal body; JSON it drops
            # The stdlib parser stops at a line it cannot read as a header and keeps the rest as
            # "payload", silently dropping those headers. Anything left over is a malformed request.
            if self.headers.defects or self.headers.get_payload() \
                    or not all(HEADER_NAME.fullmatch(k) for k in self.headers.keys()) \
                    or any(BAD_HEADER_VALUE.search(v) for v in self.headers.values()):
                raise Refused(400, "malformed header block")
            if not CANONICAL_PATH.fullmatch(path) or BAD_PATH.search(path) or "//" in path \
                    or any(seg in (".", "..") for seg in path.split("/")):
                raise Refused(400, "path is not canonical")
            if not re.fullmatch(r"[\x21-\x7e]*", query):
                raise Refused(400, "query string is not canonical")
            if self.socks_target and host != self.socks_target:
                raise Refused(400, "Host does not match the SOCKS target")

            if path in (IDENTITY_PATH, HEALTH_PATH):
                self._local(px, path)
                rec.update(decision="local", status=200)
                return

            # One credential for the whole request, taken before any body is read: a lock that
            # lands later lets this request finish and refuses the next.
            cred = px.cred
            if any(h in self.headers for h in METHOD_OVERRIDE):
                raise Refused(400, "method-override headers are not accepted")
            if query and self.command not in policy.READ_METHODS and host == cfg.api_host:
                raise Refused(400, "query strings on writes are not accepted")
            if host == cfg.api_host and len(path) > 1 and path.endswith("/"):
                raise Refused(400, "API paths do not end in /")

            body, length = body_reader(self)
            self._body_it = body
            if host == cfg.git_host:
                rec["query"] = query
                d = policy.git_request(pol, self.command, path, query)
                if d.allow and path.endswith("/git-receive-pack"):
                    if self.headers.get("Content-Encoding"):
                        raise Refused(403, "compressed receive-pack bodies are not inspected", d.repo)
                    parser, updates = policy.RefCommandParser(MAX_REF_SECTION), None
                    try:
                        for b in body:
                            updates = parser.feed(b)
                            if updates is not None:
                                break
                        if updates is None:
                            raise Refused(400, "receive-pack commands without a flush-pkt", d.repo)
                    except ValueError as e:
                        raise Refused(403, f"receive-pack: {e}", d.repo)
                    d = policy.check_ref_updates(pol, d.repo, updates)
                    body = itertools.chain([parser.consumed], body)
                upstream = cfg.git_url
            elif host == cfg.api_host:
                inspected = (self.command == "POST" and path == "/graphql") \
                    or policy.rest_needs_body(self.command, path)
                if inspected and self.headers.get("Content-Encoding"):
                    raise Refused(400, "encoded bodies cannot be inspected")
                if self.command == "POST" and path == "/graphql":
                    raw, d = inspect(body, MAX_INSPECT, lambda b: policy.graphql_request(pol, b))
                    body, length = iter([raw]), len(raw)
                elif policy.rest_needs_body(self.command, path):
                    raw, d = inspect(body, MAX_INSPECT, lambda b: policy.rest_request(pol, self.command, path, b))
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
                px.resolve_lookup(d, cred)
            scope = px.scope(d.repo)
            perms = px.perms(d.access)
            self.deadline_at = None
            self.connection.settimeout(CLIENT_TIMEOUT)   # writes use it too; drop the residual deadline
            try:
                auth = cred.git_authorization(scope, perms) if git else cred.authorization(scope, perms)
            except (credentials.UpstreamError, KeyError, ValueError) as e:
                raise Refused(502, f"could not mint a credential: {e.__class__.__name__}", d.repo)
            px.gate.touch()
            status, sent = px.forward(self, upstream, path, query, body, length, auth)
            rec.update(decision="allow", status=status, bytes_out=sent)
        except Refused as r:
            rec.update(decision="locked" if r.status == LOCKED_STATUS else "deny", status=r.status, reason=r.reason,
                       **({"repo": r.repo} if r.repo else {}), **({"detail": r.detail} if r.detail else {}))
            try:
                self._refuse(r.status, r.reason, git)
            except OSError:
                pass
        except (ConnectionError, TimeoutError, OSError) as e:
            rec.update(decision="error", reason=e.__class__.__name__)
        except Exception as e:  # noqa: BLE001 - any other failure is recorded and refused
            rec.update(decision="error", status=500, reason=f"internal: {e.__class__.__name__}")
            try:
                self._refuse(500, "internal error", git)
            except OSError:
                pass
        finally:
            rec["ms"] = int((time.monotonic() - t0) * 1000)
            px.audit.write(rec)

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _handle

    def send_error(self, code, message=None, explain=None):
        # Malformed request lines and oversized headers from BaseHTTPRequestHandler.
        self.server.proxy.audit.write({"ts": now(), "decision": "deny", "status": code,
                                       "reason": message or "bad request"})
        self.close_connection = True
        try:
            self._refuse(code, message or "bad request", False, drain=False)
        except OSError:
            pass


class UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, *a, **kw):
        self._slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self._peers_lock = threading.Lock()
        self._per_peer: dict[int, int] = {}
        super().__init__(*a, **kw)

    @staticmethod
    def _uid(request):
        try:
            return struct.unpack("3i", request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        except OSError:
            return -1

    def _busy(self, request, reason):
        try:
            request.sendall(b"HTTP/1.1 503 Busy\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        except OSError:
            pass
        self.shutdown_request(request)
        self.proxy.audit.write({"ts": now(), "decision": "deny", "status": 503, "reason": reason})

    def process_request(self, request, client_address):
        uid = self._uid(request)
        with self._peers_lock:
            if self._per_peer.get(uid, 0) >= MAX_PER_PEER:
                full = "too many connections from this uid"
            else:
                full = None
                self._per_peer[uid] = self._per_peer.get(uid, 0) + 1
        if full:
            return self._busy(request, full)
        if not self._slots.acquire(blocking=False):
            self._release_peer(uid)
            return self._busy(request, "too many connections")
        try:
            super().process_request(request, (uid,))
        except BaseException:
            # The thread never started, so process_request_thread will not release these.
            self._slots.release()
            self._release_peer(uid)
            self.proxy.audit.write({"ts": now(), "decision": "error", "reason": "could not start handler thread"})
            raise

    def _release_peer(self, uid):
        with self._peers_lock:
            n = self._per_peer.get(uid, 1) - 1
            if n <= 0:
                self._per_peer.pop(uid, None)
            else:
                self._per_peer[uid] = n

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()
            self._release_peer(client_address[0])

    def handle_error(self, request, client_address):
        pass


_inherited: dict | None = None


def _systemd_sockets() -> dict:
    """Listening sockets passed by systemd socket activation, by name: {"data": s, "admin": s}.

    One socket is the data socket whatever its name; with two, the one named "admin"
    (FileDescriptorName=admin) is the admin socket.
    """
    global _inherited
    if _inherited is not None:
        return _inherited
    _inherited = {}
    n = os.environ.get("LISTEN_FDS")
    if os.environ.get("LISTEN_PID") != str(os.getpid()) or n not in ("1", "2"):
        return _inherited
    names = (os.environ.get("LISTEN_FDNAMES") or "").split(":")
    for k in ("LISTEN_PID", "LISTEN_FDS", "LISTEN_FDNAMES"):
        os.environ.pop(k, None)
    if n == "1":
        _inherited["data"] = socket.socket(fileno=3)
        return _inherited
    if sorted(names) != ["admin", "data"]:
        raise SystemExit(f"two activated sockets need FileDescriptorName=data and =admin, got {names}")
    for i, name in enumerate(names):
        _inherited[name] = socket.socket(fileno=3 + i)
    return _inherited


def _listen(server_cls, path, handler, mode, group=None):
    if os.path.lexists(path):
        if not stat.S_ISSOCK(os.lstat(path).st_mode):
            raise SystemExit(f"{path} exists and is not a socket; refusing to replace it")
        os.unlink(path)
    old = os.umask(0o177)
    try:
        srv = server_cls(path, handler)
    finally:
        os.umask(old)
    if group:
        os.chown(path, -1, grp.getgrnam(group).gr_gid)
    os.chmod(path, mode)
    return srv


def _adopt(server_cls, path, handler, sock):
    srv = server_cls(path, handler, bind_and_activate=False)
    srv.socket.close()
    srv.socket = sock
    return srv


def bind(cfg: Config, proxy: Proxy) -> UnixServer:
    inherited = _systemd_sockets().get("data")
    if inherited is not None:
        srv = _adopt(UnixServer, cfg.socket, Handler, inherited)
    else:
        srv = _listen(UnixServer, cfg.socket, Handler, cfg.socket_mode, cfg.socket_group)
    srv.proxy = proxy
    return srv


def not_dumpable():
    """No core dump, and no ptrace from other processes running as the service user."""
    import ctypes
    PR_SET_DUMPABLE = 4
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:
        raise SystemExit(f"prctl(PR_SET_DUMPABLE) failed: errno {ctypes.get_errno()}")


def bind_admin(cfg: Config, gate) -> unlock.AdminServer:
    """The admin socket. Socket-activated, it is created by systemd with the operator as owner;
    otherwise it is bound here, 0600, owned by whoever runs the proxy."""
    acts = _systemd_sockets()
    if "admin" in acts:
        srv = _adopt(unlock.AdminServer, cfg.admin_socket, unlock.AdminHandler, acts["admin"])
    elif acts:
        raise SystemExit("unlock is configured but systemd passed no admin socket; "
                         "enable airlock-cred-proxy-admin@<name>.socket")
    else:
        # Bound here it is owned by the proxy's own uid. airlock grants sockets owned by a
        # system account, so that is only safe when the proxy runs as a login user. The
        # unlock CLI refuses such a socket (not root-served), so this path is for tests.
        if os.getuid() < client.login_uid_min():
            raise SystemExit("run as a system account, the admin socket must come from systemd "
                             "(airlock-cred-proxy-admin@<name>.socket), owned by the operator")
        srv = _listen(unlock.AdminServer, cfg.admin_socket, unlock.AdminHandler, 0o600)
    srv.gate, srv.path = gate, cfg.admin_socket
    return srv


def serve(cfg: Config):
    audit = AuditLog(cfg.audit_log)
    threads = []
    if cfg.unlock is None and "admin" in _systemd_sockets():
        raise SystemExit("systemd passed an admin socket but the config has no [unlock] table")
    if cfg.unlock is not None:
        not_dumpable()
        gate = unlock.UnlockGate(cfg, audit)
        admin = bind_admin(cfg, gate)
        stop = threading.Event()
        threads = [threading.Thread(target=admin.serve_forever, daemon=True),
                   threading.Thread(target=gate.run_timer, args=(stop,), daemon=True)]
    else:
        gate = unlock.StaticGate(credentials.build(cfg))
    srv = bind(cfg, Proxy(cfg, gate, audit))
    for t in threads:
        t.start()
    audit.write({"ts": now(), "event": "start", "identity": (gate.identity or {}).get("login"),
                 "socket": cfg.socket, "state": gate.status()["state"]})
    try:
        srv.serve_forever()
    finally:
        srv.server_close()
