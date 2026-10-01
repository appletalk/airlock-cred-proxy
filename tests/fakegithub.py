"""A fake GitHub for tests: app/token endpoints, a few REST/GraphQL answers, and git via git-http-backend."""
import base64
import json
import os
import re
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class State:
    def __init__(self, git_root):
        self.git_root = git_root
        self.lock = threading.Lock()
        self.minted = []          # access_tokens request bodies
        self.tokens = {}          # token -> body it was minted with
        self.seen = []            # (method, path, authorization) for every non-app request
        self.pulls = {}           # (repo, num) -> {"base": ..., "head": ..., "head_repo": ...}
        self.nodes = {}           # node id -> {"baseRefName": ..., "nameWithOwner": ...}
        self.app_public_key = None   # when set, App JWTs must be signed by its private key, as on GitHub
        self.installation_permissions = {"metadata": "read", "contents": "write",
                                         "pull_requests": "write", "issues": "write"}


def _jwt_ok(jwt, public_key):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    try:
        head, body, sig = jwt.split(".")
        raw = base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4))
        public_key.verify(raw, f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return True
    except (ValueError, InvalidSignature):
        return False


def _read_body(h):
    if (h.headers.get("Transfer-Encoding") or "").lower() == "chunked":
        out = b""
        while True:
            size = int(h.rfile.readline().split(b";")[0].strip(), 16)
            if size == 0:
                while h.rfile.readline() not in (b"\r\n", b"\n", b""):
                    pass
                return out
            out += h.rfile.read(size)
            h.rfile.read(2)
    n = int(h.headers.get("Content-Length") or 0)
    return h.rfile.read(n) if n else b""


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        st: State = self.server.state
        body = _read_body(self)
        path, _, query = self.path.partition("?")
        auth = self.headers.get("Authorization", "")

        if path.startswith("/app"):
            if not auth.startswith("Bearer "):
                return self._json(401, {"message": "jwt required"})
            if st.app_public_key is not None and not _jwt_ok(auth[7:], st.app_public_key):
                return self._json(401, {"message": "A JSON web token could not be decoded"})
            if path == "/app":
                return self._json(200, {"slug": "test-agent", "id": 99})
            if path == "/app/installations/7" and self.command == "GET":
                return self._json(200, {"id": 7, "permissions": st.installation_permissions})
            if path == "/app/installations":
                return self._json(200, [{"id": 7, "account": {"login": "acme"}}])
            m = re.fullmatch(r"/app/installations/7/access_tokens", path)
            if m and self.command == "POST":
                req = json.loads(body)
                with st.lock:
                    tok = f"ghs_test{len(st.minted)}"
                    st.minted.append(req)
                    st.tokens[tok] = req
                return self._json(201, {"token": tok, "expires_at": "2099-01-01T00:00:00Z",
                                        "permissions": req.get("permissions")})
            return self._json(404, {"message": "no"})

        with st.lock:
            st.seen.append((self.command, path, auth))
        tok = auth.split(" ", 1)[1] if auth.startswith("token ") else None
        if auth.startswith("Basic "):
            user, _, pw = base64.b64decode(auth[6:]).decode().partition(":")
            tok = pw if user == "x-access-token" else None
        if tok not in st.tokens:
            return self._json(401, {"message": "bad credentials"})

        if path == "/user":
            return self._json(200, {"id": 5151, "login": "token-user"})
        if path.endswith("/marker"):
            self.send_response(200)
            self.send_header("X-Airlock-Cred-Proxy", "locked")
            self.send_header("Content-Length", "2")
            self.end_headers()
            return self.wfile.write(b"{}")
        if path.endswith("/slow"):
            time.sleep(getattr(st, "delay", 0))
        if path.startswith("/users/"):
            return self._json(200, {"id": 4242, "login": path[7:]})
        m = re.fullmatch(r"/repos/([^/]+/[^/]+)/pulls/(\d+)", path)
        if m and self.command == "GET":
            p = st.pulls.get((m[1], int(m[2])))
            if not p:
                return self._json(404, {"message": "no pr"})
            return self._json(200, {"base": {"ref": p["base"]},
                                    "head": {"ref": p["head"], "repo": {"full_name": p.get("head_repo", m[1])}}})
        if path == "/graphql":
            q = json.loads(body)
            if "nodes(ids:" in q["query"] and getattr(st, "nodes_null", False):
                return self._json(200, {"data": None})
            if "nodes(ids:" in q["query"]:
                nodes = []
                scope = st.tokens[tok].get("repositories")
                for i in q["variables"]["ids"]:
                    n = st.nodes.get(i)
                    if n and scope is not None and n["nameWithOwner"].split("/", 1)[1] not in scope:
                        n = None
                    nodes.append({"baseRefName": n["baseRefName"],
                                  "repository": {"nameWithOwner": n["nameWithOwner"]}} if n else None)
                return self._json(200, {"data": {"nodes": nodes}})
            return self._json(200, {"data": {"ok": True}})
        if re.match(r"^/[^/]+/[^/]+\.git/", path):
            return self._git(path, query, body)
        if path.startswith("/repos/"):
            return self._json(200, {"ok": True, "path": path})
        return self._json(200, {"ok": True})

    def _git(self, path, query, body):
        env = {"PATH": os.environ["PATH"], "GIT_PROJECT_ROOT": self.server.state.git_root,
               "GIT_HTTP_EXPORT_ALL": "1", "PATH_INFO": path, "QUERY_STRING": query,
               "REQUEST_METHOD": self.command, "REMOTE_USER": "x-access-token", "REMOTE_ADDR": "127.0.0.1",
               "CONTENT_TYPE": self.headers.get("Content-Type", ""), "CONTENT_LENGTH": str(len(body)),
               "HTTP_CONTENT_ENCODING": self.headers.get("Content-Encoding", ""),
               "GIT_CONFIG_NOSYSTEM": "1", "HOME": self.server.state.git_root}
        r = subprocess.run(["git", "http-backend"], input=body, env=env, capture_output=True)
        head, _, out = r.stdout.partition(b"\r\n\r\n")
        status = 200
        headers = []
        for line in head.split(b"\r\n"):
            k, _, v = line.decode().partition(":")
            if k.lower() == "status":
                status = int(v.strip().split()[0])
            elif k:
                headers.append((k, v.strip()))
        self.send_response(status)
        for k, v in headers:
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_HEAD = _handle


def start(git_root):
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    srv.daemon_threads = True
    srv.state = State(git_root)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
