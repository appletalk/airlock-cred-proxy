"""Client side: the loopback forwarder for git, and the environment that points git and gh at the proxy."""
import base64
import hmac
import http.client
import json
import os
import secrets
import shlex
import socket
import socketserver
import threading

MAX_HEADER = 64 * 1024
PLACEHOLDER_TOKEN = "gh-cred-proxy-placeholder"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=30):
        super().__init__("localhost", timeout=timeout)
        self._path = path

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        self.sock = s


def local_get(sock_path: str, path: str) -> dict:
    c = UnixHTTPConnection(sock_path)
    try:
        c.request("GET", path, headers={"Host": "gh-cred-proxy"})
        r = c.getresponse()
        data = r.read()
        if r.status != 200:
            raise RuntimeError(f"{path}: HTTP {r.status} {data[:200]!r}")
        return json.loads(data)
    finally:
        c.close()


def read_or_create_secret(path: str) -> str:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        st = os.stat(path)
        if st.st_mode & 0o077:
            raise SystemExit(f"{path} is readable by group or others; chmod 600 it")
        with open(path) as f:
            return f.read().strip()
    with os.fdopen(fd, "w") as f:
        s = secrets.token_hex(32)
        f.write(s + "\n")
        return s


# ---------------------------------------------------------------- forwarder

class _Forward(socketserver.BaseRequestHandler):
    def handle(self):
        srv = self.server
        c = self.request
        c.settimeout(300)
        head = b""
        while b"\r\n\r\n" not in head:
            b = c.recv(8192)
            if not b:
                return
            head += b
            if len(head) > MAX_HEADER:
                return self._reply(431, "headers too large")
        block, rest = head.split(b"\r\n\r\n", 1)
        lines = block.split(b"\r\n")
        kept, authed = [lines[0]], False
        for ln in lines[1:]:
            name, _, value = ln.partition(b":")
            if name.strip().lower() == b"proxy-authorization":
                authed = authed or _check(value.strip(), srv.secret)
                continue
            kept.append(ln)
        if not authed:
            return self._reply(407, "proxy authentication required",
                               b'Proxy-Authenticate: Basic realm="gh-cred-proxy"\r\n')
        u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            u.connect(srv.sock_path)
        except OSError:
            return self._reply(502, "proxy socket unavailable")
        u.sendall(b"\r\n".join(kept) + b"\r\n\r\n" + rest)
        t = threading.Thread(target=_pipe, args=(c, u), daemon=True)
        t.start()
        _pipe(u, c)
        t.join(5)
        u.close()

    def _reply(self, status, msg, extra=b""):
        body = (f"gh-cred-proxy forward: {msg}\n").encode()
        self.request.sendall(b"HTTP/1.1 %d %s\r\n%sContent-Length: %d\r\nConnection: close\r\n\r\n%s"
                             % (status, msg.encode(), extra, len(body), body))


def _check(value: bytes, secret: str) -> bool:
    if not value.lower().startswith(b"basic "):
        return False
    try:
        user_pass = base64.b64decode(value[6:].strip(), validate=True).decode()
    except ValueError:
        return False
    _, _, pw = user_pass.partition(":")
    return hmac.compare_digest(pw.encode(), secret.encode())


def _pipe(src, dst):
    try:
        while b := src.recv(65536):
            dst.sendall(b)
    except OSError:
        pass
    finally:
        try:
            dst.shutdown(socket.SHUT_WR)
        except OSError:
            pass


class ForwardServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


def forward(sock_path: str, port: int, secret_file: str):
    fs = ForwardServer(("127.0.0.1", port), _Forward)
    fs.sock_path, fs.secret = sock_path, read_or_create_secret(secret_file)
    fs.serve_forever()


# ---------------------------------------------------------------- environment

def environment(sock_path: str, port: int, secret_file: str, gh_config_dir: str) -> dict:
    ident = local_get(sock_path, "/_gh-cred-proxy/identity")
    git_host, api_host = ident["git_host"], ident["api_host"]
    secret = read_or_create_secret(secret_file)
    os.makedirs(gh_config_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(gh_config_dir, "config.yml"), "w") as f:
        f.write(f"http_unix_socket: {sock_path}\ngit_protocol: https\nprompt: disabled\n")
    plain = f"http://{git_host}/"
    git = [
        (f"url.{plain}.insteadOf", f"https://{git_host}/"),
        (f"url.{plain}.insteadOf", f"git@{git_host}:"),
        (f"url.{plain}.insteadOf", f"ssh://git@{git_host}/"),
        (f"http.{plain}.proxy", f"http://agent:{secret}@127.0.0.1:{port}"),
        ("credential.helper", ""),
    ]
    env = {
        "GH_CONFIG_DIR": gh_config_dir,
        "GH_TOKEN": PLACEHOLDER_TOKEN,
        "GH_HOST": git_host,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_AUTHOR_NAME": ident["login"], "GIT_AUTHOR_EMAIL": ident["email"],
        "GIT_COMMITTER_NAME": ident["login"], "GIT_COMMITTER_EMAIL": ident["email"],
        "GIT_CONFIG_COUNT": str(len(git)),
    }
    for i, (k, v) in enumerate(git):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


def shell_exports(env: dict) -> str:
    return "".join(f"export {k}={shlex.quote(v)}\n" for k, v in env.items())
