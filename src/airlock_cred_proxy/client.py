"""Client side: talk to the proxy socket, and print the environment that routes git and gh through it."""
import http.client
import json
import os
import shlex
import socket
import stat
import struct

PLACEHOLDER_TOKEN = "airlock-cred-proxy-placeholder"
LOCKED_STATUS = 423


class LockedError(RuntimeError):
    """The proxy answered 423: its credential is locked until the operator unlocks it on the host."""


def login_uid_min() -> int:
    try:
        with open("/etc/login.defs") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "UID_MIN" and parts[1].isdigit():
                    return int(parts[1])
    except OSError:
        pass
    return 1000


def check_admin_path(path: str):
    """The admin socket must sit where nothing running as the operator (a box included) can
    put one: every directory up to / owned by root, the socket's own not writable by others."""
    real = os.path.realpath(path)
    if real != os.path.abspath(path):
        raise RuntimeError(f"{path} goes through a symlink; name the real path")
    if not stat.S_ISSOCK(os.lstat(real).st_mode):
        raise RuntimeError(f"{path} is not a socket")
    d, first = os.path.dirname(real), True
    while True:
        st = os.stat(d)
        if st.st_uid != 0:
            raise RuntimeError(f"{d} is not owned by root, so anything running as you could have made {path}")
        if st.st_mode & 0o022 and (first or not st.st_mode & 0o1000):
            raise RuntimeError(f"{d} is writable by others")
        if d == "/":
            return
        d, first = os.path.dirname(d), False


def check_admin_peer(sock: socket.socket):
    """The listener must be root (systemd) or a system account, never the operator's own uid:
    a box runs as the operator and could serve a fake admin socket asking for any pass entry."""
    uid = struct.unpack("3i", sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
    if uid == os.getuid() or (uid != 0 and uid >= login_uid_min()):
        raise RuntimeError(f"admin socket is served by uid {uid}, not by root or a system account")


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path, timeout=30, check_peer=None):
        super().__init__("localhost", timeout=timeout)
        self._path, self._check_peer = path, check_peer

    def connect(self):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.connect(self._path)
        if self._check_peer:
            try:
                self._check_peer(s)
            except BaseException:
                s.close()
                raise
        self.sock = s


def admin_call(sock_path: str, method: str, path: str, body: dict | None = None, timeout=90) -> tuple[int, dict]:
    """One request on an admin socket, after checking who serves it. Returns (status, JSON reply)."""
    check_admin_path(sock_path)
    c = UnixHTTPConnection(sock_path, timeout=timeout, check_peer=check_admin_peer)
    try:
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Host": "airlock-cred-proxy-admin"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        c.request(method, path, body=data, headers=headers)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, {"error": raw[:200].decode("ascii", "replace")}
    finally:
        c.close()


def local_get(sock_path: str, path: str) -> dict:
    c = UnixHTTPConnection(sock_path)
    try:
        c.request("GET", path, headers={"Host": "airlock-cred-proxy"})
        r = c.getresponse()
        data = r.read()
        if r.status == LOCKED_STATUS:
            raise LockedError(json.loads(data).get("message", "credential locked"))
        if r.status != 200:
            raise RuntimeError(f"{path}: HTTP {r.status} {data[:200]!r}")
        return json.loads(data)
    finally:
        c.close()


def environment(sock_path: str, gh_config_dir: str) -> dict:
    """git reaches the socket as a SOCKS5 proxy; gh through http_unix_socket."""
    sock_path = os.path.abspath(sock_path)
    try:
        ident = local_get(sock_path, "/_airlock-cred-proxy/identity")
    except LockedError:
        # Never unlocked since the proxy started: route through it anyway, so the lock shows up
        # as 423 instead of git going around the proxy. Empty author and committer make git
        # refuse to commit rather than fall back to another identity.
        ident = {**local_get(sock_path, "/_airlock-cred-proxy/health"), "login": "", "email": ""}
    git_host = ident["git_host"]
    os.makedirs(gh_config_dir, mode=0o700, exist_ok=True)
    cfg = os.path.join(gh_config_dir, "config.yml")
    fd = os.open(cfg, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(f"http_unix_socket: {sock_path}\ngit_protocol: https\nprompt: disabled\n")
    plain = f"http://{git_host}/"
    git = [
        (f"url.{plain}.insteadOf", f"https://{git_host}/"),
        (f"url.{plain}.insteadOf", f"git@{git_host}:"),
        (f"url.{plain}.insteadOf", f"ssh://git@{git_host}/"),
        (f"http.{plain}.proxy", f"socks5h://localhost{sock_path}"),
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
