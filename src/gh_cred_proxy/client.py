"""Client side: talk to the proxy socket, and print the environment that routes git and gh through it."""
import http.client
import json
import os
import shlex
import socket

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


def environment(sock_path: str, gh_config_dir: str) -> dict:
    """git reaches the socket as a SOCKS5 proxy; gh through http_unix_socket."""
    sock_path = os.path.abspath(sock_path)
    ident = local_get(sock_path, "/_gh-cred-proxy/identity")
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
