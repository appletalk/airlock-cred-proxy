"""Credential providers. Each returns an Authorization value for a given scope.

GitHub App: https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app
"""
import base64
import datetime as dt
import http.client
import json
import threading
import time
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .config import Config, ConfigError, read_source

REFRESH_MARGIN = 300


class UpstreamError(RuntimeError):
    pass


def api_call(base_url: str, method: str, path: str, auth: str, body=None, timeout=30):
    u = urlsplit(base_url)
    conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
    conn = conn_cls(u.hostname, u.port, timeout=timeout)
    try:
        headers = {"Authorization": auth, "Accept": "application/vnd.github+json",
                   "User-Agent": "airlock-cred-proxy", "X-GitHub-Api-Version": "2022-11-28"}
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, u.path + path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        if r.status >= 300:
            raise UpstreamError(f"{method} {path} -> HTTP {r.status}: {raw[:200]!r}")
        return json.loads(raw or b"null")
    finally:
        conn.close()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class AppCredential:
    """Mints installation tokens scoped per request and caches them until near expiry."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        pem = read_source(cfg.key_source)
        try:
            self._key = serialization.load_pem_private_key(pem.encode(), password=None)
        except ValueError as e:
            raise ConfigError(f"identity.key is not a usable PEM private key: {e}") from None
        del pem
        self._lock = threading.Lock()
        self._cache: dict[tuple, tuple[str, float]] = {}
        self.installation_id = cfg.installation_id or self._find_installation()
        self.identity = self._resolve_identity()

    def _jwt(self) -> str:
        now = int(time.time())
        head = _b64(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        body = _b64(json.dumps({"iat": now - 60, "exp": now + 540, "iss": self.cfg.app_id}).encode())
        sig = self._key.sign(f"{head}.{body}".encode(), padding.PKCS1v15(), hashes.SHA256())
        return f"{head}.{body}.{_b64(sig)}"

    def _find_installation(self) -> int:
        for inst in api_call(self.cfg.api_url, "GET", "/app/installations", f"Bearer {self._jwt()}"):
            if inst["account"]["login"].lower() == self.cfg.owner.lower():
                return int(inst["id"])
        raise ConfigError(f"app {self.cfg.app_id} has no installation on {self.cfg.owner}")

    def _resolve_identity(self) -> dict:
        app = api_call(self.cfg.api_url, "GET", "/app", f"Bearer {self._jwt()}")
        login = f"{app['slug']}[bot]"
        user = api_call(self.cfg.api_url, "GET", f"/users/{login}",
                        self.authorization(None, self.cfg.policy.read_permissions()))
        return {"login": login, "id": user["id"],
                "email": f"{user['id']}+{login}@users.noreply.github.com"}

    def token(self, repos: tuple[str, ...] | None, permissions: dict[str, str]) -> str:
        """repos: repo names (no owner) to scope to, or None for every repo the policy allows."""
        if repos is None and "*" not in self.cfg.policy.repos:
            repos = tuple(sorted(r.split("/", 1)[1] for r in self.cfg.policy.repos))
        key = (repos, tuple(sorted(permissions.items())))
        with self._lock:
            hit = self._cache.get(key)
            if hit and hit[1] - REFRESH_MARGIN > time.time():
                return hit[0]
            body = {"permissions": permissions}
            if repos is not None:
                body["repositories"] = list(repos)
            r = api_call(self.cfg.api_url, "POST", f"/app/installations/{self.installation_id}/access_tokens",
                         f"Bearer {self._jwt()}", body)
            exp = dt.datetime.fromisoformat(r["expires_at"].replace("Z", "+00:00")).timestamp()
            self._cache[key] = (r["token"], exp)
            return r["token"]

    def authorization(self, repos, permissions) -> str:
        return f"token {self.token(repos, permissions)}"

    def git_authorization(self, repos, permissions) -> str:
        raw = f"x-access-token:{self.token(repos, permissions)}".encode()
        return f"Basic {base64.b64encode(raw).decode()}"


class TokenCredential:
    """A fixed token (for example a user's session token). Scope comes from policy only."""

    def __init__(self, cfg: Config):
        self.cfg = cfg
        self._token = read_source(cfg.token_source).strip()
        if not self._token:
            raise ConfigError("identity.token resolved to an empty string")
        user = api_call(cfg.api_url, "GET", "/user", f"token {self._token}")
        self.identity = {"login": user["login"], "id": user["id"],
                         "email": f"{user['id']}+{user['login']}@users.noreply.github.com"}

    def token(self, repos, permissions) -> str:
        return self._token

    def authorization(self, repos, permissions) -> str:
        return f"token {self._token}"

    def git_authorization(self, repos, permissions) -> str:
        raw = f"{self.identity['login']}:{self._token}".encode()
        return f"Basic {base64.b64encode(raw).decode()}"


def build(cfg: Config):
    return AppCredential(cfg) if cfg.kind == "github-app" else TokenCredential(cfg)
