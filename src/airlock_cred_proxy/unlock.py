"""Lock state for a credential delivered at unlock time, and the admin socket that delivers it.

Design: docs/unlock.md. The admin socket has three verbs: status, unlock and lock. Unlock
always carries the secret itself; nothing extends or renews a lock without it.
"""
import datetime as dt
import json
import os
import socket
import socketserver
import stat
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler

from . import credentials
from .config import Config

ADMIN_MAX_BODY = 256 * 1024
ADMIN_TIMEOUT = 30
TIMER_MAX_SLEEP = 30


class Locked(Exception):
    pass


def boottime() -> float:
    """Counts through suspend and never steps backwards, unlike the wall clock."""
    return time.clock_gettime(time.CLOCK_BOOTTIME)


def fmt(ts: float | None) -> str | None:
    return None if ts is None else time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(ts))


def deadline(now: float, cfg: Config, for_seconds: int | None = None) -> float:
    """The earliest of: now + max_lifetime, now + for_seconds, and the next expire_at after now."""
    u = cfg.unlock
    d = now + u.max_lifetime
    if for_seconds is not None:
        d = now + min(for_seconds, u.max_lifetime)
    if u.expire_at is not None:
        # Naive local time plus mktime with isdst=-1 keeps "18:00" at 18:00 across DST changes.
        local = dt.datetime.fromtimestamp(now)
        at = local.replace(hour=u.expire_at[0], minute=u.expire_at[1], second=0, microsecond=0)
        ts = time.mktime(at.timetuple())
        if ts <= now:
            ts = time.mktime((at + dt.timedelta(days=1)).timetuple())
        d = min(d, ts)
    return d


class StaticGate:
    """A credential read at start from a file, command or systemd credential: never locks."""

    unlockable = False

    def __init__(self, cred):
        self._cred = cred
        self.identity = cred.identity

    def current(self):
        return self._cred

    def touch(self):
        pass

    def status(self) -> dict:
        return {"state": "static"}


class UnlockGate:
    """Holds the credential in memory between an unlock and its deadline. Locked at start."""

    unlockable = True

    def __init__(self, cfg: Config, audit=None, clock=time.time, build=credentials.build, boot=boottime):
        self.cfg, self.audit, self.clock, self._build, self.boot = cfg, audit, clock, build, boot
        self._lock = threading.Lock()
        self._cred = None
        self._expires_at = None
        self._boot_deadline = None   # the same lifetime on the boot clock: a wall clock set back cannot extend it
        self._last_used = None
        self._generation = 0         # bumped by every lock; an unlock that raced one does not install
        self._locked_reason = "not unlocked since start"
        self._wake = threading.Event()
        self.identity = None      # from the last unlock; not secret, and env needs it

    def _log(self, **rec):
        if self.audit:
            self.audit.write({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), **rec})

    def _due(self, now) -> str | None:
        if self._cred is None:
            return None
        if now >= self._expires_at or self.boot() >= self._boot_deadline:
            return f"expired {fmt(self._expires_at)}"
        idle = self.cfg.unlock.idle
        if idle is not None and now - self._last_used >= idle:
            return f"idle for {idle}s"
        return None

    def _drop(self, reason):
        # Dropping the credential drops its cache of minted App tokens with it.
        self._cred = None
        self._expires_at = self._boot_deadline = None
        self._locked_reason = reason
        self._log(event="lock", reason=reason)

    def check(self):
        """Lock now if a deadline has passed. Called on every use and by the timer."""
        with self._lock:
            why = self._due(self.clock())
            if why:
                self._drop(why)

    def current(self):
        with self._lock:
            why = self._due(self.clock())
            if why:
                self._drop(why)
            if self._cred is None:
                raise Locked(self._locked_reason)
            return self._cred

    def touch(self):
        with self._lock:
            if self._cred is not None:
                self._last_used = self.clock()

    def unlock(self, secret: str, for_seconds: int | None = None) -> dict:
        """Build the credential from the delivered secret; it checks itself against GitHub.

        A secret that does not work leaves the gate as it was.
        """
        with self._lock:
            gen = self._generation
        cred = self._build(self.cfg, secret)      # talks to GitHub; a lock may land meanwhile
        with self._lock:
            if self._generation != gen:
                raise Locked("locked while the unlock was being checked")
            now = self.clock()
            expires = deadline(now, self.cfg, for_seconds)     # before installing anything
            self._cred = cred
            self.identity = cred.identity
            self._expires_at = expires
            self._boot_deadline = self.boot() + (expires - now)
            self._last_used = now
        self._wake.set()
        try:
            self._log(event="unlock", identity=cred.identity.get("login"), expires_at=fmt(self._expires_at))
        except Exception:  # noqa: BLE001 - installed is installed; a failed audit write must not report otherwise
            pass
        return self.status()

    def lock(self, reason="locked by operator"):
        # Only an explicit lock discards an unlock in flight; expiry during a renewal does not.
        with self._lock:
            self._generation += 1
            if self._cred is not None:
                self._drop(reason)
            else:
                self._locked_reason = reason

    def status(self) -> dict:
        with self._lock:
            why = self._due(self.clock())
            if why:
                self._drop(why)
            if self._cred is None:
                return {"state": "locked", "reason": self._locked_reason}
            out = {"state": "unlocked", "expires_at": fmt(self._expires_at),
                   "expires_at_epoch": int(self._expires_at),
                   "expires_in": int(min(self._expires_at - self.clock(), self._boot_deadline - self.boot()))}
            if self.cfg.unlock.idle is not None:
                out["idle_lock_in"] = int(self._last_used + self.cfg.unlock.idle - self.clock())
            return out

    def run_timer(self, stop: threading.Event):
        """Lock at the deadline even when no request arrives."""
        while not stop.is_set():
            self.check()
            with self._lock:
                nxt = None
                if self._cred is not None:
                    nxt = self._expires_at
                    if self.cfg.unlock.idle is not None:
                        nxt = min(nxt, self._last_used + self.cfg.unlock.idle)
            wait = TIMER_MAX_SLEEP if nxt is None else max(0.05, min(TIMER_MAX_SLEEP, nxt - self.clock()))
            self._wake.wait(wait)
            self._wake.clear()


class AdminHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "airlock-cred-proxy-admin"
    sys_version = ""
    timeout = ADMIN_TIMEOUT

    def log_message(self, fmt_, *args):
        pass

    def address_string(self):
        return "unix"

    def _reply(self, status, obj):
        data = json.dumps(obj).encode()
        self.send_response_only(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def _peer_uid(self):
        try:
            return struct.unpack("3i", self.request.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")))[1]
        except OSError:
            return None

    def _authorised(self) -> str | None:
        """None if the peer may administer; otherwise why not."""
        path = self.server.path
        try:
            st = os.stat(path)
        except OSError:
            return "admin socket path is missing"
        if not stat.S_ISSOCK(st.st_mode):
            return "admin socket path is not a socket"
        if st.st_mode & 0o077:
            return "admin socket must be mode 0600"
        uid = self._peer_uid()
        if uid is None or uid != st.st_uid:
            return "peer is not the admin socket's owner"
        return None

    def _handle(self):
        gate: UnlockGate = self.server.gate
        self.close_connection = True
        rec = {"event": "admin", "method": self.command, "path": self.path, "peer_uid": self._peer_uid()}
        # Read a well-framed body before deciding anything: a reply sent while the client is
        # still writing reaches it as a broken pipe instead of the reason for the refusal.
        self._body = None
        n = self.headers.get("Content-Length", "")
        if not self.headers.get("Transfer-Encoding") and n.isdigit() and int(n) <= ADMIN_MAX_BODY:
            self._body = self.rfile.read(int(n))
        try:
            why = self._authorised()
            if why:
                rec.update(decision="deny", reason=why)
                return self._reply(403, {"error": why})
            if self.command == "GET" and self.path == "/status":
                rec.update(decision="status")
                return self._reply(200, {**gate.status(), "entries": [gate.cfg.pass_entry],
                                         "identity": (gate.identity or {}).get("login")})
            if self.command == "POST" and self.path == "/lock":
                gate.lock()
                rec.update(decision="lock")
                return self._reply(200, gate.status())
            if self.command == "POST" and self.path == "/unlock":
                return self._unlock(gate, rec)
            rec.update(decision="deny", reason="unknown admin request")
            return self._reply(404, {"error": "admin verbs are GET /status, POST /unlock and POST /lock"})
        finally:
            gate._log(**rec)

    def _unlock(self, gate, rec):
        if self._body is None:
            rec.update(decision="deny", reason="unlock needs a Content-Length body under the limit")
            return self._reply(400, {"error": rec["reason"]})
        try:
            req = json.loads(self._body)
            secret = req["secrets"][gate.cfg.pass_entry]
            for_s = req.get("for_seconds")
            if not isinstance(secret, str) or not secret.strip():
                raise ValueError("empty secret")
            if for_s is not None and (not isinstance(for_s, int) or isinstance(for_s, bool) or for_s <= 0):
                raise ValueError("for_seconds must be a positive integer")
        except (ValueError, KeyError, TypeError) as e:
            rec.update(decision="deny", reason=f"bad unlock request: {e.__class__.__name__}")
            return self._reply(400, {"error": rec["reason"]})
        try:
            st = gate.unlock(secret, for_s)
        except Locked as e:
            rec.update(decision="deny", reason=str(e))
            return self._reply(409, {"error": rec["reason"], **gate.status()})
        except Exception as e:  # noqa: BLE001 - any failure to build leaves the gate as it was
            rec.update(decision="deny", reason=f"credential did not work: {e.__class__.__name__}")
            return self._reply(422, {"error": rec["reason"], **gate.status()})
        finally:
            del secret
        rec.update(decision="unlock", expires_at=st.get("expires_at"))
        return self._reply(200, {**st, "identity": gate.identity.get("login")})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle


class AdminServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = False

    def handle_error(self, request, client_address):
        pass
