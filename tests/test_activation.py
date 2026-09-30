import os
import subprocess
import sys
import tempfile
import unittest

CHILD = r'''
import os, socket, sys
from airlock_cred_proxy import config, server
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX); s.bind(path); s.listen(4)
os.dup2(s.fileno(), 3)
os.environ.update(LISTEN_PID=str(os.getpid()), LISTEN_FDS="1")
cfg = config.parse({"server": {"socket": path, "socket_group": "no-such-group-anywhere"},
                    "identity": {"kind": "token", "token": {"command": ["true"]}}, "policy": {"repos": ["*"]}})
srv = server.bind(cfg, proxy=None)
assert srv.socket.fileno() == 3, srv.socket.fileno()
assert srv.socket.getsockname() == path
assert "LISTEN_FDS" not in os.environ
print("ok")
'''


class Activation(unittest.TestCase):
    def test_inherited_socket_is_used_without_chown(self):
        # socket_group names a group that does not exist: the activated path must never look it up.
        d = tempfile.mkdtemp(prefix="gcpa.", dir="/tmp")
        r = subprocess.run([sys.executable, "-c", CHILD, os.path.join(d, "s.sock")],
                           capture_output=True, text=True, timeout=30,
                           env={**os.environ, "PYTHONPATH": os.path.join(os.path.dirname(__file__), "..", "src")})
        self.assertEqual(r.stdout.strip(), "ok", r.stderr)


if __name__ == "__main__":
    unittest.main()
