"""The client side (env, status, audit) runs inside an agent's box, often straight from a
read-only checkout with no dependencies installed. It must import with the standard library
alone."""
import os
import subprocess
import sys
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
PROBE = r'''
import json, os, socket, sys, tempfile, threading
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in ("graphql", "cryptography"):
            raise ImportError("blocked for this test: " + name)
sys.meta_path.insert(0, Block())
from airlock_cred_proxy import cli

# A fake proxy answering the two local endpoints, so the SUCCESS paths run too.
d = tempfile.mkdtemp(prefix="gcpdeps.", dir="/tmp")
sock = os.path.join(d, "p.sock")
srv = socket.socket(socket.AF_UNIX); srv.bind(sock); srv.listen(8)
ident = {"login": "bot[bot]", "id": 1, "email": "1+bot[bot]@users.noreply.github.com",
         "api_host": "api.github.com", "git_host": "github.com"}
def serve():
    while True:
        c, _ = srv.accept()
        req = c.recv(4096).split(b" ")[1]
        body = json.dumps({"status": "ok"} if b"health" in req else ident).encode()
        c.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s" % (len(body), body))
        c.close()
threading.Thread(target=serve, daemon=True).start()
log = os.path.join(d, "audit.jsonl")
open(log, "w").write('{"ts":"t","decision":"deny","reason":"r"}\n')

rcs = [cli.main(["status", "--socket", sock]),
       cli.main(["env", "--socket", sock, "--gh-config-dir", os.path.join(d, "gh")]),
       cli.main(["audit", "--log", log, "--denied"]),
       cli.main(["status", "--socket", "/nonexistent/airlock-cred-proxy.sock"]),
       cli.main(["env", "--socket", "/nonexistent/airlock-cred-proxy.sock", "--gh-config-dir", os.path.join(d, "gh2")])]
print("rcs", rcs)
'''


class ClientDeps(unittest.TestCase):
    def test_client_commands_need_only_the_standard_library(self):
        r = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": SRC}, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        # success paths of status, env and audit; clean failures (no traceback) when unreachable
        self.assertIn("rcs [0, 0, 0, 1, 1]", r.stdout, r.stderr)
        self.assertNotIn("Traceback", r.stderr)


if __name__ == "__main__":
    unittest.main()
