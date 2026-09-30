"""The client side (env, status, audit) runs inside an agent's box, often straight from a
read-only checkout with no dependencies installed. It must import with the standard library
alone."""
import os
import subprocess
import sys
import unittest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
PROBE = r'''
import sys
class Block:
    def find_spec(self, name, path=None, target=None):
        if name.split(".")[0] in ("graphql", "cryptography"):
            raise ImportError("blocked for this test: " + name)
sys.meta_path.insert(0, Block())
from gh_cred_proxy import cli, client
rc = cli.main(["status", "--socket", "/nonexistent/gh-cred-proxy.sock"])
print("rc", rc)
'''


class ClientDeps(unittest.TestCase):
    def test_client_commands_need_only_the_standard_library(self):
        r = subprocess.run([sys.executable, "-c", PROBE], capture_output=True, text=True,
                           env={**os.environ, "PYTHONPATH": SRC}, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("rc 1", r.stdout)            # status ran, and reported the missing socket


if __name__ == "__main__":
    unittest.main()
