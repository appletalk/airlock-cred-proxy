import contextlib
import io
import json
import os
import tempfile
import unittest

from airlock_cred_proxy import cli


class Audit(unittest.TestCase):
    def test_audit_output_escapes_control_characters(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            f.write(json.dumps({"ts": "t", "decision": "deny", "path": "/\x1b]0;PWNED\x07\x9bx",
                                "reason": "r\x1b[2J"}) + "\n")
        try:
            for extra in ([], ["--summary"]):
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    cli.main(["audit", "--log", f.name, *extra])
                text = out.getvalue()
                self.assertNotIn("\x1b", text)
                self.assertNotIn("\x9b", text)
                self.assertNotIn("\x07", text)
        finally:
            os.unlink(f.name)


class AuditFilter(unittest.TestCase):
    def test_denied_includes_errors(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as f:
            for d in ("allow", "deny", "error"):
                f.write(json.dumps({"ts": "t", "decision": d, "reason": f"r-{d}"}) + "\n")
        try:
            out = io.StringIO()
            with contextlib.redirect_stdout(out):
                cli.main(["audit", "--log", f.name, "--denied"])
            text = out.getvalue()
            self.assertIn("r-deny", text)
            self.assertIn("r-error", text)
            self.assertNotIn("r-allow", text)
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
