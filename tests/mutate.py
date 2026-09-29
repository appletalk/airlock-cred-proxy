"""Break each protection in a scratch copy and require the test suite to fail."""
import os, shutil, subprocess, sys, tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTANTS = [
 ("strip client auth", "server.py", 'STRIP_REQUEST = HOP_BY_HOP | {"host", "authorization",', 'STRIP_REQUEST = HOP_BY_HOP | {"host",'),
 ("REST approval check", "policy.py", 'if policy.deny_approvals and str(event).upper() == "APPROVE":', 'if False:'),
 ("graphql variable defaults", "policy.py", 'op_vars[vname] = _value(vd.default_value, {})', 'pass'),
 ("duplicate JSON keys", "policy.py", 'return json.loads(body, object_pairs_hook=_no_dupes)', 'return json.loads(body)'),
 ("ref update check", "server.py", 'd = policy.check_ref_updates(pol, d.repo, updates)', 'pass'),
 ("canonical path", "server.py", 'or any(seg in (".", "..") for seg in path.split("/")):', ':'),
 ("smuggling framing", "server.py", 'if te and cl:\n        raise Refused(400, "both Transfer-Encoding and Content-Length")', 'if False:\n        pass'),
 ("REST merge lookup", "server.py", 'if d.lookup:\n                px.resolve_lookup(d)', 'if False:\n                pass'),
 ("forwarder auth", "client.py", 'if not authed:', 'if False:'),
 ("per-repo token scope", "server.py", '        return (name,)', '        return None'),
 ("repo allowlist", "config.py", 'return full_name.lower() in {r.lower() for r in self.repos}', 'return True'),
 ("mutation allowlist", "policy.py", 'if name not in policy.mutations:', 'if False:'),
]
bad = 0
for label, f, old, new in MUTANTS:
    d = tempfile.mkdtemp(prefix="gcpmut.", dir="/tmp")
    shutil.copytree(SRC, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".venv", ".git"))
    p = os.path.join(d, "src/gh_cred_proxy", f)
    s = open(p).read()
    if s.count(old) != 1:
        print(f"SKIP  {label}: pattern count {s.count(old)}"); bad += 1; continue
    open(p, "w").write(s.replace(old, new))
    r = subprocess.run([f"{SRC}/.venv/bin/python", "-m", "unittest", "tests.test_proxy"], cwd=d,
                       env={**os.environ, "PYTHONPATH": os.path.join(d, "src")}, capture_output=True, text=True, timeout=300)
    killed = r.returncode != 0
    fails = [l.split("(")[0].replace("FAIL: ","").replace("ERROR: ","") for l in r.stderr.splitlines() if l.startswith(("FAIL:","ERROR:"))]
    print(f"{'KILLED' if killed else 'SURVIVED'}  {label}: {', '.join(fails[:3])}")
    bad += 0 if killed else 1
    shutil.rmtree(d)
sys.exit(bad)
