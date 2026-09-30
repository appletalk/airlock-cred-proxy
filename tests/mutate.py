"""Break each protection in a scratch copy and require the test suite to fail."""
import os, shutil, subprocess, sys, tempfile
SRC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MUTANTS = [
 ("strip client auth", "server.py", 'STRIP_REQUEST = HOP_BY_HOP | {"host", "authorization",', 'STRIP_REQUEST = HOP_BY_HOP | {"host",'),
 ("REST approval check", "policy.py", 'if policy.deny_approvals and (event or "").upper() == "APPROVE":', 'if False:'),
 ("graphql variable defaults", "policy.py", 'op_vars[vname] = _value(vd.default_value, {})', 'pass'),
 ("duplicate JSON keys", "policy.py", 'return json.loads(body, object_pairs_hook=_no_dupes)', 'return json.loads(body)'),
 ("ref update check", "server.py", 'd = policy.check_ref_updates(pol, d.repo, updates)', 'pass'),
 ("canonical path", "server.py", 'or any(seg in (".", "..") for seg in path.split("/")):', ':'),
 ("smuggling framing", "server.py", 'if te and cl:\n        raise Refused(400, "both Transfer-Encoding and Content-Length")', 'if False:\n        pass'),
 ("REST merge lookup", "server.py", 'if d.lookup:\n                px.resolve_lookup(d)', 'if False:\n                pass'),
 ("per-repo token scope", "server.py", '        return (name,)', '        return None'),
 ("repo allowlist", "config.py", 'return full_name.lower() in {r.lower() for r in self.repos}', 'return True'),
 ("project pin", "policy.py", 'if name in PROJECT_MUTATIONS and policy.projects is not None:', 'if False:'),
 ("rest_writes switch", "policy.py", 'if not policy.rest_writes:', 'if False:'),
 ("mutation allowlist", "policy.py", 'if name not in policy.mutations:', 'if False:'),
 ("graphql retarget check", "policy.py", 'lookups.append({"id": pr, "base": normalise_branch(base)})', 'pass'),
 ("auto-merge out of defaults", "config.py", '"markPullRequestReadyForReview", "mergePullRequest",', '"markPullRequestReadyForReview", "mergePullRequest", "enablePullRequestAutoMerge",'),
 ("percent and /repos/ shape", "policy.py", 'if "%" in path and not CONTENTS_PATH.match(path):\n        return deny("percent-encoding is only accepted in a contents file path")\n    rm = REPO_PATH.match(path)\n    if path.startswith("/repos/") and not rm:\n        return deny("unrecognised /repos/ path")', 'rm = REPO_PATH.match(path)'),
 ("query on writes", "server.py", 'if query and self.command not in policy.READ_METHODS and host == cfg.api_host:', 'if False:'),
 ("method override", "server.py", 'if any(h in self.headers for h in METHOD_OVERRIDE):', 'if False:'),
 ("archive refusal", "policy.py", 'if REFUSED_READS.match(path):', 'if False:'),
 ("chunk read in pieces", "server.py", '        while size > 0:\n            b = _read_exact(rfile, min(CHUNK, size))\n            size -= len(b)\n            yield b', '        yield _read_exact(rfile, size)'),
 ("connection cap", "server.py", 'if not self._slots.acquire(blocking=False):', 'if not self._slots.acquire(blocking=False) and False:'),
 ("graphql duplicate fields", "policy.py", '            if f.name.value in out:\n                return UNRESOLVED', ''),
 ("undeclared variables", "policy.py", 'return variables[name] if name in variables else UNRESOLVED', 'return variables.get(name)'),
 ("graphql depth limits (both layers)", "policy.py", '    if _too_deep(req["query"]):\n        return deny(f"graphql document nested deeper than {GQL_MAX_DEPTH}")\n    try:\n        doc = gql_parse(req["query"], no_location=True, max_tokens=GQL_MAX_TOKENS)\n    except GraphQLError as e:\n        return deny(f"graphql parse error: {e.message}")\n    except RecursionError:\n        return deny("graphql document too deeply nested")', '    try:\n        doc = gql_parse(req["query"], no_location=True, max_tokens=GQL_MAX_TOKENS)\n    except GraphQLError as e:\n        return deny(f"graphql parse error: {e.message}")'),
 ("socks host match", "server.py", 'if self.socks_target and host != self.socks_target:', 'if False:'),
 ("socks target check", "server.py", 'ok = ver == 5 and cmd == 1 and host in (cfg.git_host, cfg.api_host) and port == 80', 'ok = True'),
 ("branch normalisation", "config.py", '        branch = normalise_branch(branch)\n', ''),
 ("string-typed fields", "policy.py", '    if v is not None and not isinstance(v, str):', '    if False:'),
 ("socket activation", "server.py", '    inherited = _systemd_socket()\n', '    inherited = None\n'),
 ("deadline at raw read", "server.py", '            if left <= 0:\n                raise TimeoutError("request deadline passed")\n            self._sock.settimeout(min(CLIENT_TIMEOUT, left))', '            self._sock.settimeout(CLIENT_TIMEOUT)'),
 ("release slots on thread-start failure", "server.py", '            self._slots.release()\n            self._release_peer(uid)\n            self.proxy.audit.write', '            self.proxy.audit.write'),
 ("parse slot after upload", "server.py", '    raw = buffer_body(it, limit)\n    if not _inspect_slots.acquire(timeout=INSPECT_WAIT):\n        raise Refused(503, "too many requests being inspected")\n    try:\n        return raw, decide(raw)', '    if not _inspect_slots.acquire(timeout=INSPECT_WAIT):\n        raise Refused(503, "too many requests being inspected")\n    try:\n        raw = buffer_body(it, limit)\n        return raw, decide(raw)'),
 ("header control characters", "server.py", '                    or any(BAD_HEADER_VALUE.search(v) for v in self.headers.values()):', '                    or False:'),
 ("encoded inspected bodies", "server.py", '                if inspected and self.headers.get("Content-Encoding"):', '                if False:'),
 ("trailing slash", "server.py", '            if host == cfg.api_host and len(path) > 1 and path.endswith("/"):', '            if False:'),
 ("client timeout restored after authorisation", "server.py", '            self.connection.settimeout(CLIENT_TIMEOUT)   # writes use it too; drop the residual deadline\n', ''),
 ("per-uid cap", "server.py", 'if self._per_peer.get(uid, 0) >= MAX_PER_PEER:', 'if False:'),
 ("inspection slots", "server.py", '    if not _inspect_slots.acquire(timeout=INSPECT_WAIT):\n        raise Refused(503, "too many requests being inspected")', '    _inspect_slots.acquire()'),
 ("malformed header block", "server.py", 'if self.headers.defects or self.headers.get_payload() \\', 'if False \\'),
 ("release asset refusal", "policy.py", '|releases/assets/\\d+)$")', ')$")'),
 ("depth pre-check skips strings", "policy.py", '        if ch == \'"\':\n            i += 1', '        if False:\n            i += 1'),
 ("classified mutations only", "config.py", 'unknown = sorted(set(mutations) - SAFE_MUTATIONS)', 'unknown = []'),
 ("audit --denied includes errors", "cli.py", 'if a.denied and r.get("decision") not in ("deny", "error"):', 'if a.denied and r.get("decision") != "deny":'),
 ("audit escaping", "cli.py", 'return UNPRINTABLE.sub(lambda m: f"\\\\x{ord(m.group()):02x}", str(v if v is not None else ""))', 'return str(v if v is not None else "")'),
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
    r = subprocess.run([f"{SRC}/.venv/bin/python", "-m", "unittest", "discover", "-s", "tests", "-t", "."], cwd=d,
                       env={**os.environ, "PYTHONPATH": os.path.join(d, "src")}, capture_output=True, text=True, timeout=300)
    killed = r.returncode != 0
    fails = [l.split("(")[0].replace("FAIL: ","").replace("ERROR: ","") for l in r.stderr.splitlines() if l.startswith(("FAIL:","ERROR:"))]
    print(f"{'KILLED' if killed else 'SURVIVED'}  {label}: {', '.join(fails[:3])}")
    bad += 0 if killed else 1
    shutil.rmtree(d)
sys.exit(bad)
