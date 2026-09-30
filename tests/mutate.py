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
 ("REST merge lookup", "server.py", 'if d.lookup:\n                px.resolve_lookup(d, cred)', 'if False:\n                pass'),
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
 ("socket activation", "server.py", '    inherited = _systemd_sockets().get("data")\n', '    inherited = None\n'),
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
 ("unlock: 423 marker header", "server.py", '        if status == LOCKED_STATUS:\n            self.send_header("X-Airlock-Cred-Proxy", "locked")\n', ''),
 ("unlock: upstream marker stripped", "server.py", '"set-cookie", "x-airlock-cred-proxy"}', '"set-cookie"}'),
 ("unlock: expire_at strictly after now", "unlock.py", '        if ts <= now:', '        if ts < now:'),
 ("unlock: expire_at applied", "unlock.py", '        d = min(d, ts)', '        pass'),
 ("unlock: idle lock", "unlock.py", 'if idle is not None and now - self._last_used >= idle:', 'if False:'),
 ("unlock: boot-clock deadline", "unlock.py", 'if now >= self._expires_at or self.boot() >= self._boot_deadline:', 'if now >= self._expires_at:'),
 ("unlock: lock drops the credential", "unlock.py", '            if self._cred is not None:\n                self._drop(reason)', '            if False:\n                self._drop(reason)'),
 ("unlock: lock during unlock check", "unlock.py", '            if self._generation != gen:', '            if False:'),
 ("unlock: timer checks without traffic", "unlock.py", '        while not stop.is_set():\n            self.check()', '        while not stop.is_set():\n            pass'),
 ("unlock: admin peer uid", "unlock.py", 'if uid is None or uid != st.st_uid:', 'if False:'),
 ("unlock: admin socket mode", "unlock.py", '        if st.st_mode & 0o077:', '        if False:'),
 ("unlock: admin not bound by a system account", "server.py", 'if os.getuid() < client.login_uid_min():', 'if False:'),
 ("unlock: not dumpable", "server.py", 'if libc.prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0:', 'if False:'),
 ("unlock: two activated sockets need names", "server.py", 'if sorted(names) != ["admin", "data"]:', 'if False:'),
 ("unlock: client admin dir owned by root", "client.py", '        if st.st_uid != 0:', '        if False:'),
 ("unlock: client admin symlink", "client.py", '    if real != os.path.abspath(path):', '    if False:'),
 ("unlock: client admin peer", "client.py", 'if uid == os.getuid() or (uid != 0 and uid >= login_uid_min()):', 'if False:'),
 ("unlock: client entry check", "cli.py", '    if not config.valid_pass_entry(entry):', '    if False:'),
 ("unlock: env empty identity before unlock", "client.py", '"login": "", "email": ""}', '"login": "someone", "email": "s@example.com"}'),
 ("unlock: pass entry pattern", "config.py", 'PASS_ENTRY = re.compile(r"[A-Za-z0-9_@+][A-Za-z0-9._@+-]*(?:/[A-Za-z0-9_@+][A-Za-z0-9._@+-]*)*")', 'PASS_ENTRY = re.compile(r"[A-Za-z0-9._/@+-]+")'),
 ("unlock: pass needs [unlock]", "config.py", '    if cfg.pass_entry and cfg.unlock is None:', '    if False:'),
 ("unlock: proxy never reads pass", "config.py", '    if k == "pass":\n        raise ConfigError', '    if False:\n        raise ConfigError'),
 ("unlock: 24h cap", "config.py", '    if life > MAX_DAY_LIFETIME:', '    if False:'),
 ("unlock: allowed request resets idle", "server.py", '            px.gate.touch()\n', ''),
 ("unlock: static config refuses an admin fd", "server.py", '    if cfg.unlock is None and "admin" in _systemd_sockets():', '    if False:'),
 ("unlock: activated unlock needs its admin fd", "server.py", '    elif acts:\n        raise SystemExit', '    elif False:\n        raise SystemExit'),
 ("unlock: for_seconds validation", "unlock.py", 'if for_s is not None and (not isinstance(for_s, int) or isinstance(for_s, bool) or for_s <= 0):', 'if False:'),
 ("unlock: admin refuses chunked", "unlock.py", 'if not self.headers.get("Transfer-Encoding") and n.isdigit() and int(n) <= ADMIN_MAX_BODY:', 'if n.isdigit() and int(n) <= ADMIN_MAX_BODY:'),
 ("unlock: client admin dir not writable by others", "client.py", '        if st.st_mode & 0o022 and (first or not st.st_mode & 0o1000):', '        if st.st_mode & 0o022 and not st.st_mode & 0o1000:'),
 ("unlock: for capped at max_lifetime", "unlock.py", '        d = now + min(for_seconds, u.max_lifetime)', '        d = min(d, now + for_seconds)'),
 ("unlock: DST-naive expire_at", "unlock.py", '            ts = time.mktime((at + dt.timedelta(days=1)).timetuple())', '            ts = ts + 86400'),
 ("unlock: any build failure is a 422", "unlock.py", '        except Exception as e:  # noqa: BLE001 - any failure to build leaves the gate as it was', '        except (ValueError, KeyError) as e:'),
 ("unlock: audit failure does not hide an unlock", "unlock.py", '        except Exception:  # noqa: BLE001 - installed is installed; a failed audit write must not report otherwise\n            pass', '        finally:\n            pass'),
 ("unlock: expiry does not bump generation", "unlock.py", '        # Dropping the credential drops its cache of minted App tokens with it.\n        self._cred = None', '        # Dropping the credential drops its cache of minted App tokens with it.\n        self._generation += 1\n        self._cred = None'),
]
bad = 0
for label, f, old, new in MUTANTS:
    d = tempfile.mkdtemp(prefix="gcpmut.", dir="/tmp")
    shutil.copytree(SRC, d, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".venv", ".git"))
    p = os.path.join(d, "src/airlock_cred_proxy", f)
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
