"""Per-repo permission sets: [policy.repo."owner/name"] permissions = {...}."""
import base64
import contextlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import threading
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from airlock_cred_proxy import cli, client, config, credentials, policy, server

from . import fakegithub

GLOBAL = {"metadata": "read", "contents": "write", "pull_requests": "write", "issues": "write"}
ISSUES_ONLY = {"metadata": "read", "issues": "write"}


def parse(repo_tables=None, kind="github-app", **over):
    pol = {"repos": ["acme/app", "acme/other", "acme/tracker"], "push_branches": ["agent/*"],
           "merge_denied_bases": ["main"],
           "repo": {"acme/tracker": {"permissions": {"issues": "write"}}} if repo_tables is None else repo_tables,
           **over}
    ident = {"kind": "github-app", "app_id": 1, "owner": "acme", "key": {"file": "/dev/null"}} \
        if kind == "github-app" else {"kind": "token", "token": {"command": ["true"]}}
    return config.parse({"server": {"socket": "/tmp/x.sock"}, "identity": ident, "policy": pol})


def gql(query, variables=None):
    return json.dumps({"query": query, "variables": variables or {}}).encode()


CREATE_ISSUE = 'mutation { createIssue(input:{repositoryId:"R", title:"t"}) { issue { id } } }'
CREATE_PR = ('mutation { createPullRequest(input:{repositoryId:"R", baseRefName:"dev", headRefName:"agent/x", '
             'title:"t"}) { pullRequest { id } } }')
MIXED = ('mutation { createIssue(input:{repositoryId:"R", title:"t"}) { issue { id } } '
         'createPullRequest(input:{repositoryId:"R", baseRefName:"dev", headRefName:"agent/x", title:"t"}) '
         '{ pullRequest { id } } }')


class ConfigTest(unittest.TestCase):
    def test_effective_sets(self):
        p = parse().policy
        self.assertEqual(p.repo_permissions("acme/tracker"), ISSUES_ONLY)
        self.assertEqual(p.repo_permissions("ACME/Tracker"), ISSUES_ONLY)
        self.assertEqual(p.repo_permissions("acme/app"), GLOBAL)
        self.assertEqual(p.full_repos(), ["acme/app", "acme/other"])

    def test_shared_set_is_the_lowest_level_every_repo_grants(self):
        p = parse({"acme/tracker": {"permissions": {"issues": "write", "contents": "read", "pull_requests": "read"}},
                   "acme/other": {"permissions": {"issues": "read", "contents": "write"}}}).policy
        self.assertEqual(p.shared_permissions(), {"metadata": "read", "issues": "read", "contents": "read"})
        self.assertEqual(p.read_permissions(), {"metadata": "read", "issues": "read", "contents": "read"})
        self.assertEqual(p.read_permissions("acme/other"), {"metadata": "read", "issues": "read", "contents": "read"})

    def test_no_per_repo_sets_leaves_everything_global(self):
        p = parse({}).policy
        self.assertIs(p.shared_permissions(), p.permissions)
        self.assertEqual(p.read_permissions(), {k: "read" for k in GLOBAL})
        self.assertIsNone(p.full_repos())

    def test_merge_denied_bases_still_read_from_the_same_table(self):
        p = parse({"acme/tracker": {"merge_denied_bases": ["release/*"], "permissions": {"issues": "write"}}}).policy
        self.assertTrue(p.merge_protected("acme/tracker", "release/1"))
        self.assertFalse(p.merge_protected("acme/app", "release/1"))

    def test_must_be_a_subset_of_the_global_set(self):
        for bad in ({"contents": "write", "administration": "read"}, {"actions": "read"}):
            with self.assertRaises(config.ConfigError, msg=bad):
                parse({"acme/tracker": {"permissions": bad}})
        with self.assertRaises(config.ConfigError):
            parse({"acme/tracker": {"permissions": {"contents": "write"}}}, permissions={"contents": "read"})
        with self.assertRaises(config.ConfigError):
            parse({"acme/tracker": {"permissions": {"metadata": "write"}}})

    def test_values_must_be_read_or_write(self):
        for bad in ({"issues": "admin"}, {"issues": True}, ["issues"], "issues"):
            with self.assertRaises(config.ConfigError, msg=repr(bad)):
                parse({"acme/tracker": {"permissions": bad}})

    def test_unknown_repo_table_keys_refused(self):
        for table in ({"permission": {"issues": "write"}}, {"push_branches": ["x/*"]}):
            with self.assertRaises(config.ConfigError, msg=table):
                parse({"acme/tracker": table})

    def test_repo_must_be_listed(self):
        with self.assertRaises(config.ConfigError):
            parse({"acme/elsewhere": {"permissions": {"issues": "write"}}})

    def test_same_repo_twice_refused(self):
        with self.assertRaises(config.ConfigError):
            parse({"acme/tracker": {"permissions": {"issues": "write"}}, "ACME/tracker": {"merge_denied_bases": []}})

    def test_star_repos_refused(self):
        with self.assertRaises(config.ConfigError):
            parse(repos=["*", "acme/tracker"])

    def test_token_identity_refused(self):
        with self.assertRaises(config.ConfigError):
            parse(kind="token")
        parse({}, kind="token")

    def test_missing_grants(self):
        self.assertEqual(config.missing_grants({"a": "write", "b": "read", "c": "read", "d": "write"},
                                               {"a": "read", "b": "write", "d": "admin"}),
                         ["a:write", "c:read"])

    def test_global_values_must_be_read_or_write(self):
        with self.assertRaises(config.ConfigError):
            parse({}, permissions={"issues": "admin"})


class PolicyTest(unittest.TestCase):
    def setUp(self):
        self.p = parse().policy

    def rest(self, method, path, body=b"{}"):
        return policy.rest_request(self.p, method, path, body)

    def test_issue_writes_allowed_on_issues_only_repo(self):
        for m, path in (("POST", "/repos/acme/tracker/issues"), ("PATCH", "/repos/acme/tracker/issues/1"),
                        ("POST", "/repos/acme/tracker/issues/1/comments"),
                        ("POST", "/repos/acme/tracker/issues/1/labels"),
                        ("DELETE", "/repos/acme/tracker/issues/comments/3")):
            d = self.rest(m, path)
            self.assertTrue(d.allow, (m, path, d.reason))
            self.assertEqual(policy.token_scope(self.p, d), (["acme/tracker"], ISSUES_ONLY))

    def test_other_writes_refused_on_issues_only_repo(self):
        for m, path, body in (("POST", "/repos/acme/tracker/pulls", b'{"base":"dev","head":"agent/x"}'),
                              ("PATCH", "/repos/acme/tracker/pulls/1", b'{"title":"t"}'),
                              ("POST", "/repos/acme/tracker/pulls/1/reviews", b'{"event":"COMMENT"}'),
                              ("PUT", "/repos/acme/tracker/pulls/1/merge", b"{}"),
                              ("PUT", "/repos/acme/tracker/pulls/1/update-branch", b"{}"),
                              ("PUT", "/repos/acme/tracker/contents/a", b'{"branch":"agent/x"}'),
                              ("POST", "/repos/acme/tracker/git/refs", b'{"ref":"refs/heads/agent/x"}'),
                              ("DELETE", "/repos/acme/tracker/git/refs/heads/agent/x", None),
                              ("POST", "/repos/acme/tracker/merges", b'{"base":"agent/x"}'),
                              ("POST", "/repos/acme/tracker/git/blobs", None)):
            d = self.rest(m, path, body)
            self.assertFalse(d.allow, (m, path))
            self.assertIn("is not granted", d.reason)
            self.assertIsNone(d.lookup)
        for m, path in (("POST", "/repos/acme/app/pulls"), ("PUT", "/repos/acme/app/pulls/1/merge")):
            self.assertTrue(self.rest(m, path, b'{"base":"dev","head":"agent/x"}').allow, path)

    def test_repo_name_case_does_not_matter(self):
        d = self.rest("POST", "/repos/ACME/Tracker/pulls", b'{"base":"dev","head":"agent/x"}')
        self.assertFalse(d.allow)
        d = self.rest("POST", "/repos/ACME/Tracker/issues")
        self.assertEqual(policy.token_scope(self.p, d), (["ACME/Tracker"], ISSUES_ONLY))

    def test_a_write_needing_two_permissions_needs_both(self):
        p = parse({"acme/tracker": {"permissions": {"pull_requests": "write", "contents": "read"}}}).policy
        self.assertTrue(policy.rest_request(p, "PATCH", "/repos/acme/tracker/pulls/1", b"{}").allow)
        self.assertFalse(policy.rest_request(p, "PUT", "/repos/acme/tracker/pulls/1/merge", b"{}").allow)

    def test_push_refused_on_issues_only_repo(self):
        for q, path in (("service=git-receive-pack", "/acme/tracker.git/info/refs"),
                        ("", "/acme/tracker.git/git-receive-pack")):
            d = policy.git_request(self.p, "GET" if q else "POST", path, q)
            self.assertFalse(d.allow, path)
            self.assertIn("contents write", d.reason)
        d = policy.git_request(self.p, "GET", "/acme/tracker.git/info/refs", "service=git-upload-pack")
        self.assertTrue(d.allow)
        self.assertEqual(policy.token_scope(self.p, d), (["acme/tracker"], {"metadata": "read", "issues": "read"}))
        self.assertTrue(policy.git_request(self.p, "POST", "/acme/app.git/git-receive-pack", "").allow)

    def test_global_set_does_not_gain_proxy_checks(self):
        # Without its own set a repo's writes are left to GitHub, as before per-repo sets existed.
        p = parse({}, permissions={"issues": "write"}).policy
        self.assertTrue(policy.rest_request(p, "POST", "/repos/acme/app/pulls", b"{}").allow)

    def test_rest_allow_on_narrowed_repo_gets_its_own_set(self):
        p = parse(rest_allow=[["POST", "/repos/{owner}/{repo}/check-runs"]]).policy
        d = policy.rest_request(p, "POST", "/repos/acme/tracker/check-runs", None)
        self.assertTrue(d.allow)
        self.assertEqual(policy.token_scope(p, d), (["acme/tracker"], ISSUES_ONLY))

    def graphql(self, q, p=None):
        d = policy.graphql_request(p or self.p, gql(q))
        self.assertTrue(d.allow, d.reason)
        return policy.token_scope(p or self.p, d)

    def test_graphql_issue_mutations_get_the_shared_set_over_every_repo(self):
        self.assertEqual(self.graphql(CREATE_ISSUE), (None, ISSUES_ONLY))
        for name in policy.ISSUE_MUTATIONS & config.DEFAULT_MUTATIONS:
            q = f'mutation {{ {name}(input:{{}}) {{ clientMutationId }} }}'
            self.assertEqual(self.graphql(q), (None, ISSUES_ONLY), name)
        p = parse({"acme/tracker": {"permissions": {"issues": "write", "contents": "read", "pull_requests": "read"}}}).policy
        self.assertEqual(self.graphql(CREATE_ISSUE, p),
                         (None, {"metadata": "read", "issues": "write", "contents": "read", "pull_requests": "read"}))

    def test_graphql_other_mutations_get_the_global_set_over_full_repos_only(self):
        self.assertEqual(self.graphql(CREATE_PR), (["acme/app", "acme/other"], GLOBAL))

    def test_graphql_issue_mutations_take_the_full_token_when_a_repo_lacks_issues_write(self):
        p = parse({"acme/tracker": {"permissions": {"contents": "write", "issues": "read"}}}).policy
        self.assertEqual(self.graphql(CREATE_ISSUE, p), (["acme/app", "acme/other"], GLOBAL))
        p = parse({}, permissions={"contents": "write"}).policy
        self.assertEqual(self.graphql(CREATE_ISSUE, p), (None, {"metadata": "read", "contents": "write"}))

    def test_graphql_mixed_document_gets_the_full_token(self):
        self.assertEqual(self.graphql(MIXED), (["acme/app", "acme/other"], GLOBAL))

    def test_graphql_query_reads_the_shared_set(self):
        self.assertEqual(self.graphql("query { viewer { login } }"), (None, {"metadata": "read", "issues": "read"}))

    def test_graphql_full_mutation_with_no_full_repo_refused(self):
        p = parse({r: {"permissions": {"issues": "write"}} for r in ("acme/app", "acme/other", "acme/tracker")}).policy
        d = policy.graphql_request(p, gql(CREATE_PR))
        self.assertFalse(d.allow)
        self.assertIn("full permission set", d.reason)
        self.assertEqual(self.graphql(CREATE_ISSUE, p), (None, ISSUES_ONLY))

    def test_unnarrowed_config_scopes_as_before(self):
        p = parse({}).policy
        for q in (CREATE_ISSUE, CREATE_PR, MIXED):
            self.assertEqual(self.graphql(q, p), (None, GLOBAL))
        self.assertEqual(self.graphql("query { viewer { login } }", p), (None, {k: "read" for k in GLOBAL}))
        d = policy.rest_request(p, "POST", "/repos/acme/app/issues", b"{}")
        self.assertEqual(policy.token_scope(p, d), (["acme/app"], GLOBAL))


class StubCred:
    identity = None

    def __init__(self):
        self.calls = []

    def authorization(self, repos, perms):
        self.calls.append((repos, dict(perms)))
        return "token stub"


class LookupScopeTest(unittest.TestCase):
    """Lookups read with the repos and permissions of the token the request will get."""

    def setUp(self):
        self.cfg = parse({"acme/tracker": {"permissions": {"issues": "write"}},
                          "acme/other": {"permissions": {"contents": "write", "pull_requests": "write"}}})
        self.px = server.Proxy(self.cfg, StubCred(), audit=None)

    def test_rest_merge_lookup_uses_the_repo_read_set(self):
        d = policy.rest_request(self.cfg.policy, "PUT", "/repos/acme/other/pulls/4/merge", b"{}")
        cred = StubCred()
        with mock.patch.object(credentials, "api_call",
                               return_value={"base": {"ref": "dev"}, "head": {"ref": "agent/x"}}):
            self.px.resolve_lookup(d, cred, *self.px.mint_scope(d))
        self.assertEqual(cred.calls, [(("other",), {"metadata": "read", "contents": "read", "pull_requests": "read"})])

    def test_graphql_merge_lookup_uses_full_repos_only(self):
        q = 'mutation { mergePullRequest(input:{pullRequestId:"PR_1"}) { clientMutationId } }'
        d = policy.graphql_request(self.cfg.policy, gql(q))
        cred = StubCred()
        nodes = {"data": {"nodes": [{"baseRefName": "dev", "repository": {"nameWithOwner": "acme/app"}}]}}
        with mock.patch.object(credentials, "api_call", return_value=nodes):
            self.px.resolve_lookup(d, cred, *self.px.mint_scope(d))
        self.assertEqual(cred.calls, [(("app",), {k: "read" for k in GLOBAL})])

    def test_empty_repo_list_never_minted(self):
        d = policy.allow("x", access="write", across="full")
        with mock.patch.object(policy, "token_scope", return_value=([], GLOBAL)):
            with self.assertRaises(server.Refused):
                self.px.mint_scope(d)


class EndToEnd(unittest.TestCase):
    """The real proxy against the fake GitHub; tokens are read back from what it minted."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="gcp.", dir="/tmp")
        cls.git_root = os.path.join(cls.tmp, "git")
        env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "HOME": cls.tmp}
        seed = os.path.join(cls.tmp, "seed")
        subprocess.run(["git", "init", "-q", "-b", "main", seed], check=True, env=env)
        cls.git(seed, "commit", "-q", "--allow-empty", "-m", "seed")
        for name in ("app", "tracker"):
            bare = os.path.join(cls.git_root, "acme", f"{name}.git")
            os.makedirs(bare)
            subprocess.run(["git", "init", "-q", "--bare", "-b", "main", bare], check=True, env=env)
            subprocess.run(["git", "-C", bare, "config", "http.receivepack", "true"], check=True, env=env)
            cls.git(seed, "push", "-q", bare, "main")

        cls.fake = fakegithub.start(cls.git_root)
        base = f"http://127.0.0.1:{cls.fake.server_port}"
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.key_path = os.path.join(cls.tmp, "app.pem")
        with open(cls.key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        cls.sock = os.path.join(cls.tmp, "p.sock")
        cls.config_path = os.path.join(cls.tmp, "config.toml")
        with open(cls.config_path, "w") as f:
            f.write(f'''
[server]
socket = "{cls.sock}"
audit_log = "{os.path.join(cls.tmp, 'audit.jsonl')}"
api_url = "{base}"
git_url = "{base}"
api_host = "api.github.com"
git_host = "github.com"

[identity]
kind = "github-app"
app_id = 99
owner = "acme"
key = {{ file = "{cls.key_path}" }}

[policy]
repos = ["acme/app", "acme/other", "acme/tracker"]
permissions = {{ contents = "write", pull_requests = "write", issues = "write" }}
push_branches = ["agent/*"]
merge_denied_bases = ["main"]

[policy.repo."acme/tracker"]
permissions = {{ issues = "write" }}
''')
        cls.cfg = config.load(cls.config_path)
        cls.srv = server.bind(cls.cfg, server.Proxy(cls.cfg, credentials.build(cls.cfg),
                                                    server.AuditLog(os.path.join(cls.tmp, "audit.jsonl"))))
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.env = client.environment(cls.sock, os.path.join(cls.tmp, "gh"))

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.fake.shutdown()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def git(cls, cwd, *args, env=None, check=True):
        base = {"PATH": os.environ["PATH"], "HOME": cls.tmp, "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
                "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com"}
        r = subprocess.run(["git", *args], cwd=cwd, env={**base, **(env or {})}, capture_output=True, text=True)
        if check and r.returncode:
            raise AssertionError(f"git {args} failed: {r.stderr}")
        return r

    def api(self, method, path, body=None):
        c = client.UnixHTTPConnection(self.sock)
        c.request(method, path, body=json.dumps(body).encode() if body is not None else None,
                  headers={"Host": "api.github.com"})
        r = c.getresponse()
        out = r.status, r.read()
        c.close()
        return out

    def used_token(self, n, path):
        """The minted body of the token the proxy forwarded the first matching request with, after seen[n]."""
        for _, p, auth in self.fake.state.seen[n:]:
            if p == path:
                tok = base64.b64decode(auth[6:]).decode().split(":", 1)[1] if auth.startswith("Basic ") \
                    else auth.split(" ", 1)[1]
                return self.fake.state.tokens[tok]
        self.fail(f"nothing reached {path}")

    def test_rest_issue_create_on_issues_only_repo(self):
        n = len(self.fake.state.seen)
        self.assertEqual(self.api("POST", "/repos/acme/tracker/issues", {"title": "t"})[0], 200)
        self.assertEqual(self.used_token(n, "/repos/acme/tracker/issues"),
                         {"repositories": ["tracker"], "permissions": ISSUES_ONLY})

    def test_rest_read_on_issues_only_repo_is_read_of_its_set(self):
        n = len(self.fake.state.seen)
        self.assertEqual(self.api("GET", "/repos/acme/tracker/issues")[0], 200)
        self.assertEqual(self.used_token(n, "/repos/acme/tracker/issues"),
                         {"repositories": ["tracker"], "permissions": {"metadata": "read", "issues": "read"}})

    def test_rest_pr_create_on_issues_only_repo_refused_before_upstream(self):
        n = len(self.fake.state.seen)
        status, body = self.api("POST", "/repos/acme/tracker/pulls", {"base": "dev", "head": "agent/x"})
        self.assertEqual(status, 403)
        self.assertIn(b"not granted pull_requests write", body)
        self.assertEqual(self.fake.state.seen[n:], [])
        self.assertEqual(self.api("POST", "/repos/acme/app/pulls", {"base": "dev", "head": "agent/x"})[0], 200)

    def test_push_to_issues_only_repo_refused_by_proxy(self):
        d = tempfile.mkdtemp(dir=self.tmp)
        self.git(self.tmp, "clone", "-q", "git@github.com:acme/tracker.git", d, env=self.env)
        self.git(d, "commit", "-q", "--allow-empty", "-m", "work", env=self.env)
        n = len(self.fake.state.seen)
        r = self.git(d, "push", "origin", "HEAD:refs/heads/agent/x", env=self.env, check=False)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("403", r.stderr)
        self.assertFalse([p for _, p, _ in self.fake.state.seen[n:] if "receive-pack" in p])
        bare = os.path.join(self.git_root, "acme", "tracker.git")
        self.assertNotIn("refs/heads/agent/x", self.git(bare, "for-each-ref", "--format=%(refname)").stdout.split())
        # The same push to a full repo goes through, with contents write over that repo alone.
        d = tempfile.mkdtemp(dir=self.tmp)
        self.git(self.tmp, "clone", "-q", "git@github.com:acme/app.git", d, env=self.env)
        self.git(d, "commit", "-q", "--allow-empty", "-m", "work", env=self.env)
        n = len(self.fake.state.seen)
        self.git(d, "push", "-q", "origin", "HEAD:refs/heads/agent/x", env=self.env)
        self.assertEqual(self.used_token(n, "/acme/app.git/git-receive-pack"),
                         {"repositories": ["app"], "permissions": GLOBAL})

    def gql(self, q, variables=None):
        n = len(self.fake.state.seen)
        status, body = self.api("POST", "/graphql", {"query": q, "variables": variables or {}})
        self.assertEqual(status, 200, body)
        graphql = [i for i, (_, p, _) in enumerate(self.fake.state.seen[n:]) if p == "/graphql"]
        return self.used_token(n + graphql[-1], "/graphql")

    def test_graphql_create_issue_gets_the_shared_set(self):
        self.assertEqual(self.gql(CREATE_ISSUE),
                         {"repositories": ["app", "other", "tracker"], "permissions": ISSUES_ONLY})

    def test_graphql_create_pr_never_covers_the_issues_only_repo(self):
        self.assertEqual(self.gql(CREATE_PR), {"repositories": ["app", "other"], "permissions": GLOBAL})

    def test_graphql_mixed_document_gets_full_repos_only(self):
        self.assertEqual(self.gql(MIXED), {"repositories": ["app", "other"], "permissions": GLOBAL})

    def test_graphql_query_reads_the_shared_set_over_every_repo(self):
        self.assertEqual(self.gql("query { viewer { login } }"),
                         {"repositories": ["app", "other", "tracker"],
                          "permissions": {"metadata": "read", "issues": "read"}})

    def test_graphql_merge_lookup_uses_the_full_token_and_cannot_see_the_issues_only_repo(self):
        self.fake.state.nodes["PR_t"] = {"baseRefName": "dev", "nameWithOwner": "acme/tracker"}
        self.fake.state.nodes["PR_a"] = {"baseRefName": "dev", "nameWithOwner": "acme/app"}
        q = "mutation($id: ID!) { mergePullRequest(input:{pullRequestId:$id}) { clientMutationId } }"
        n = len(self.fake.state.seen)
        self.assertEqual(self.api("POST", "/graphql", {"query": q, "variables": {"id": "PR_a"}})[0], 200)
        self.assertEqual(self.used_token(n, "/graphql"),
                         {"repositories": ["app", "other"], "permissions": {k: "read" for k in GLOBAL}})
        status, body = self.api("POST", "/graphql", {"query": q, "variables": {"id": "PR_t"}})
        self.assertEqual(status, 403)
        self.assertIn(b"not a pull request the credential can see", body)

    def test_app_credential_refuses_an_empty_repo_list(self):
        # GitHub reads a missing repositories list as every repo the installation reaches.
        cred = credentials.build(self.cfg)
        n = len(self.fake.state.minted)
        with self.assertRaises(ValueError):
            cred.token((), GLOBAL)
        self.assertEqual(len(self.fake.state.minted), n)

    def check_config(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli.main(["check-config", "--config", self.config_path, *extra])
        return rc, out.getvalue(), err.getvalue()

    def test_check_config_prints_effective_sets_and_graphql_tokens(self):
        rc, out, _ = self.check_config()
        self.assertEqual(rc, 0)
        self.assertIn("acme/tracker (own set): issues:write, metadata:read", out)
        self.assertIn("acme/app: contents:write, issues:write, metadata:read, pull_requests:write", out)
        self.assertIn("other mutations  acme/app, acme/other: contents:write", out)
        self.assertIn("issue mutations  every policy repo: issues:write, metadata:read", out)
        self.assertIn("cannot read contents, pull_requests on any repo", out)

    def test_check_config_resolve_compares_with_the_installation(self):
        rc, out, _ = self.check_config("--resolve")
        self.assertEqual(rc, 0, out)
        self.assertIn("grants policy.permissions", out)
        old = self.fake.state.installation_permissions
        self.fake.state.installation_permissions = {"metadata": "read", "issues": "write", "contents": "read"}
        try:
            rc, _, err = self.check_config("--resolve")
        finally:
            self.fake.state.installation_permissions = old
        self.assertEqual(rc, 2)
        self.assertIn("contents:write, pull_requests:write", err)

    def test_explain_shows_the_token(self):
        body = os.path.join(self.tmp, "q.json")
        with open(body, "wb") as f:
            f.write(gql(CREATE_PR))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = cli.main(["explain", "--config", self.config_path, "POST", "https://api.github.com/graphql",
                           "--body", body])
        self.assertEqual(rc, 0)
        self.assertEqual(json.loads(out.getvalue())["token"],
                         {"repos": ["acme/app", "acme/other"], "permissions": GLOBAL})


if __name__ == "__main__":
    unittest.main()
