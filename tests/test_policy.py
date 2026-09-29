import unittest

from gh_cred_proxy import config, policy


def pkt(s: bytes) -> bytes:
    return b"%04x" % (len(s) + 4) + s


def pol(**over):
    base = {"server": {"socket": "/tmp/x.sock"},
            "identity": {"kind": "github-app", "app_id": 1, "owner": "acme", "key": {"file": "/dev/null"}},
            "policy": {"repos": ["acme/app"], "push_branches": ["agent/*"], "merge_denied_bases": ["main"]}}
    base["policy"].update(over)
    return config.parse(base).policy


OLD, NEW = "a" * 40, "b" * 40


class RefUpdates(unittest.TestCase):
    def test_needs_flush(self):
        self.assertIsNone(policy.parse_ref_updates(pkt(f"{OLD} {NEW} refs/heads/x\0report-status".encode())))

    def test_parses_commands_and_capabilities(self):
        data = pkt(f"{OLD} {NEW} refs/heads/agent/a\0report-status side-band-64k".encode()) \
            + pkt(f"{OLD} {'0' * 40} refs/heads/agent/b\n".encode()) + b"0000PACK..."
        self.assertEqual(policy.parse_ref_updates(data),
                         [(OLD, NEW, "refs/heads/agent/a"), (OLD, "0" * 40, "refs/heads/agent/b")])

    def test_malformed_refused(self):
        for bad in (b"zzzz", b"0003", pkt(b"garbage line") + b"0000",
                    pkt(f"{OLD} {NEW}".encode()) + b"0000", pkt(b"push-cert\0x") + b"0000"):
            with self.assertRaises(ValueError, msg=bad):
                policy.parse_ref_updates(bad)

    def test_sha256_object_ids(self):
        o, n = "c" * 64, "d" * 64
        self.assertEqual(policy.parse_ref_updates(pkt(f"{o} {n} refs/heads/agent/x".encode()) + b"0000"),
                         [(o, n, "refs/heads/agent/x")])

    def test_ref_rules(self):
        p = pol()
        ok = policy.check_ref_updates(p, "acme/app", [(OLD, NEW, "refs/heads/agent/x")])
        self.assertTrue(ok.allow)
        for ref in ("refs/heads/main", "refs/heads/feature", "refs/tags/v1", "refs/notes/x", "HEAD"):
            self.assertFalse(policy.check_ref_updates(p, "acme/app", [(OLD, NEW, ref)]).allow, ref)
        self.assertTrue(policy.check_ref_updates(pol(push_tags=True), "acme/app", [(OLD, NEW, "refs/tags/v1")]).allow)

    def test_protected_base_beats_push_pattern(self):
        p = pol(push_branches=["*"])
        self.assertFalse(policy.check_ref_updates(p, "acme/app", [(OLD, NEW, "refs/heads/main")]).allow)


class Rest(unittest.TestCase):
    def test_contents_needs_explicit_allowed_branch(self):
        p = pol()
        self.assertFalse(policy.rest_request(p, "PUT", "/repos/acme/app/contents/a.txt", b'{"message":"m"}').allow)
        self.assertFalse(policy.rest_request(p, "PUT", "/repos/acme/app/contents/a.txt",
                                             b'{"branch":"main"}').allow)
        self.assertTrue(policy.rest_request(p, "PUT", "/repos/acme/app/contents/a.txt",
                                            b'{"branch":"agent/x"}').allow)

    def test_pr_retarget_to_protected_base_refused(self):
        p = pol()
        self.assertFalse(policy.rest_request(p, "PATCH", "/repos/acme/app/pulls/3", b'{"base":"main"}').allow)
        self.assertTrue(policy.rest_request(p, "PATCH", "/repos/acme/app/pulls/3", b'{"title":"t"}').allow)

    def test_branch_ref_writes(self):
        p = pol()
        self.assertTrue(policy.rest_request(p, "DELETE", "/repos/acme/app/git/refs/heads/agent/x", None).allow)
        self.assertFalse(policy.rest_request(p, "DELETE", "/repos/acme/app/git/refs/heads/main", None).allow)
        self.assertFalse(policy.rest_request(p, "POST", "/repos/acme/app/git/refs",
                                             b'{"ref":"refs/heads/main","sha":"x"}').allow)

    def test_non_repo_reads(self):
        p = pol()
        self.assertTrue(policy.rest_request(p, "GET", "/rate_limit", None).allow)
        self.assertTrue(policy.rest_request(p, "GET", "/users/someone", None).allow)
        self.assertFalse(policy.rest_request(p, "GET", "/user/repos", None).allow)
        self.assertFalse(policy.rest_request(p, "GET", "/users/someone/repos", None).allow)

    def test_rest_allow_extends(self):
        p = pol(rest_allow=[["POST", "/repos/{owner}/{repo}/check-runs"]])
        self.assertTrue(policy.rest_request(p, "POST", "/repos/acme/app/check-runs", None).allow)
        self.assertFalse(policy.rest_request(pol(), "POST", "/repos/acme/app/check-runs", None).allow)


class Config(unittest.TestCase):
    def test_repos_required(self):
        with self.assertRaises(config.ConfigError):
            pol(repos=[])

    def test_bad_permission_level(self):
        with self.assertRaises(config.ConfigError):
            pol(permissions={"contents": "admin"})

    def test_socket_path_limit(self):
        with self.assertRaises(config.ConfigError):
            config.parse({"server": {"socket": "/" + "x" * 120},
                          "identity": {"kind": "token", "token": {"command": ["true"]}},
                          "policy": {"repos": ["*"]}})

    def test_bad_secret_source(self):
        with self.assertRaises(config.ConfigError):
            config.parse({"server": {"socket": "/tmp/s"},
                          "identity": {"kind": "token", "token": {"command": "not-a-list"}},
                          "policy": {"repos": ["*"]}})


if __name__ == "__main__":
    unittest.main()
