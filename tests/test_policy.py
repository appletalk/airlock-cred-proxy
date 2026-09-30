import time
import unittest

from airlock_cred_proxy import config, policy


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


class ReviewRound1(unittest.TestCase):
    def test_percent_encoded_owner_cannot_reach_rest_allow(self):
        p = pol(rest_allow=[["POST", "/repos/{owner}/{repo}/check-runs"]])
        self.assertFalse(policy.rest_request(p, "POST", "/repos/%65vil/secret/check-runs", None).allow)
        self.assertFalse(policy.rest_request(p, "POST", "/repos/evil/secret/check-runs", None).allow)
        self.assertTrue(policy.rest_request(p, "POST", "/repos/acme/app/check-runs", None).allow)

    def test_percent_allowed_only_in_contents_path(self):
        p = pol()
        self.assertTrue(policy.rest_request(p, "GET", "/repos/acme/app/contents/a%20b.txt", None).allow)
        self.assertFalse(policy.rest_request(p, "GET", "/repos/acme/app/issues%3fx", None).allow)

    def test_parser_is_linear_on_one_byte_feeds(self):
        line = pkt(f"{OLD} {NEW} refs/heads/agent/{'x' * 100}".encode())
        data = line * 1500 + b"0000"
        parser = policy.RefCommandParser(len(data) + 1)
        t0 = time.monotonic()
        out = None
        for i in range(len(data)):
            out = parser.feed(data[i:i + 1])
            if out is not None:
                break
        self.assertEqual(len(out), 1500)
        self.assertLess(time.monotonic() - t0, 5)

    def test_parser_refuses_oversized_section(self):
        parser = policy.RefCommandParser(1000)
        with self.assertRaises(ValueError):
            parser.feed(pkt(f"{OLD} {NEW} refs/heads/agent/x".encode()) * 50)

    def test_fully_qualified_branch_names_normalised(self):
        p = pol(push_branches=["*"])
        self.assertFalse(policy.rest_request(p, "PUT", "/repos/acme/app/contents/a",
                                             b'{"branch":"refs/heads/main"}').allow)
        self.assertFalse(policy.rest_request(p, "POST", "/repos/acme/app/merges",
                                             b'{"base":"refs/heads/main","head":"x"}').allow)
        self.assertFalse(policy.rest_request(p, "PATCH", "/repos/acme/app/pulls/1",
                                             b'{"base":"refs/heads/main"}').allow)
        self.assertFalse(policy.rest_request(p, "DELETE", "/repos/acme/app/git/refs/heads/refs/heads/main",
                                             None).allow)

    def test_fully_qualified_allowed_branch_accepted(self):
        p = pol()
        self.assertTrue(policy.rest_request(p, "PUT", "/repos/acme/app/contents/a",
                                            b'{"branch":"refs/heads/agent/x"}').allow)

    def test_non_string_fields_refused(self):
        p = pol()
        self.assertFalse(policy.rest_request(p, "PATCH", "/repos/acme/app/pulls/1", b'{"base":["main"]}').allow)
        self.assertFalse(policy.rest_request(p, "POST", "/repos/acme/app/pulls/1/reviews",
                                             b'{"event":["APPROVE"]}').allow)


class ReviewRound2(unittest.TestCase):
    def test_depth_precheck_ignores_brackets_in_strings(self):
        q = 'query { a(x: "' + "}" * 200 + '") ' + "{b" * 100 + "}" * 100 + " }"
        self.assertTrue(policy._too_deep(q))
        q = 'query { a(x: """' + "}" * 200 + '""") ' + "{b" * 100 + "}" * 100 + " }"
        self.assertTrue(policy._too_deep(q))
        q = "query { a # " + "}" * 200 + "\n" + "{b" * 100 + "}" * 100 + " }"
        self.assertTrue(policy._too_deep(q))
        self.assertFalse(policy._too_deep('query { a(x: "' + "{" * 200 + '") { b } }'))


def gql(query, variables=None):
    import json
    return json.dumps({"query": query, "variables": variables or {}}).encode()


class BoardIdentity(unittest.TestCase):
    """A token identity pinned to one project board, with REST writes off."""

    MUTS = ["updateProjectV2ItemFieldValue", "clearProjectV2ItemFieldValue",
            "addProjectV2ItemById", "archiveProjectV2Item"]

    def board(self, **over):
        return pol(**{"graphql_mutations": self.MUTS, "projects": ["PVT_board"], "rest_writes": False, **over})

    def test_clear_and_archive_are_pinned_too(self):
        for name, extra in (("clearProjectV2ItemFieldValue", 'itemId:"I", fieldId:"F"'),
                            ("archiveProjectV2Item", 'itemId:"I"')):
            for pid, ok in (("PVT_board", True), ("PVT_other", False)):
                q = f'mutation {{ {name}(input:{{projectId:"{pid}", {extra}}}) {{ clientMutationId }} }}'
                self.assertEqual(policy.graphql_request(self.board(), gql(q)).allow, ok, (name, pid))

    def test_empty_projects_list_refuses_every_project_mutation(self):
        q = 'mutation { addProjectV2ItemById(input:{projectId:"PVT_board", contentId:"C"}) { item { id } } }'
        self.assertFalse(policy.graphql_request(self.board(projects=[]), gql(q)).allow)

    def test_non_string_project_id_refused(self):
        q = 'mutation { addProjectV2ItemById(input:{projectId:["PVT_board"], contentId:"C"}) { item { id } } }'
        self.assertFalse(policy.graphql_request(self.board(), gql(q)).allow)

    def test_rest_writes_off_covers_every_write_method(self):
        p = self.board()
        for m, path in (("PUT", "/repos/acme/app/contents/a"), ("DELETE", "/repos/acme/app/issues/comments/1"),
                        ("POST", "/repos/acme/app/issues"), ("PATCH", "/repos/acme/app/issues/1"),
                        ("OPTIONS", "/repos/acme/app/issues")):
            self.assertFalse(policy.rest_request(p, m, path, b'{"branch":"agent/x"}').allow, m)

    def test_every_project_mutation_that_can_be_enabled_is_pinned(self):
        classified = {m for m in config.SAFE_MUTATIONS if "ProjectV2" in m}
        self.assertTrue(classified)
        self.assertLessEqual(classified, policy.PROJECT_MUTATIONS)

    def test_token_identity_board_config(self):
        cfg = config.parse({"server": {"socket": "/tmp/b.sock"},
                            "identity": {"kind": "token", "token": {"command": ["true"]}},
                            "policy": {"repos": ["acme/tracker"], "graphql_mutations": self.MUTS,
                                       "projects": ["PVT_board"], "rest_writes": False}})
        q = 'mutation { archiveProjectV2Item(input:{projectId:"PVT_other", itemId:"I"}) { clientMutationId } }'
        self.assertFalse(policy.graphql_request(cfg.policy, gql(q)).allow)

    def test_project_mutation_on_the_allowed_board(self):
        q = 'mutation { updateProjectV2ItemFieldValue(input:{projectId:"PVT_board", itemId:"I", fieldId:"F", value:{date:"2030-01-01"}}) { clientMutationId } }'
        self.assertTrue(policy.graphql_request(self.board(), gql(q)).allow)

    def test_project_mutation_on_another_board_refused(self):
        q = 'mutation { updateProjectV2ItemFieldValue(input:{projectId:"PVT_other", itemId:"I", fieldId:"F", value:{date:"2030-01-01"}}) { clientMutationId } }'
        self.assertFalse(policy.graphql_request(self.board(), gql(q)).allow)

    def test_project_id_through_variables_and_defaults(self):
        q = 'mutation($p: ID!) { addProjectV2ItemById(input:{projectId:$p, contentId:"C"}) { item { id } } }'
        self.assertTrue(policy.graphql_request(self.board(), gql(q, {"p": "PVT_board"})).allow)
        self.assertFalse(policy.graphql_request(self.board(), gql(q, {"p": "PVT_other"})).allow)
        q2 = 'mutation($p: ID! = "PVT_other") { addProjectV2ItemById(input:{projectId:$p, contentId:"C"}) { item { id } } }'
        self.assertFalse(policy.graphql_request(self.board(), gql(q2)).allow)

    def test_missing_project_id_refused(self):
        q = 'mutation { addProjectV2ItemById(input:{contentId:"C"}) { item { id } } }'
        self.assertFalse(policy.graphql_request(self.board(), gql(q)).allow)

    def test_no_projects_key_means_no_pin(self):
        q = 'mutation { addProjectV2ItemById(input:{projectId:"PVT_any", contentId:"C"}) { item { id } } }'
        self.assertTrue(policy.graphql_request(pol(graphql_mutations=["addProjectV2ItemById"]), gql(q)).allow)

    def test_rest_writes_off_refuses_writes_keeps_reads(self):
        p = self.board()
        self.assertFalse(policy.rest_request(p, "POST", "/repos/acme/app/issues", b'{"title":"t"}').allow)
        self.assertFalse(policy.rest_request(p, "PATCH", "/repos/acme/app/issues/1", b'{"state":"closed"}').allow)
        self.assertTrue(policy.rest_request(p, "GET", "/repos/acme/app/issues/1", None).allow)
        self.assertTrue(policy.rest_request(pol(), "POST", "/repos/acme/app/issues", b'{"title":"t"}').allow)


class Config(unittest.TestCase):
    def test_booleans_must_be_booleans(self):
        for key in ("rest_writes", "push_tags", "deny_approvals"):
            with self.assertRaises(config.ConfigError, msg=key):
                pol(**{key: "false"})

    def test_projects_must_be_a_list_of_project_ids(self):
        for bad in ("PVT_board", ["board"], [1]):
            with self.assertRaises(config.ConfigError, msg=repr(bad)):
                pol(projects=bad)

    def test_token_identity_with_project_mutations_must_pin_a_board(self):
        base = {"server": {"socket": "/tmp/b.sock"},
                "identity": {"kind": "token", "token": {"command": ["true"]}},
                "policy": {"repos": ["acme/tracker"], "graphql_mutations": ["addProjectV2ItemById"]}}
        with self.assertRaises(config.ConfigError):
            config.parse(base)
        base["policy"]["projects"] = ["PVT_board"]
        config.parse(base)

    def test_unclassified_mutations_refused(self):
        for m in ("createLinkedBranch", "dismissPullRequestReview", "someFutureMutation"):
            with self.assertRaises(config.ConfigError, msg=m):
                pol(graphql_mutations=["createPullRequest", m])
        pol(graphql_mutations=["createPullRequest", "updateProjectV2ItemFieldValue"])

    def test_never_mutations_cannot_be_enabled(self):
        for m in ("enablePullRequestAutoMerge", "createCommitOnBranch", "updateRefs", "enqueuePullRequest"):
            with self.assertRaises(config.ConfigError, msg=m):
                pol(graphql_mutations=["createPullRequest", m])

    def test_world_accessible_socket_refused(self):
        with self.assertRaises(config.ConfigError):
            config.parse({"server": {"socket": "/tmp/s", "socket_mode": "0666"},
                          "identity": {"kind": "token", "token": {"command": ["true"]}},
                          "policy": {"repos": ["*"]}})

    def test_repo_outside_app_owner_refused(self):
        with self.assertRaises(config.ConfigError):
            pol(repos=["acme/app", "other/app"])

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
