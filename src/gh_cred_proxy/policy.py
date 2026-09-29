"""Request classification and allow/deny decisions. Everything unrecognised is denied.

Two rules govern every checker here:
- anything that can move a ref, change a pull request's base, or merge goes through a checker;
- input the proxy cannot read exactly as GitHub will is refused, not guessed at.
"""
import json
import re
from dataclasses import dataclass, field

from graphql import parse as gql_parse
from graphql.error import GraphQLError
from graphql.language import ast as gast

from .config import Policy, normalise_branch

_OWNER = r"(?P<owner>[A-Za-z0-9_.-]+)"
_REPO = r"(?P<repo>[A-Za-z0-9_.-]+?)"
GQL_MAX_TOKENS = 20000
GQL_MAX_DEPTH = 64


@dataclass
class Decision:
    allow: bool
    reason: str
    repo: str | None = None          # owner/name the request is about, when known
    access: str = "read"             # token level to mint: read or write
    detail: dict = field(default_factory=dict)
    lookup: dict | None = None       # a follow-up check the server must resolve upstream


def deny(reason, **kw):
    return Decision(False, reason, **kw)


def allow(reason, **kw):
    return Decision(True, reason, **kw)


# ---------------------------------------------------------------- git smart HTTP
# https://git-scm.com/docs/http-protocol

GIT_PATH = re.compile(rf"^/{_OWNER}/{_REPO}(?:\.git)?/(?P<svc>info/refs|git-upload-pack|git-receive-pack)$")
OID = re.compile(rb"[0-9a-f]{40}|[0-9a-f]{64}")


def git_request(policy: Policy, method: str, path: str, query: str) -> Decision:
    m = GIT_PATH.match(path)
    if not m:
        return deny("not a git smart-HTTP path")
    repo = f"{m['owner']}/{m['repo']}"
    if not policy.repo_allowed(repo):
        return deny("repo not in policy", repo=repo)
    svc = m["svc"]
    if svc == "info/refs":
        if method not in ("GET", "HEAD"):
            return deny("info/refs must be GET", repo=repo)
        if query == "service=git-upload-pack":
            return allow("fetch advertisement", repo=repo)
        if query == "service=git-receive-pack":
            return allow("push advertisement", repo=repo, access="write")
        return deny("dumb HTTP or unknown service", repo=repo)
    if method != "POST" or query:
        return deny(f"{svc} must be a POST without a query string", repo=repo)
    if svc == "git-upload-pack":
        return allow("fetch", repo=repo)
    return allow("push; ref updates checked separately", repo=repo, access="write")


class RefCommandParser:
    """Incremental parser for the command section of a receive-pack request.

    feed() returns [(old, new, ref)] once the flush-pkt arrives, None while more is needed,
    and raises ValueError on anything malformed. Each byte is examined once.
    """

    def __init__(self, limit: int):
        self.buf = bytearray()
        self.pos = 0
        self.limit = limit
        self.out = []

    def feed(self, data: bytes):
        self.buf += data
        while True:
            if len(self.buf) - self.pos < 4:
                break
            head = bytes(self.buf[self.pos:self.pos + 4])
            if not re.fullmatch(rb"[0-9a-f]{4}", head):
                raise ValueError("bad pkt-line length")
            n = int(head, 16)
            if n == 0:
                return self.out
            if n < 4:
                raise ValueError("reserved pkt-line length")
            if len(self.buf) - self.pos < n:
                break
            self._line(bytes(self.buf[self.pos + 4:self.pos + n]))
            self.pos += n
        if len(self.buf) > self.limit:
            raise ValueError("command section too large")
        return None

    def _line(self, raw: bytes):
        line = raw.split(b"\0", 1)[0].rstrip(b"\n")
        if line.startswith(b"shallow "):
            return
        if line.startswith(b"push-cert"):
            raise ValueError("signed pushes are not supported")
        parts = line.split(b" ")
        if len(parts) != 3 or not (OID.fullmatch(parts[0]) and OID.fullmatch(parts[1])):
            raise ValueError(f"unexpected command line {line[:80]!r}")
        try:
            ref = parts[2].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError("non-ASCII ref name")
        self.out.append((parts[0].decode(), parts[1].decode(), ref))

    @property
    def consumed(self) -> bytes:
        return bytes(self.buf)


def parse_ref_updates(data: bytes):
    """One-shot form of RefCommandParser, for tests and the CLI."""
    return RefCommandParser(len(data) + 1).feed(data)


def check_ref_updates(policy: Policy, repo: str, updates) -> Decision:
    # An empty list is git's four-byte probe before a large push; it updates nothing.
    for old, new, ref in updates:
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/"):]
            if not policy.branch_pushable(branch):
                return deny(f"push to branch {branch!r} not allowed", repo=repo, access="write")
        elif ref.startswith("refs/tags/"):
            if not policy.push_tags:
                return deny(f"tag push {ref!r} not allowed", repo=repo, access="write")
        else:
            return deny(f"push to {ref!r} not allowed", repo=repo, access="write")
    return allow("ref updates allowed", repo=repo, access="write",
                 detail={"refs": [f"{'delete' if set(n) == {'0'} else 'update'} {r}" for _, n, r in updates]})


# ---------------------------------------------------------------- REST
# Write endpoints a pull-request and issue workflow needs. Each maps to a checker.

_NAME = r"[A-Za-z0-9_.-]+"
R = rf"^/repos/(?P<owner>{_NAME})/(?P<repo>{_NAME})"
N = r"(?P<num>\d+)"
REST_WRITES = [
    ("POST", R + r"/pulls$", "pr_create"),
    ("PATCH", R + rf"/pulls/{N}$", "pr_patch"),
    ("PUT", R + rf"/pulls/{N}/merge$", "merge"),
    ("PUT", R + rf"/pulls/{N}/update-branch$", "update_branch"),
    ("POST", R + rf"/pulls/{N}/reviews$", "review"),
    ("PUT", R + rf"/pulls/{N}/reviews/\d+$", "plain"),
    ("POST", R + rf"/pulls/{N}/reviews/\d+/events$", "review"),
    ("POST", R + rf"/pulls/{N}/comments$", "plain"),
    ("POST", R + rf"/pulls/{N}/comments/\d+/replies$", "plain"),
    ("POST", R + rf"/pulls/{N}/requested_reviewers$", "plain"),
    ("DELETE", R + rf"/pulls/{N}/requested_reviewers$", "plain"),
    ("PATCH", R + r"/pulls/comments/\d+$", "plain"),
    ("POST", R + r"/issues$", "plain"),
    ("PATCH", R + rf"/issues/{N}$", "plain"),
    ("POST", R + rf"/issues/{N}/comments$", "plain"),
    ("PATCH", R + r"/issues/comments/\d+$", "plain"),
    ("DELETE", R + r"/issues/comments/\d+$", "plain"),
    ("POST", R + rf"/issues/{N}/labels$", "plain"),
    ("PUT", R + rf"/issues/{N}/labels$", "plain"),
    ("DELETE", R + rf"/issues/{N}/labels(/[^/]+)?$", "plain"),
    ("POST", R + rf"/issues/{N}/assignees$", "plain"),
    ("DELETE", R + rf"/issues/{N}/assignees$", "plain"),
    ("POST", R + r"/git/(blobs|trees|commits)$", "plain"),
    ("POST", R + r"/git/refs$", "ref_create"),
    ("PATCH", R + r"/git/refs/heads/(?P<branch>.+)$", "ref_branch"),
    ("DELETE", R + r"/git/refs/heads/(?P<branch>.+)$", "ref_branch"),
    ("PUT", R + r"/contents/.+$", "contents"),
    ("DELETE", R + r"/contents/.+$", "contents"),
    ("POST", R + r"/merges$", "merges"),
]
REST_WRITES = [(m, re.compile(p), k) for m, p, k in REST_WRITES]
BODY_CHECKERS = {"review", "ref_create", "contents", "merges", "pr_patch", "pr_create"}
REPO_PATH = re.compile(R + r"(/.*)?$")
CONTENTS_PATH = re.compile(R + r"/contents/")
# Redirects from these carry a signed download token.
REFUSED_READS = re.compile(R + r"/(tarball|zipball)(/.*)?$")
READ_METHODS = ("GET", "HEAD")


def _glob_path(pattern: str, path: str) -> bool:
    rx = "^" + re.escape(pattern).replace(r"\{owner\}", _NAME).replace(r"\{repo\}", _NAME) \
        .replace(r"\*\*", "[A-Za-z0-9_./-]*").replace(r"\*", "[A-Za-z0-9_.-]*") + "$"
    return re.match(rx, path) is not None


def _no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate JSON key")
    return dict(pairs)


def strict_json(body: bytes):
    """json.loads that refuses duplicate keys, so the proxy and GitHub cannot read different values."""
    return json.loads(body, object_pairs_hook=_no_dupes)


def _json(body: bytes | None):
    if not body:
        return {}
    try:
        v = strict_json(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        raise ValueError("body is not JSON (or has duplicate keys)")
    if not isinstance(v, dict):
        raise ValueError("body is not a JSON object")
    return v


def _str(body: dict, key: str):
    """A body field the policy reads: absent, or a string. Anything else is refused."""
    v = body.get(key)
    if v is not None and not isinstance(v, str):
        raise ValueError(f"field {key!r} must be a string")
    return v


def rest_needs_body(method: str, path: str) -> bool:
    """Whether the checker for this endpoint inspects the body (so the server buffers it)."""
    for m, rx, kind in REST_WRITES:
        if m == method and rx.match(path):
            return kind in BODY_CHECKERS
    return False


def rest_request(policy: Policy, method: str, path: str, body: bytes | None) -> Decision:
    if "%" in path and not CONTENTS_PATH.match(path):
        return deny("percent-encoding is only accepted in a contents file path")
    rm = REPO_PATH.match(path)
    if path.startswith("/repos/") and not rm:
        return deny("unrecognised /repos/ path")
    repo = f"{rm['owner']}/{rm['repo']}" if rm else None
    if repo and not policy.repo_allowed(repo):
        return deny("repo not in policy", repo=repo)

    if method in READ_METHODS:
        if REFUSED_READS.match(path):
            return deny("archive downloads redirect with a signed token", repo=repo)
        if repo:
            return allow("read", repo=repo)
        if any(_glob_path(p, path) for p in policy.read_paths):
            return allow("read (non-repo path)")
        return deny("non-repo read path not in read_paths")

    for m, rx, kind in REST_WRITES:
        if m != method:
            continue
        mm = rx.match(path)
        if not mm:
            continue
        try:
            return _rest_check(policy, kind, repo, mm, _json(body) if kind in BODY_CHECKERS else {})
        except ValueError as e:
            return deny(str(e), repo=repo, access="write")

    if repo and any(m == method and _glob_path(p, path) for m, p in policy.rest_allow):
        return allow("rest_allow", repo=repo, access="write")
    return deny("no rule allows this write", repo=repo, access="write")


def _rest_check(policy: Policy, kind: str, repo: str, m, body: dict) -> Decision:
    w = dict(repo=repo, access="write")
    if kind == "plain":
        return allow("allowed write", **w)
    if kind in ("pr_patch", "pr_create"):
        # Opening or retargeting a PR onto a protected base is how a merge gate gets walked around
        # (with auto-merge, or a merge racing the retarget). Opening one is fine; retargeting is not.
        base = _str(body, "base")
        _str(body, "head")
        if kind == "pr_patch" and base is not None and policy.merge_protected(repo, base):
            return deny(f"retargeting to protected base {base!r}", **w)
        return allow("pr create/update", **w)
    if kind == "review":
        event = _str(body, "event")
        if policy.deny_approvals and (event or "").upper() == "APPROVE":
            return deny("approvals are not allowed", **w)
        return allow("review without approval", **w)
    if kind == "merge":
        return allow("merge; base checked upstream", **w, lookup={"pr_base": int(m["num"])})
    if kind == "update_branch":
        return allow("update-branch; head checked upstream", **w, lookup={"pr_head": int(m["num"])})
    if kind == "ref_create":
        ref = _str(body, "ref") or ""
        if ref.startswith("refs/heads/") and policy.branch_pushable(ref[11:]):
            return allow("create allowed branch", **w)
        if ref.startswith("refs/tags/") and policy.push_tags:
            return allow("create tag", **w)
        return deny(f"creating ref {ref!r} not allowed", **w)
    if kind == "ref_branch":
        if policy.branch_pushable(m["branch"]):
            return allow("branch ref write", **w)
        return deny(f"ref write to branch {m['branch']!r} not allowed", **w)
    if kind == "contents":
        branch = _str(body, "branch")
        if not branch:
            return deny("contents write without an explicit branch targets the default branch", **w)
        if policy.branch_pushable(branch):
            return allow("contents write to allowed branch", **w)
        return deny(f"contents write to branch {branch!r} not allowed", **w)
    if kind == "merges":
        base = _str(body, "base") or ""
        if policy.branch_pushable(base):
            return allow("merge into allowed branch", **w)
        return deny(f"merge into branch {base!r} not allowed", **w)
    return deny(f"internal: unknown checker {kind}", **w)


# ---------------------------------------------------------------- GraphQL

REVIEW_MUTATIONS = {"addPullRequestReview", "submitPullRequestReview"}
UNRESOLVED = object()


def _value(node, variables):
    """Resolve a GraphQL value node, substituting variables. UNRESOLVED if impossible."""
    if node is None:
        return None
    if isinstance(node, gast.VariableNode):
        name = node.name.value
        return variables[name] if name in variables else UNRESOLVED
    if isinstance(node, gast.ObjectValueNode):
        out = {}
        for f in node.fields:
            if f.name.value in out:
                return UNRESOLVED
            v = _value(f.value, variables)
            if v is UNRESOLVED:
                return UNRESOLVED
            out[f.name.value] = v
        return out
    if isinstance(node, gast.ListValueNode):
        vals = [_value(v, variables) for v in node.values]
        return UNRESOLVED if any(v is UNRESOLVED for v in vals) else vals
    if isinstance(node, gast.NullValueNode):
        return None
    if isinstance(node, (gast.EnumValueNode, gast.StringValueNode, gast.BooleanValueNode,
                         gast.IntValueNode, gast.FloatValueNode)):
        return node.value
    return UNRESOLVED


def _input(field_node, variables):
    """The resolved `input` argument of a mutation field, {} if absent, UNRESOLVED if unreadable."""
    names = [a.name.value for a in field_node.arguments or ()]
    if len(names) != len(set(names)):
        return UNRESOLVED
    for a in field_node.arguments or ():
        if a.name.value == "input":
            v = _value(a.value, variables)
            return v if isinstance(v, dict) else UNRESOLVED
    return {}


def _too_deep(query: str) -> bool:
    depth = peak = 0
    for ch in query:
        if ch in "{([":
            depth += 1
            peak = max(peak, depth)
        elif ch in "})]":
            depth -= 1
    return peak > GQL_MAX_DEPTH


def graphql_request(policy: Policy, body: bytes) -> Decision:
    try:
        req = strict_json(body)
    except (ValueError, UnicodeDecodeError, RecursionError):
        return deny("graphql body is not JSON (or has duplicate keys)")
    if not isinstance(req, dict) or not isinstance(req.get("query"), str):
        return deny("graphql body must be a single {query, variables} object")
    variables = req.get("variables") or {}
    if not isinstance(variables, dict):
        return deny("graphql variables must be an object")
    if _too_deep(req["query"]):
        return deny(f"graphql document nested deeper than {GQL_MAX_DEPTH}")
    try:
        doc = gql_parse(req["query"], no_location=True, max_tokens=GQL_MAX_TOKENS)
    except GraphQLError as e:
        return deny(f"graphql parse error: {e.message}")
    except RecursionError:
        return deny("graphql document too deeply nested")

    ops, fields, lookups = [], [], []
    for d in doc.definitions:
        if isinstance(d, gast.FragmentDefinitionNode):
            continue
        if not isinstance(d, gast.OperationDefinitionNode):
            return deny("graphql document contains a non-executable definition")
        op = d.operation.value
        ops.append(op)
        if op == "query":
            continue
        if op != "mutation":
            return deny(f"graphql {op} not allowed")
        # Effective variables: declared ones only; supplied value, else default, else null.
        op_vars = {}
        for vd in d.variable_definitions or ():
            vname = vd.variable.name.value
            if vname in op_vars:
                return deny(f"variable ${vname} declared twice")
            if vname in variables:
                op_vars[vname] = variables[vname]
            elif vd.default_value is not None:
                op_vars[vname] = _value(vd.default_value, {})
            else:
                op_vars[vname] = None
        for sel in d.selection_set.selections:
            if not isinstance(sel, gast.FieldNode):
                return deny("fragments at the top level of a mutation are not allowed")
            name = sel.name.value
            fields.append(name)
            if name not in policy.mutations:
                return deny(f"mutation {name} not allowed", detail={"mutations": fields})
            inp = _input(sel, op_vars)
            if inp is UNRESOLVED:
                return deny(f"{name}: could not resolve its input", detail={"mutations": fields})
            if name in REVIEW_MUTATIONS and policy.deny_approvals:
                event = inp.get("event")
                if not isinstance(event, (str, type(None))) or (event or "").upper() == "APPROVE":
                    return deny("approvals are not allowed", detail={"mutations": fields})
                if name == "submitPullRequestReview" and event is None:
                    return deny("submitPullRequestReview without an event")
            if name == "mergePullRequest":
                pr = inp.get("pullRequestId")
                if not isinstance(pr, str) or not pr:
                    return deny(f"{name}: could not resolve pullRequestId")
                lookups.append({"id": pr, "base": None})
            if name == "updatePullRequest" and inp.get("baseRefName") is not None:
                pr, base = inp.get("pullRequestId"), inp.get("baseRefName")
                if not isinstance(pr, str) or not pr or not isinstance(base, str):
                    return deny(f"{name}: could not resolve pullRequestId and baseRefName")
                lookups.append({"id": pr, "base": normalise_branch(base)})
    if not ops:
        return deny("graphql document has no operation")
    mutating = "mutation" in ops
    return allow("graphql " + ("mutation" if mutating else "query"),
                 access="write" if mutating else "read",
                 detail={"ops": ops, "mutations": fields},
                 lookup={"pr_nodes": lookups} if lookups else None)
