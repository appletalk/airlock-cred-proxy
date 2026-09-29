"""Request classification and allow/deny decisions. Everything unrecognised is denied."""
import json
import re
from dataclasses import dataclass, field

from graphql import parse as gql_parse
from graphql.error import GraphQLError
from graphql.language import ast as gast

from .config import Policy

ZERO = "0" * 40
_OWNER = r"(?P<owner>[A-Za-z0-9_.-]+)"
_REPO = r"(?P<repo>[A-Za-z0-9_.-]+?)"


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
    if method != "POST":
        return deny(f"{svc} must be POST", repo=repo)
    if svc == "git-upload-pack":
        return allow("fetch", repo=repo)
    return allow("push; ref updates checked separately", repo=repo, access="write")


def parse_ref_updates(data: bytes) -> list[tuple[str, str, str]] | None:
    """Parse the command section of a receive-pack request.

    Returns [(old, new, ref)] once a flush-pkt has been seen, None if more data is needed.
    Raises ValueError on anything malformed.
    """
    out, pos = [], 0
    while True:
        if len(data) - pos < 4:
            return None
        n = int(data[pos:pos + 4], 16)
        if n == 0:
            return out
        if n < 4:
            raise ValueError("reserved pkt-line length")
        if len(data) - pos < n:
            return None
        line = data[pos + 4:pos + n].split(b"\0", 1)[0].rstrip(b"\n").decode("utf-8")
        pos += n
        if line.startswith("shallow "):
            continue
        if line.startswith("push-cert"):
            raise ValueError("signed pushes are not supported")
        parts = line.split(" ")
        if len(parts) != 3 or not all(re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", p) for p in parts[:2]):
            raise ValueError(f"unexpected command line {line[:80]!r}")
        out.append((parts[0], parts[1], parts[2]))


def check_ref_updates(policy: Policy, repo: str, updates) -> Decision:
    for old, new, ref in updates:
        if ref.startswith("refs/heads/"):
            branch = ref[len("refs/heads/"):]
            if not policy.branch_pushable(branch):
                return deny(f"push to branch {branch!r} not allowed", repo=repo)
        elif ref.startswith("refs/tags/"):
            if not policy.push_tags:
                return deny(f"tag push {ref!r} not allowed", repo=repo)
        else:
            return deny(f"push to {ref!r} not allowed", repo=repo)
    return allow("ref updates allowed", repo=repo, access="write",
                 detail={"refs": [f"{'delete' if set(n) == {'0'} else 'update'} {r}" for _, n, r in updates]})


# ---------------------------------------------------------------- REST
# Write endpoints a pull-request and issue workflow needs. Each maps to a checker.

R = rf"^/repos/{_OWNER}/(?P<repo>[A-Za-z0-9_.-]+)"
N = r"(?P<num>\d+)"
REST_WRITES = [
    ("POST", R + r"/pulls$", "plain"),
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
REPO_PATH = re.compile(R + r"(/.*)?$")
READ_METHODS = ("GET", "HEAD")


def _glob_path(pattern: str, path: str) -> bool:
    rx = "^" + re.escape(pattern).replace(r"\{owner\}", "[^/]+").replace(r"\{repo\}", "[^/]+") \
        .replace(r"\*\*", ".*").replace(r"\*", "[^/]*") + "$"
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
    except (ValueError, UnicodeDecodeError):
        raise ValueError("body is not JSON (or has duplicate keys)")
    if not isinstance(v, dict):
        raise ValueError("body is not a JSON object")
    return v


def rest_needs_body(method: str, path: str) -> bool:
    """Whether the checker for this endpoint inspects the body (so the server buffers it)."""
    for m, rx, kind in REST_WRITES:
        if m == method and rx.match(path):
            return kind in ("review", "ref_create", "contents", "merges", "pr_patch")
    return False


def rest_request(policy: Policy, method: str, path: str, body: bytes | None) -> Decision:
    rm = REPO_PATH.match(path)
    repo = f"{rm['owner']}/{rm['repo']}" if rm else None
    if repo and not policy.repo_allowed(repo):
        return deny("repo not in policy", repo=repo)

    if method in READ_METHODS:
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
            return _rest_check(policy, kind, repo, mm, _json(body) if rest_needs_body(method, path) else {})
        except ValueError as e:
            return deny(str(e), repo=repo)

    if any(m == method and _glob_path(p, path) for m, p in policy.rest_allow):
        return allow("rest_allow", repo=repo, access="write")
    return deny("no rule allows this write", repo=repo)


def _rest_check(policy: Policy, kind: str, repo: str, m, body: dict) -> Decision:
    w = dict(repo=repo, access="write")
    if kind == "plain":
        return allow("allowed write", **w)
    if kind == "pr_patch":
        # Retargeting a PR onto a protected base is how a merge gate gets walked around.
        if "base" in body and policy.merge_protected(repo, str(body["base"])):
            return deny(f"retargeting to protected base {body['base']!r}", **w)
        return allow("pr update", **w)
    if kind == "review":
        event = body.get("event")
        if policy.deny_approvals and str(event).upper() == "APPROVE":
            return deny("approvals are not allowed", **w)
        return allow("review without approval", **w)
    if kind == "merge":
        return allow("merge; base checked upstream", **w, lookup={"pr_base": int(m["num"])})
    if kind == "update_branch":
        return allow("update-branch; head checked upstream", **w, lookup={"pr_head": int(m["num"])})
    if kind == "ref_create":
        ref = str(body.get("ref", ""))
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
        branch = body.get("branch")
        if not branch:
            return deny("contents write without an explicit branch targets the default branch", **w)
        if policy.branch_pushable(str(branch)):
            return allow("contents write to allowed branch", **w)
        return deny(f"contents write to branch {branch!r} not allowed", **w)
    if kind == "merges":
        base = str(body.get("base", ""))
        if policy.branch_pushable(base):
            return allow("merge into allowed branch", **w)
        return deny(f"merge into branch {base!r} not allowed", **w)
    return deny(f"internal: unknown checker {kind}", **w)


# ---------------------------------------------------------------- GraphQL

REVIEW_MUTATIONS = {"addPullRequestReview", "submitPullRequestReview"}
MERGE_MUTATIONS = {"mergePullRequest", "enablePullRequestAutoMerge"}
UNRESOLVED = object()


def _value(node, variables):
    """Resolve a GraphQL value node, substituting variables. UNRESOLVED if impossible."""
    if node is None:
        return None
    if isinstance(node, gast.VariableNode):
        return variables.get(node.name.value, None) if isinstance(variables, dict) else UNRESOLVED
    if isinstance(node, gast.ObjectValueNode):
        out = {}
        for f in node.fields:
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
    if isinstance(node, (gast.EnumValueNode, gast.StringValueNode)):
        return node.value
    if isinstance(node, gast.BooleanValueNode):
        return node.value
    if isinstance(node, (gast.IntValueNode, gast.FloatValueNode)):
        return node.value
    return UNRESOLVED


def _input(field_node, variables):
    for a in field_node.arguments or ():
        if a.name.value == "input":
            v = _value(a.value, variables)
            return v if isinstance(v, dict) or v is UNRESOLVED else UNRESOLVED
    return {}


def graphql_request(policy: Policy, body: bytes) -> Decision:
    try:
        req = strict_json(body)
    except (ValueError, UnicodeDecodeError):
        return deny("graphql body is not JSON (or has duplicate keys)")
    if not isinstance(req, dict) or not isinstance(req.get("query"), str):
        return deny("graphql body must be a single {query, variables} object")
    variables = req.get("variables") or {}
    if not isinstance(variables, dict):
        return deny("graphql variables must be an object")
    try:
        doc = gql_parse(req["query"], no_location=True)
    except GraphQLError as e:
        return deny(f"graphql parse error: {e.message}")

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
        # Effective variables: declared defaults, overridden by supplied values.
        op_vars = {}
        for vd in d.variable_definitions or ():
            vname = vd.variable.name.value
            if vname in variables:
                op_vars[vname] = variables[vname]
            elif vd.default_value is not None:
                op_vars[vname] = _value(vd.default_value, {})
        for sel in d.selection_set.selections:
            if not isinstance(sel, gast.FieldNode):
                return deny("fragments at the top level of a mutation are not allowed")
            name = sel.name.value
            fields.append(name)
            if name not in policy.mutations:
                return deny(f"mutation {name} not allowed", detail={"mutations": fields})
            inp = _input(sel, op_vars)
            if name in REVIEW_MUTATIONS and policy.deny_approvals:
                if inp is UNRESOLVED:
                    return deny(f"{name}: could not resolve input to check the review event")
                event = inp.get("event")
                if event is UNRESOLVED or not isinstance(event, (str, type(None))) \
                        or (event or "").upper() == "APPROVE":
                    return deny("approvals are not allowed", detail={"mutations": fields})
                if name == "submitPullRequestReview" and event is None:
                    return deny("submitPullRequestReview without an event")
            if name in MERGE_MUTATIONS:
                pr = inp.get("pullRequestId") if isinstance(inp, dict) else None
                if not isinstance(pr, str) or not pr:
                    return deny(f"{name}: could not resolve pullRequestId")
                lookups.append(pr)
    if not ops:
        return deny("graphql document has no operation")
    mutating = "mutation" in ops
    return allow("graphql " + ("mutation" if mutating else "query"),
                 access="write" if mutating else "read",
                 detail={"ops": ops, "mutations": fields},
                 lookup={"pr_nodes": lookups} if lookups else None)
