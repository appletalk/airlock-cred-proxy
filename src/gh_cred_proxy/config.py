"""Configuration: one identity and one policy per proxy instance."""
import os
import tomllib
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from urllib.parse import urlsplit

# Mutations a pull-request and issue workflow needs. Anything else is refused
# unless the config replaces this list.
DEFAULT_MUTATIONS = frozenset({
    "addAssigneesToAssignable", "addComment", "addLabelsToLabelable",
    "addPullRequestReview", "addPullRequestReviewComment", "addPullRequestReviewThread",
    "closeIssue", "closePullRequest", "convertPullRequestToDraft", "createIssue",
    "createPullRequest", "deleteIssueComment", "disablePullRequestAutoMerge",
    "markPullRequestReadyForReview", "mergePullRequest",
    "removeAssigneesFromAssignable", "removeLabelsFromLabelable", "reopenIssue",
    "reopenPullRequest", "requestReviews", "submitPullRequestReview", "updateIssue",
    "updateIssueComment", "updatePullRequest",
})

# Mutations that move refs or merge without a checker in this proxy. They cannot be enabled:
# auto-merge and the merge queue act later, after the base can have been retargeted.
NEVER_MUTATIONS = frozenset({
    "enablePullRequestAutoMerge", "enqueuePullRequest", "createCommitOnBranch", "mergeBranch",
    "updateRefs", "createRef", "updateRef", "deleteRef", "updatePullRequestBranch",
    "revertPullRequest",
    "cloneTemplateRepository", "createRepository", "deleteRepository", "transferRepository",
    "updateBranchProtectionRule", "deleteBranchProtectionRule", "createBranchProtectionRule",
})

DEFAULT_READ_PATHS = ("/rate_limit", "/meta", "/zen", "/users/*")

ACCESS_LEVELS = ("read", "write")


class ConfigError(ValueError):
    pass


def normalise_branch(name: str) -> str:
    """GitHub accepts both 'main' and 'refs/heads/main' for a branch; compare the short form."""
    return name[len("refs/heads/"):] if name.startswith("refs/heads/") else name


@dataclass
class Policy:
    repos: list[str]
    permissions: dict[str, str]
    push_branches: list[str]
    push_tags: bool
    deny_approvals: bool
    merge_denied_bases: list[str]
    repo_merge_denied_bases: dict[str, list[str]]
    mutations: frozenset[str]
    rest_allow: list[tuple[str, str]]
    read_paths: tuple[str, ...]

    def repo_allowed(self, full_name: str) -> bool:
        if "*" in self.repos:
            return True
        return full_name.lower() in {r.lower() for r in self.repos}

    def branch_pushable(self, branch: str) -> bool:
        branch = normalise_branch(branch)
        if self.merge_protected(None, branch):
            return False
        return any(fnmatchcase(branch, p) for p in self.push_branches)

    def merge_protected(self, full_name: str | None, base: str) -> bool:
        base = normalise_branch(base)
        pats = list(self.merge_denied_bases)
        if full_name:
            for name, extra in self.repo_merge_denied_bases.items():
                if name.lower() == full_name.lower():
                    pats += extra
        return any(fnmatchcase(base, p) for p in pats)

    def read_permissions(self) -> dict[str, str]:
        return {k: "read" for k in self.permissions}


@dataclass
class Config:
    socket: str
    socket_mode: int
    socket_group: str | None
    audit_log: str
    api_host: str
    git_host: str
    api_url: str
    git_url: str
    kind: str
    app_id: str | None
    owner: str | None
    installation_id: int | None
    key_source: dict
    token_source: dict
    policy: Policy = field(repr=False)


def _need(table: dict, key: str, where: str):
    if key not in table:
        raise ConfigError(f"missing {where}.{key}")
    return table[key]


def _source(value, where: str) -> dict:
    if not isinstance(value, dict) or len(value) != 1:
        raise ConfigError(f"{where} must be one of {{command=[...]}}, {{file=...}}, {{systemd_credential=...}}")
    (k, v), = value.items()
    if k == "command" and isinstance(v, list) and v and all(isinstance(x, str) for x in v):
        return value
    if k in ("file", "systemd_credential") and isinstance(v, str) and v:
        return value
    raise ConfigError(f"{where}: bad {k!r}")


def parse(data: dict) -> Config:
    server = data.get("server", {})
    ident = _need(data, "identity", "")
    pol = data.get("policy", {})

    kind = _need(ident, "kind", "identity")
    if kind not in ("github-app", "token"):
        raise ConfigError("identity.kind must be 'github-app' or 'token'")

    perms = pol.get("permissions", {"contents": "write", "pull_requests": "write", "issues": "write"})
    for k, v in perms.items():
        if v not in ACCESS_LEVELS:
            raise ConfigError(f"policy.permissions.{k} must be read or write")
    perms = {"metadata": "read", **perms}

    repos = pol.get("repos")
    if not repos:
        raise ConfigError("policy.repos is required; use [\"*\"] to allow every repo the credential reaches")

    repo_tables = pol.get("repo", {})
    mutations = pol.get("graphql_mutations")
    if mutations is not None:
        bad = sorted(set(mutations) & NEVER_MUTATIONS)
        if bad:
            raise ConfigError(f"policy.graphql_mutations cannot include {', '.join(bad)}: "
                              "they move refs or merge without a check this proxy can make")
    policy = Policy(
        repos=list(repos),
        permissions=perms,
        push_branches=list(pol.get("push_branches", [])),
        push_tags=bool(pol.get("push_tags", False)),
        deny_approvals=bool(pol.get("deny_approvals", True)),
        merge_denied_bases=list(pol.get("merge_denied_bases", [])),
        repo_merge_denied_bases={n: list(t.get("merge_denied_bases", [])) for n, t in repo_tables.items()},
        mutations=frozenset(mutations) if mutations is not None else DEFAULT_MUTATIONS,
        rest_allow=[(m.upper(), p) for m, p in pol.get("rest_allow", [])],
        read_paths=tuple(pol.get("read_paths", DEFAULT_READ_PATHS)),
    )

    api_url = server.get("api_url", "https://api.github.com")
    git_url = server.get("git_url", "https://github.com")
    cfg = Config(
        socket=_need(server, "socket", "server"),
        socket_mode=int(str(server.get("socket_mode", "0660")), 8),
        socket_group=server.get("socket_group"),
        audit_log=server.get("audit_log", "-"),
        api_host=server.get("api_host", urlsplit(api_url).hostname),
        git_host=server.get("git_host", urlsplit(git_url).hostname),
        api_url=api_url.rstrip("/"),
        git_url=git_url.rstrip("/"),
        kind=kind,
        app_id=str(ident["app_id"]) if "app_id" in ident else None,
        owner=ident.get("owner"),
        installation_id=int(ident["installation_id"]) if ident.get("installation_id") else None,
        key_source=_source(ident["key"], "identity.key") if kind == "github-app" else {},
        token_source=_source(ident["token"], "identity.token") if kind == "token" else {},
        policy=policy,
    )
    if kind == "github-app" and not (cfg.app_id and cfg.owner and "key" in ident):
        raise ConfigError("github-app identity needs app_id, owner and key")
    if cfg.socket_mode & 0o007:
        raise ConfigError("server.socket_mode must not grant access to other users")
    if kind == "github-app":
        stray = [r for r in cfg.policy.repos if r != "*" and r.split("/", 1)[0].lower() != cfg.owner.lower()]
        stray += [r for r in cfg.policy.repo_merge_denied_bases if r.split("/", 1)[0].lower() != cfg.owner.lower()]
        if stray:
            raise ConfigError(f"repos outside the installation owner {cfg.owner!r}: {', '.join(stray)}")
    if any("/" not in r for r in cfg.policy.repos if r != "*"):
        raise ConfigError("policy.repos entries must be owner/name")
    if len(cfg.socket.encode()) > 107:
        raise ConfigError("server.socket path is longer than the 107-byte Unix socket limit")
    return cfg


def load(path: str) -> Config:
    with open(path, "rb") as f:
        return parse(tomllib.load(f))


def read_source(src: dict) -> str:
    """Resolve a secret source to its text. The caller keeps it in memory only."""
    import subprocess
    (k, v), = src.items()
    if k == "command":
        r = subprocess.run(v, capture_output=True, text=True, timeout=60)
        if r.returncode:
            raise ConfigError(f"secret command {v[0]!r} exited {r.returncode}")
        return r.stdout
    if k == "file":
        with open(v) as f:
            return f.read()
    cred_dir = os.environ.get("CREDENTIALS_DIRECTORY")
    if not cred_dir:
        raise ConfigError("systemd_credential set but CREDENTIALS_DIRECTORY is not (run under systemd with LoadCredential=)")
    with open(os.path.join(cred_dir, v)) as f:
        return f.read()
