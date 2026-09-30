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

# Every mutation the proxy has classified: the defaults, which it checks or knows to be
# harmless for a PR and issue workflow, plus a few that only touch project boards and
# reactions. graphql_mutations may only name these; anything else is a config error, so a
# new or unfamiliar mutation is never enabled by accident. Auto-merge and the merge queue are
# deliberately absent: they act later, after the base can have been retargeted.
SAFE_MUTATIONS = DEFAULT_MUTATIONS | frozenset({
    "addProjectV2ItemById", "archiveProjectV2Item", "clearProjectV2ItemFieldValue",
    "deleteProjectV2Item", "unarchiveProjectV2Item", "updateProjectV2ItemFieldValue",
    "updateProjectV2ItemPosition", "addReaction", "removeReaction",
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
    rest_writes: bool
    projects: frozenset[str] | None
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


def _bool(table: dict, key: str, default: bool) -> bool:
    """A TOML boolean. A string such as "false" is truthy in Python, so it is refused."""
    v = table.get(key, default)
    if not isinstance(v, bool):
        raise ConfigError(f"policy.{key} must be true or false, not {v!r}")
    return v


def _projects(table: dict):
    if "projects" not in table:
        return None
    v = table["projects"]
    if not isinstance(v, list) or not all(isinstance(p, str) and p.startswith("PVT_") for p in v):
        raise ConfigError("policy.projects must be a list of project node IDs (PVT_...)")
    return frozenset(v)


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
        unknown = sorted(set(mutations) - SAFE_MUTATIONS)
        if unknown:
            raise ConfigError(f"policy.graphql_mutations names mutations this proxy has not classified: "
                              f"{', '.join(unknown)}. Mutations that move refs or merge without a check "
                              "(auto-merge, merge queue, createCommitOnBranch, updateRefs) are never classified.")
    policy = Policy(
        repos=list(repos),
        permissions=perms,
        push_branches=list(pol.get("push_branches", [])),
        push_tags=_bool(pol, "push_tags", False),
        deny_approvals=_bool(pol, "deny_approvals", True),
        merge_denied_bases=list(pol.get("merge_denied_bases", [])),
        repo_merge_denied_bases={n: list(t.get("merge_denied_bases", [])) for n, t in repo_tables.items()},
        mutations=frozenset(mutations) if mutations is not None else DEFAULT_MUTATIONS,
        rest_allow=[(m.upper(), p) for m, p in pol.get("rest_allow", [])],
        rest_writes=_bool(pol, "rest_writes", True),
        projects=_projects(pol),
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
    # A token identity cannot be narrowed at mint time, so project mutations without a board
    # pin would reach every board the token can edit.
    project_muts = {m for m in cfg.policy.mutations if "ProjectV2" in m}
    if kind == "token" and project_muts and cfg.policy.projects is None:
        raise ConfigError(f"a token identity allowing {', '.join(sorted(project_muts))} must set policy.projects")
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
