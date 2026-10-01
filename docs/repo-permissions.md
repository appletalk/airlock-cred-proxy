# Per-repo permissions

A GitHub App identity has one permission set, `policy.permissions`, used for every repo in
`policy.repos`. A repo can be given a narrower set of its own, so that the identity can,
say, open and work issues on a repo without also being able to push to it or open pull
requests there:

```toml
[policy]
repos = ["example-org/service-a", "example-org/service-b", "example-org/infra"]
permissions = { contents = "write", pull_requests = "write", issues = "write" }

[policy.repo."example-org/infra"]
permissions = { issues = "write" }      # replaces the global set for this repo
```

The set replaces the global one for that repo; it is not merged with it. `metadata = "read"`
is always added, as it is to the global set.

## The rule

A token the proxy mints never carries more permission on a repo than that repo's
effective set: its own set if it has one, else the global set. GitHub refuses anything
beyond the token, so the proxy's own request checks are not the only line.

## What each request gets

| Request | Token covers | Permissions |
|---|---|---|
| REST or git on one repo | that repo | its effective set; reads get the read-only form of it |
| GraphQL query | every policy repo | the *shared set*, read-only |
| GraphQL document whose mutations are all issue-level | every policy repo | the shared set |
| Any other GraphQL mutation document | only the *full repos* | the global set |

- The **shared set** is each permission that every policy repo grants, at the lowest level
  any of them grants it. With `infra` above it is `issues:write, metadata:read`.
- The **full repos** are those whose effective set is the whole global set. With `infra`
  above they are `service-a` and `service-b`.
- **Issue-level mutations** are `createIssue`, `updateIssue`, `closeIssue`, `reopenIssue`,
  `addComment`, `updateIssueComment`, `deleteIssueComment`, `addLabelsToLabelable`,
  `removeLabelsFromLabelable`, `addAssigneesToAssignable`, `removeAssigneesFromAssignable`,
  `addReaction` and `removeReaction`. The two comment edits are here on purpose: an issue
  comment, on an issue or a pull request, needs only issues write.
- If some repo's own set lacks `issues = "write"`, the shared set cannot write issues, so
  issue-level documents take the full token instead (full repos, global set).
- A document that **mixes** issue-level and other mutations gets the full token, over the
  full repos only, so it cannot reach a narrowed repo at all.
- An installation token has one permission set for all its repos, which is why GraphQL
  needs these rules: the proxy cannot tell which repo a node ID belongs to before it
  forwards the request.

REST and git writes are also checked by the proxy, before anything reaches GitHub. On a
repo with its own set, each write needs its permission at write level there: pull request
endpoints need `pull_requests`, issue, label and assignee endpoints need `issues`, and
pushes, refs, contents and merges-into-branch need `contents`. Merging a pull request and
updating its branch need both `contents` and `pull_requests`. On a repo without its own
set nothing changes: those writes are left to GitHub and the token, as before. A
`rest_allow` write on a narrowed repo is passed with that repo's token, so GitHub decides
it.

## Keeping gh's reads working

`gh` uses GraphQL for most reads (`gh pr list`, `gh pr view`, `gh issue list`), and a
GraphQL query token covers every policy repo, so it can only read what every repo can
read. With `infra = { issues = "write" }` above, a query can no longer read pull
requests or code in any repo, `service-a` included. If you need those reads, grant them
read-only in the narrow repo's set:

```toml
[policy.repo."example-org/infra"]
permissions = { issues = "write", contents = "read", pull_requests = "read" }
```

That still refuses pushes and pull-request writes on `infra`, and the issue-level GraphQL
token becomes `issues:write` plus read of contents and pull requests across every repo.

`check-config` prints a note when the shared set is missing something from the global
set. It also prints each repo's effective set and the three GraphQL tokens:

```
  perms      contents:write, issues:write, metadata:read, pull_requests:write
    example-org/service-a: contents:write, issues:write, metadata:read, pull_requests:write
    example-org/service-b: contents:write, issues:write, metadata:read, pull_requests:write
    example-org/infra (own set): issues:write, metadata:read
  graphql    one token per request, so it carries no more than every repo it covers allows:
    queries          every policy repo: issues:read, metadata:read
    issue mutations  every policy repo: issues:write, metadata:read
    other mutations  example-org/service-a, example-org/service-b: contents:write, ...
```

`explain` shows the token a request would get, as `token.repos` and `token.permissions`.

## Validation

The config is refused when:

- a per-repo set names a permission the global set lacks, or a higher level than the
  global set grants;
- a value is anything but `"read"` or `"write"`;
- a `[policy.repo."..."]` table has a key other than `permissions` and
  `merge_denied_bases`, or the same repo appears twice (names are compared without case);
- the repo is not in `policy.repos`;
- `policy.repos` is `["*"]`, because a GraphQL token for every repo the installation
  reaches would cover the narrowed repo with the full set;
- the identity is a `token`, because a fixed token cannot be narrowed at mint time.

`check-config --resolve` also compares `policy.permissions` with what the App installation
actually grants and refuses the config if it asks for more. Every per-repo set is a subset of
the global set, so that covers them too.

These checks apply to every config: a `[policy.repo]` table with a misspelt key, which was
silently ignored before, is now an error.

If every policy repo has a narrower set of its own, no repo is full, and a GraphQL
mutation other than an issue-level one is refused.
