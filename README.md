# gh-cred-proxy

A credential-injecting, policy-enforcing proxy between an AI coding agent (or any
untrusted process) and GitHub.

The agent never holds a GitHub credential. It talks to a Unix socket. The proxy decides
whether each request is allowed, attaches a short-lived token scoped to that one request,
and forwards it to GitHub. Every request is written to an audit log.

This follows the proxy pattern in Anthropic's guide to
[securely deploying AI agents](https://code.claude.com/docs/en/agent-sdk/secure-deployment):
keep credentials outside the agent's security boundary, inject them at a proxy, allowlist
what the agent may reach, and log everything.

## What it enforces

| Control | Behaviour |
|---|---|
| Credential isolation | The client's own `Authorization` is always stripped. The key stays in the proxy process. |
| Least privilege per request | A GitHub App token is minted for the one repo a request touches, read-only for reads, write only for writes. Tokens are cached until five minutes before expiry. |
| Repo allowlist | Requests for repos outside `policy.repos` are refused before anything reaches GitHub. |
| Branch pushes | `git push`, ref API writes, contents API writes and merges-into-branch only reach branches matching `push_branches`. Tags are refused unless `push_tags = true`. A push that mixes allowed and refused refs is refused whole. |
| No approvals | Approving reviews are refused over REST and GraphQL, including through variables, variable defaults and aliases. The agent cannot approve its own or anyone else's pull request. |
| Protected bases | Merging a PR into a `merge_denied_bases` branch is refused. The proxy looks up the PR's real base on GitHub instead of trusting the request. Retargeting a PR onto a protected base is refused over REST and GraphQL. Auto-merge and the merge queue cannot be enabled, because they act after the check. |
| REST writes | Only a fixed set of pull-request, issue and branch endpoints. Everything else is refused unless listed in `rest_allow`. |
| GraphQL | Parsed with `graphql-core`. Queries pass. Mutations must be in the allowlist, and mutations that move refs without a check here (`createCommitOnBranch`, `updateRefs` and similar) cannot be added to it. Subscriptions, top-level fragments in mutations, duplicate fields or JSON keys, undeclared variables and deeply nested documents are refused. |
| Request hygiene | Non-ASCII or non-canonical paths, `%` outside a contents file path, query strings and method-override headers on writes, ambiguous body framing and unknown hosts are refused. Archive downloads are refused because their redirects carry a signed token. |
| Resource limits | Inspected bodies are capped at 1 MiB and read in pieces, the push command section is parsed incrementally, and concurrent connections are capped. |
| Audit | One JSON line per request: time, peer pid and uid, method, host, path, repo, decision, reason, status, bytes. Never tokens or bodies. |

Anything the proxy cannot classify is refused.

## How clients reach it

- **`gh`** has an `http_unix_socket` setting and speaks plain HTTP over it, so it talks
  to the proxy directly. It needs a placeholder `GH_TOKEN` to start; the proxy discards it.
- **`git`** reaches the same socket as a SOCKS5 proxy
  (`http.proxy=socks5h://localhost/<socket>`; needs a curl that supports SOCKS over a
  Unix socket, tested with curl 8.22). It
  connects to `github.com:80` through the proxy and sends plain HTTP, which the proxy
  inspects like any other request.
- **`gh-cred-proxy env`** prints the environment for one shell: URL rewrites from
  `https://`, `git@` and `ssh://` to plain `http://github.com/`, the SOCKS proxy for that
  URL, an empty credential helper, the `gh` settings, and the bot's git author and
  committer identity.

Access control is the socket's file permissions. Nothing listens on TCP.

Nothing is written to any repository's `.git/config`. Remotes keep their normal
`git@github.com:` or `https://` URLs, so the same checkout still works outside the
agent's shell with your own SSH key.

## Install

```
git clone https://github.com/appletalk/gh-cred-proxy
cd gh-cred-proxy
python3 -m venv .venv
.venv/bin/pip install --require-hashes -r requirements.lock
.venv/bin/pip install --no-deps .
```

Run the service from an installed copy owned by root, never from a working tree that the
agent or your everyday account can edit. `contrib/` has a socket unit and a hardened
service unit; systemd creates the socket with the right group and mode.

## Configure

See `examples/config.toml`. Validate and dry-run before deploying:

```
gh-cred-proxy check-config --config config.toml
gh-cred-proxy check-config --config config.toml --resolve     # also load the key and mint a token
gh-cred-proxy explain --config config.toml POST https://api.github.com/repos/o/r/pulls/1/reviews --body review.json
gh-cred-proxy explain --config config.toml POST https://github.com/o/r.git/git-receive-pack --ref refs/heads/main
```

`explain` exits 0 when the request would be allowed and 1 when refused. It makes no
network calls, so checks that need GitHub (a PR's real base) show as `upstream_check`.

## Run

```
gh-cred-proxy serve --config /etc/gh-cred-proxy/app.toml                   # the service
gh-cred-proxy status --socket /run/gh-cred-proxy/app.sock                  # health and identity
eval "$(gh-cred-proxy env --socket /run/gh-cred-proxy/app.sock)"           # per shell
gh-cred-proxy audit --log /var/log/gh-cred-proxy/app.jsonl --denied        # what was refused, and why
gh-cred-proxy audit --log /var/log/gh-cred-proxy/app.jsonl --summary
```

A refused `git push` shows only `HTTP 403` on the client, because git does not print
error bodies for push requests. The reason is in the audit log.

## Identities

- `kind = "github-app"`: the recommended identity. Tokens are minted per request and
  scoped by repo and permission. With `deny_approvals` on, the App cannot approve anything.
- `kind = "token"`: fronts an existing token, for example a person's session token, so
  an agent can use a narrow slice of it without holding it. The token cannot be narrowed
  at mint time, so the policy is the only control. GraphQL queries and mutations are not
  limited by repo: an allowed mutation works on any repo the token reaches. Use a tight
  `graphql_mutations` list, and prefer a GitHub App wherever one can do the job.

One identity per proxy instance. Run one instance per identity, each with its own socket.

## Scaling beyond one workstation

The proxy is the only component that holds the key. It can run on a shared host, with
each operator reaching it over a socket or an authenticated tunnel, so the key exists in
one place instead of on every workstation. `env` and the socket mount stay local to each
client.

## Test

```
.venv/bin/python -m unittest discover -s tests -t .
.venv/bin/python tests/mutate.py        # each protection, broken on purpose, must fail a test
```

The end-to-end tests run the real proxy with real `git` over SOCKS5 against a fake
GitHub backed by `git http-backend`.

## Licence

AGPL-3.0-or-later.
