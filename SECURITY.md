# Security model

## What it protects

A process (typically an AI agent in a sandbox) needs to work on GitHub: clone, push
branches, open and update pull requests and issues. It must not be able to:

1. obtain a GitHub credential it could use or leak outside the proxy,
2. act on repos outside its allowlist,
3. push to branches outside its allowed patterns, including default and release branches,
4. approve pull requests, which would defeat branch protection that requires a review,
5. merge into protected bases,
6. use the API beyond the workflow it needs.

## Trust boundaries

| Component | Trusted with | Must not be writable by |
|---|---|---|
| Proxy process | The App private key or the fronted token | The agent, and ideally the operator's everyday account |
| Proxy config | Policy | The agent |
| Proxy code | Enforcement | The agent; run an installed copy, not a working tree |
| The socket | Use of the identity | Accounts outside its group |
| The agent | Nothing | - |

Run the proxy as a dedicated system user, with the key delivered by systemd
`LoadCredential=` (or `LoadCredentialEncrypted=`), and the socket group-restricted to the
accounts that may use it. The units in `contrib/` do this. Nothing listens on TCP: git
reaches the socket as a SOCKS5 proxy.

## Design choices

- **Fail closed.** Unknown endpoints, unparseable bodies, unresolvable or undeclared
  variables, failed upstream lookups and anything larger than the inspection limit are
  refused. An unexpected exception is refused with a 500 and recorded as `error`.
- **Parse like the server does.** Bodies the policy reads are parsed once and forwarded
  byte-for-byte. Duplicate JSON keys are refused so the proxy and GitHub cannot read
  different values. Requests with both `Content-Length` and `Transfer-Encoding` are
  refused.
- **Check the real state.** Merge decisions use the base branch GitHub reports for the
  PR, not what the request claims. Anything that moves a ref, a PR's base or merges goes
  through a checker; mutations with no possible checker cannot be enabled.
- **Mint narrow.** Each token covers one repo (or the allowlist, for GraphQL) and only
  the access the request needs.
- **Log decisions, not secrets.** The audit log never contains tokens or bodies.

## Known limits

- A `token` identity cannot be narrowed at mint time. GraphQL queries and allowed
  mutations through it reach any repo the token can.
- Check, then act. A merge is checked against the PR's base at request time; a
  retarget that lands between the check and GitHub acting on the merge is not caught.
  Retargeting onto a protected base is itself refused, so this needs a second actor.
  GitHub branch protection on those branches is the backstop.
- Responses are passed through. GitHub-signed URLs in responses work without the proxy
  until they expire: contents `download_url` for private repos, image links in rendered
  `body_html` / `bodyHTML`, and Actions log or artifact redirects if the App ever has
  Actions access. They are read-only and cover content the agent could already read
  through the proxy. Archive and release-asset downloads, whose redirects are such URLs,
  are refused.
- A client in the socket group can use up to its per-uid connection share and slow the
  service for others sharing that uid.
- Anyone in the socket's group can use the identity.
- Allowed branches are only as safe as the branch protection behind them. The proxy
  keeps the agent off protected branches. It does not replace GitHub rulesets, which
  should still require reviews on those branches.
- The proxy does not inspect pack contents. It does not stop the agent pushing
  secrets or large files to an allowed branch.
- Allowed actions can have effects the proxy does not see:
  - Labels and comments can trigger merge bots and label-driven auto-merge workflows.
    Do not run such automation on repos an agent works in, or restrict it to human
    actors.
  - Pushes made with a GitHub App token trigger workflows, unlike `GITHUB_TOKEN`. A push
    to an allowed branch runs CI with whatever the agent put in the scripts it calls.
    Keep the agent's branch patterns out of workflows and environments that hold
    secrets.
  - `updateIssueComment` and `deleteIssueComment` work on other people's comments where
    the credential allows it. Remove them from `graphql_mutations` if that matters.
- GitHub Enterprise Server is untested.

## Reporting

Open a private security advisory on the repository.
