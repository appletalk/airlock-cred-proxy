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
| Forwarder, `env` | The forwarder secret | Other local users |
| The agent | Nothing | - |

Run the proxy as a dedicated system user, with the key delivered by systemd
`LoadCredential=` (or `LoadCredentialEncrypted=`), and the socket group-restricted to the
accounts that may use it. `contrib/gh-cred-proxy@.service` does this.

## Design choices

- **Fail closed.** Unknown endpoints, unparseable bodies, unresolvable variables,
  failed upstream lookups and anything larger than the inspection limit are refused.
- **Parse like the server does.** Bodies the policy reads are parsed once and forwarded
  byte-for-byte. Duplicate JSON keys are refused so the proxy and GitHub cannot read
  different values. Requests with both `Content-Length` and `Transfer-Encoding` are
  refused.
- **Check the real state.** Merge decisions use the base branch GitHub reports for the
  PR, not what the request claims.
- **Mint narrow.** Each token covers one repo (or the allowlist, for GraphQL) and only
  the access the request needs.
- **Log decisions, not secrets.** The audit log never contains tokens or bodies.

## Known limits

- A `token` identity cannot be narrowed at mint time. GraphQL queries through it can
  read anything the token can.
- The loopback forwarder authenticates the first request on each connection. Anyone
  who can read the forwarder secret file (mode 0600) can use the identity.
- Allowed branches are only as safe as the branch protection behind them. The proxy
  keeps the agent off protected branches. It does not replace GitHub rulesets, which
  should still require reviews on those branches.
- The proxy does not inspect pack contents. It does not stop the agent pushing
  secrets or large files to an allowed branch.
- GitHub Enterprise Server is untested.

## Reporting

Open a private security advisory on the repository.
