# Unlock: credentials held in memory for the working day

Status: built 2026-09-30; the systemd wiring is untested on a live host.

## Goal

Sit down at the workstation, unlock once, work. The credential the proxy fronts is not on
disk in usable form, and it is not held in memory longer than the working day. Unlocking
uses the password the operator already types (the gpg passphrase for `pass`), so the proxy
adds no password of its own.

Without unlock, the key reaches the service from a file (`LoadCredential=`, `file`) or a
command the service runs at start. Those leave the credential usable at rest: anyone who can
read the file, or restart the service, has it. With unlock, the only copy outside the
operator's password store is in the proxy's memory, and it is gone when the proxy locks,
restarts, or the machine reboots.

## The boundary

The agent in a box can never unlock. This is not a rule the agent follows: no path leads
from a box to an unlocked credential, and any path found is a defect.

### Assumption

The box cannot run code on the host as the operator. If it can, this boundary and every
other one airlock draws are gone: code running as the operator can read `pass` while
gpg-agent has the passphrase cached, or run `unlock` itself. Known channels from a box to
host code execution are airlock's to close, not this proxy's:

- a shared directory the host later runs code from (git hooks and `core.fsmonitor` in a
  `share_rw` repo, the read-write memory directory an unboxed session loads);
- an unboxed agent session on the same host, which can unlock as easily as the operator.

A dedicated `GNUPGHOME` for the unlock entries with a cache TTL of 0 would narrow the
gpg-agent window, at the cost of a passphrase prompt per unlock. It is not done here.

### What unlocking needs

| Needed to unlock | Why a box cannot reach it | Enforced by |
|---|---|---|
| The admin socket | Owned by the operator's uid. airlock grants only sockets owned by a dedicated service account and refuses the operator's own sockets whatever the path, with no override. `airlock mount` refuses directories outside `$HOME`. Folder shares do not yet get these checks: see the airlock gaps below. | claude-airlock `_airlock_socket_check`, `_airlock_mount_check` |
| The secret | Stored in `pass`, encrypted to the operator's gpg key. `~/.password-store` and `~/.gnupg` are on airlock's mount deny list, with no override. | `AIRLOCK_MOUNT_DENY` |
| The gpg agent | A socket owned by the operator and named `S.gpg-agent*`: refused by owner and by name. The same holds for ssh-agent. | `_airlock_socket_check` |
| The gpg key | The passphrase alone is useless without the key in `~/.gnupg`. The box does share the operator's terminal and could draw a fake pinentry, so the key, not the terminal, is what protects this row. | `AIRLOCK_MOUNT_DENY` |

### Inside the proxy

- **No secretless verb.** The admin socket has three operations: status, unlock and lock.
  Unlock carries the secret; there is no "extend", "refresh" or "renew". A process that
  reached the admin socket could lock the proxy, or install a credential it already holds.
  It could not turn a locked proxy back on.
- **Peer check.** The admin socket refuses any peer whose uid is not the socket file's
  owner, and refuses everyone if the socket's mode grants group or other access.
- **Not grantable when bound by the proxy.** Outside systemd the proxy binds the admin
  socket itself, owned by its own uid. It refuses to do that when it runs as a system
  account, because airlock grants sockets owned by system accounts.
- **No admin path on the data socket.** The data socket serves proxied requests and two
  read-only local paths (health, identity). Admin paths there are refused like any other.
- **Unix sockets only.** Nothing listens on TCP. A box on a bridged network can reach host
  TCP listeners, so nothing that unlocks may ever listen there.

### Inside the `unlock` command

`unlock` runs on the host and hands out secrets, so it must not be pointed at a socket a box
controls. A box runs as the operator, so a socket it serves from a shared directory looks
like any other operator-owned socket. Before sending anything, `unlock` checks:

- the socket path has no symlink, and every directory from it up to `/` is owned by root,
  with the socket's own directory writable by nobody else;
- the process listening on it (`SO_PEERCRED`) is root, which systemd is for an activated
  socket, or a system account. It is never the operator's own uid.

It also re-checks each entry name the proxy asks for before it reaches `pass show`.

A box runs as the operator's uid (podman keep-id), so file permissions and `SO_PEERCRED`
cannot tell a box from the operator. What holds the boundary is that the admin socket, the
store and the key never reach a box, which is why airlock's refusals carry no override.

The same boundary goes into every later design in this repo: each one states how it keeps
unlocking out of reach of a box.

## Operator flow

```
$ airlock-cred-proxy unlock
board: unlocked as keith-phsa until 2026-09-30T18:00:00-0700
```

1. `unlock` finds the admin sockets (`/run/airlock-cred-proxy/*.admin.sock`, or those named
   with `--socket`) and checks each as above.
2. It asks each proxy which `pass` entries it needs. The proxy answers from its own
   root-owned config, so `unlock` reads only those entries.
3. It runs `pass show <entry>` for each. gpg-agent prompts once and caches the passphrase,
   so several instances cost one prompt.
4. It sends the material over the admin socket. The proxy builds the credential and checks
   it against GitHub (the identity lookup it does at start today) before it reports
   unlocked. A secret that does not work leaves the proxy as it was.

`airlock-cred-proxy lock` locks every instance at once. `unlock --for 2h` unlocks for less
than the configured lifetime, never more. Unlocking again while unlocked restarts the clock;
it needs the secret, so that is not a way around the lifetime. `unlock` warns when the
deadline it got is under 30 minutes away.

## Expiry

```toml
[unlock]
max_lifetime = "10h"    # required, at most 24h; matches a gpg-agent max-cache-ttl of 36000
expire_at = "18:00"     # optional; the proxy's local time
idle = "2h"             # optional; lock after this long with no allowed request
```

The proxy locks at whichever comes first:

- unlock time plus `max_lifetime` (or `--for`);
- the next `expire_at` strictly after the unlock. An unlock at exactly 18:00 rolls to
  tomorrow's 18:00, which the lifetime then caps;
- `idle` since the last allowed, forwarded request. Health, identity and refused requests
  do not count.

This covers the out-of-hours case: unlocking at 19:00 with `expire_at = "18:00"` locks at
05:00, ten hours later, because the next 18:00 is further away. `expire_at` follows local
time across DST changes. A time inside the spring-forward gap resolves an hour later.

The lifetime is checked on two clocks. The wall clock is read on every use, so a
workstation that wakes from suspend is locked on its first request even if no timer has
fired. The boot clock (`CLOCK_BOOTTIME`) keeps running through suspend and never steps
backwards, so setting the wall clock back cannot extend the session. A background timer
locks at the deadline, re-checking at least every 30 seconds, so memory is cleared without
traffic. A restart always starts locked. Restarting the service or either socket unit, or
upgrading the package, therefore needs a fresh unlock.

Deadlines are reported with their UTC offset and as epoch seconds, because a box usually
runs in UTC while `expire_at` is the host's local time.

## When the credential is locked

Every proxied request gets **HTTP 423 Locked**, with the body
`airlock-cred-proxy: credential locked (<reason>); unlock on the host with 'airlock-cred-proxy unlock'`
and the header `X-Airlock-Cred-Proxy: locked`. The proxy strips that header from upstream
responses, so GitHub cannot forge it. The lock is checked before anything else about the
request, so a locked proxy answers 423 even to a request the policy would refuse. The audit
log records `decision: "locked"`.

Tested with git 2.55 and gh 2.101: neither retries. git prints the body as `remote:` lines
and then `The requested URL returned error: 423`. On a push, git may print only
`RPC failed; HTTP 423`, so the agent keys on the status and the body text, not on the
header, which git and gh do not show.

The health path reports the state, the deadline and the minutes left, so
`airlock-cred-proxy status` in the box shows time remaining. It exits 3 while locked.

The identity path answers with the identity from the last unlock, because it is not secret.
Before the first unlock since the proxy started, it returns 423. `env` then still routes
git and gh through the proxy, so the lock shows up as 423 and nothing goes around the
proxy. It sets an empty author and committer, so git refuses to commit instead of falling
back to another identity, and it says why on stderr.

Each request takes the credential once, before reading its body, and uses it to the end.
A lock that lands later lets that request finish and refuses the next one. Such a request
can still mint an App token after the lock, bounded by the request deadline (30s) and the
upstream timeout (600s). Minted installation tokens stay valid at GitHub for up to an hour.
They never leave the proxy, and the lock drops the cache that holds them. A multi-step
operation can stop between steps (a branch pushed, its pull request not yet opened), and
never inside one request.

A lock that arrives while an unlock is being checked against GitHub wins: the unlock is
discarded and reports that it was locked.

## What the agent does on 423

This is agent behaviour, recorded here so the proxy matches what the agent needs. For Otto
it goes into Otto's repo conventions.

- Stop the workflow at the step that got 423. Do not retry: a lock does not clear by itself.
- Report to the operator which steps completed, the step that failed, and the exact step to
  resume from. Name a half-done operation as such.
- Before a multi-step write sequence, read `status`. If the lock is under 30 minutes away,
  say so first.
- Never try to unlock. There is no way to from the box; asking the operator is the only
  path, and it is the intended friction.

## Configuration

A credential that unlocks names its `pass` entry:

```toml
[identity]
kind = "token"
token = { pass = "github/gh_token" }     # the first line of the entry
tier = "day"

# or, for an App:
# key = { pass = "github/otto-app.pem" } # the whole entry, a PEM key

[server]
socket = "/run/airlock-cred-proxy/board.sock"
# admin_socket defaults to the socket path with .admin.sock

[unlock]
max_lifetime = "10h"
expire_at = "18:00"
```

Rules, checked when the config loads:

- A `pass` source needs an `[unlock]` table, and `[unlock]` needs a `pass` source.
- An entry is `/`-separated segments of letters, digits and `._@+-`, each starting with a
  letter, digit or `_@+`. No option, no dot-file, no `..`.
- `tier` is `day`, the only tier today. It exists so elevation can be added without
  reshaping the config.
- `max_lifetime` is at most 24h; `expire_at` is `HH:MM`.
- The proxy never reads a `pass` source itself; only `unlock` does, on the host.

The existing sources (`file`, `systemd_credential`, `command`) work unchanged: unlocked from
start, no expiry, no admin socket.

## systemd

`contrib/airlock-cred-proxy-admin@.socket` listens on `/run/airlock-cred-proxy/%i.admin.sock`
and activates the same service (`Service=airlock-cred-proxy@%i.service`). It is owned by
root with mode 0600 until a drop-in names the operator (`SocketUser=`). Owning it as the
operator is what makes airlock refuse to grant it. The two descriptors are told apart by
`FileDescriptorName=data` and `=admin`; the service refuses two descriptors without those
names, and refuses an admin descriptor when the config has no `[unlock]`.

`contrib/unlock.conf.example` has the drop-ins: the admin socket owner, `Sockets=` and
`Requires=` for both sockets, and an empty `LoadCredential=` so the instance loads no key
from disk. Delete the instance's old key file.

The service unit sets `MemorySwapMax=0` and `LimitCORE=0`, and the proxy sets
`PR_SET_DUMPABLE` to 0 when unlock is configured, so the credential is kept out of swap and
core dumps and other processes of the service user cannot ptrace it. Python cannot reliably
wipe a string, so "gone" means unreferenced, not zeroed. Hibernation writes memory to disk
and is not covered.

## Later: elevation

Some actions deserve a fresh, short unlock even inside the working day, the way GitHub asks
for the password again before sensitive changes. With tiers in the config this becomes
`airlock-cred-proxy elevate --for 15m`, unlocking an `elevated` credential that expires on
its own clock. Not built; the `tier` field and the per-credential gate are the hooks.

## Later: many users

Not designed yet; recorded so the single-user build does not close it off.

Keep the proxy on each workstation and centralise only what issues credentials. A central
proxy would put agent traffic on the network, see every user's requests, and add a WAN
round trip to every git call. The one thing a workstation should not hold is the App's
private key.

```
box --unix socket--> local proxy (inspects, enforces, audits)
                        |  TLS, short-lived user token
                        v
                  token broker (App key in a vault or HSM)
                        |  mints a 1h installation token scoped to the user's entitlement
                        v
                     GitHub
```

- **Unlock becomes a single sign-on login** with MFA on the host. The proxy holds a
  session token, not the key. Expiry, 423 and the no-unlock-from-box boundary stay as they
  are.
- **The broker mints tokens** after checking the user's token against their entitlements.
  Revoking a user removes an entitlement; no key rotation on workstations.
- **Policy is distributed, signed, and the daemon is centrally managed**, so neither the
  user nor their agent can edit it locally.
- **Audit ships centrally.**
- **Elevation becomes step-up authentication** for the verbs that need it.

Prior art for the exchange step exists (an OIDC-to-installation-token service, a secrets
engine that mints installation tokens); check its current state before choosing. None of
it does the per-request inspection this proxy does, which is the part to keep.

Iteration path: pass and unlock for one operator (this build); the key moves to a vault
behind a broker and unlock becomes a login; then signed policy, central audit and per-user
entitlements for a fleet.

## Adopting it

Nothing here is specific to one operator: entries come from config, the admin socket owner
from a drop-in, and `pass` is the only store supported today. Another store would be another
source kind that `unlock` reads on the host. The proxy never runs the store's command
itself, because its service account has no access to the operator's keys.

## Relation to airlock and `--network none`

Nothing here depends on the box's network. With bridged networking the box firewall enforces
egress as it does today. With `--network none` the data socket is the box's only route to
GitHub. Unlocking is a host operation in both.

## airlock gaps this design found

These are airlock work, recorded here because the boundary above depends on them:

- **Folder shares get none of `airlock mount`'s checks.** `_gate_shares` joins the share
  base with the relpath from `.airlock/config` and tests it with `[ -d ]`, which follows
  symlinks. There is no canonicalisation, deny list or `$HOME` limit, and `..` is not
  refused. A box that can write in a `share_rw` directory can plant a symlink to
  `/run/airlock-cred-proxy` and request it as a share. The prompt shows the unresolved path.
  Shares need the mount checks, a resolved and stored target, and a refusal of any
  directory that contains a socket.
- **Directory mounts are not checked for sockets inside them.** An agent socket in an
  ordinary directory (a custom `GNUPGHOME`, say) would ride in on a mount.
- **airlock's `secrets` can inject any `pass` entry into a box**, including one a proxy
  unlocks with. It should refuse entries that a proxy config names.

## Tests

`tests/test_unlock.py` covers each property above, and `tests/mutate.py` breaks each
protection to show a test fails:

- locked at start; 423 with the marker on API, GraphQL and git; the marker cannot come from
  upstream; locked answers before a policy refusal
- unlock with a working secret unlocks; one that does not stays locked
- the lock lands at `max_lifetime`, at `expire_at` (strictly after, DST-correct), at
  `idle`, whichever is first; with no traffic; after a wall-clock jump forward; and a wall
  clock set back does not extend it
- `--for` shortens and cannot lengthen
- a lock during an unlock's check wins
- lock drops the cached App tokens; an in-flight request completes across a lock
- the admin socket refuses a peer with another uid and a loose mode, and is not bound by a
  system account; no admin verb unlocks without the secret; the data socket has no admin
  paths
- `unlock` reads only the entry the proxy names, refuses an invalid one, refuses an
  operator-owned or symlinked admin socket
- `env` before the first unlock routes through the proxy and git refuses to commit
- two activated descriptors are told apart by name; the process is not dumpable
- the config rules above
