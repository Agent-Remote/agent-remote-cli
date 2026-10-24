# 09 Local State And Secrets

- SQLite stores local metadata only; schema changes must be backward compatible or include an explicit migration.
- Access tokens and private keys belong in the platform credential store when available.
- The user-token secret may contain a versioned CLI session with access/refresh credentials
  and deadlines. Update this as one secret, serialize login/refresh/logout with a local file
  lock, and never persist either credential in SQLite. Legacy raw tokens migrate only while
  the Server still accepts them; expired/revoked sessions require login. API mutations are
  not retried automatically after authentication failures.
- File fallback is permitted only with owner-only permissions and atomic writes.
- The community-local-trust macOS build stores the active Network Broker credential in the fixed
  `device-broker-credential.json` under `AGENT_REMOTE_HOME`. It must use an atomic owner-only write;
  the Broker independently rejects symlinks, other owners, links, unsafe modes, and oversized data.
- Tool account credentials, browser cookies, and remote login state must never enter local SQLite or configuration.
- `AGENT_REMOTE_HOME` overrides state paths for tests and custom installations; tests must never use a developer's real home.

WireGuard private keys are generated locally and only public keys are enrolled. SSH private keys remain local and agent forwarding requires explicit authorization. Logout and repair flows must distinguish local cleanup from remote revocation and report partial failures clearly.

## Confirmed WireGuard Configuration

The shared WireGuard configuration workflow uses `SecretStore::read_strict` and
`write_strict`; ordinary credential APIs retain their compatibility behavior.
Strict automatic mode reads a fallback only after the native store definitively
reports absence. Denial, unavailable storage, invalid data, cancellation and timeout
are errors, never permission to generate another key or silently change backend.
Explicit file mode never probes the system store. Secret wrappers have no `Debug`
or `Serialize` implementation; native macOS writes never put secrets in argv.

Strict fallback reads are bounded to 64 KiB, use opened directory/file handles,
and reject links, special files, unsafe ownership and permissions. Windows checks
native ACLs and file identities; directories allow privileged System/Administrators
access but reject untrusted write grants. Staging files receive protected current-user
permissions before secret bytes are written; WireGuard configuration additionally
grants LocalSystem read access. Windows identities use the full 128-bit file ID.
`Config::load_strict` separately bounds non-secret TOML to 64 KiB and rejects linked
or special files without imposing secret-file-only modes on configuration.

Acquire locks in this order: the existing per-home login lock, the user-wide
server/device WireGuard credential lock, then the publication directory lock.
The credential lock defaults to `~/.agent-remote-wireguard-locks`, independent of
`AGENT_REMOTE_HOME`. `AGENT_REMOTE_WIREGUARD_LOCK_ROOT` may select an absolute,
safe shared root with an existing parent. Every cooperating home for the same OS
user must use the same root. Tests must override it with an isolated temporary
root. This lock does not retrofit cross-home serialization into existing login or
logout flows.

Native Keychain/Windows credential calls do not provide a forcibly cancellable
internal deadline. The caller retains its lock guards until such a call returns:
use `block_in_place` on a multithread Tokio runtime and a synchronous boundary on
a current-thread runtime, never a detached credential-writing task. The desktop's
outer CLI-process termination limit remains the final boundary, with unknown
outcome; cancellation cannot claim operating-system work rolled back. Linux
`secret-tool` operations bound stdin/stdout/stderr work, honor cancellation and a
three-second deadline, kill their process group, and bound leader reaping to
500 ms. A CLI SIGTERM handler must drop/cancel the operation so this cleanup runs;
unconditional external SIGKILL cannot execute Rust destructors.

## Skill Command Journal

Store only exact requests, reviewed metadata, operation IDs and idempotency keys, partitioned by
Server URL and authenticated user UUID. Never store credentials, file bytes or live source paths.
Keep distinct configuration/state/resolution/migration/prune/deployment-retry intent domains.
Persist before POST, preserve original receipts, and recover pending input before fresh selection.
SQLite connections close before HTTP awaits. Backend recovery retains its caller-selected UUID on
Server. Its shared CLI public key/receipt registry retains only reviewed identity and submission
evidence, never a second backend execution state machine. See
[runtime recovery](../desktop-runtime-recovery.md) and [architecture](02-architecture.md#skill-manager).

## Account Configuration Import Journal

The CLI is the sole durable owner of original account import request keys. Store only context,
account/request UUIDs, reviewed plan/intent hashes, exact task ID and acceptance phase; never
source paths, manifests or bytes. Reserve before one POST, block a fresh same-account intent
while its original result is pending, and recover only that key and exact task. Status queries
never change the journal. Explicit forget may remove a single definitively rejected submission
or a freshly verified terminal task; never evict ambiguous, in-flight or missing-status keys.
See [desktop import protocol](../desktop-account-import.md) for the bounds and API contract.
