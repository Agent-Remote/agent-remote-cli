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

`skill_commands` records only command metadata, exact request JSON, idempotency identity and original
operation ID, partitioned by Server URL and authenticated user UUID. No token or source file bytes
enter this table. Pending intent uniqueness is enforced by SQLite, and a received receipt cannot be
replaced by a different operation ID. Restart recovery uses the retained generation and request;
Server conflicts are not permission to generate a new plan automatically.

Installation requests reuse `skill_commands` after all package trees are Server-complete. Recovery
stores only immutable item/source metadata, never captured file bytes or live source paths. The
bounded request limit is 4 MiB to accommodate up to 100 items; the schema remains version 4.
Relative source recovery is bound to the original working directory and exact source argument.

Update records share the existing metadata-only journal schema. Local --from paths enter intent hashes,
not stored requests. Batch recovery enumerates pending records only for the exact Server/user, with a
1000-record/16 MiB metadata bound, and recovers automatic Git updates before new source reads. Received
records are excluded. Each skill keeps its original key and generation; there is no global batch key.

State reset/restore uses the same journal with a distinct canonical request shape and intent domain.
The complete exact request is stored before any actual POST; preview requests are never journaled.
No checkpoint bytes enter SQLite. State receipts are recovered via the state operation key endpoint,
not the library endpoint. --last retains request metadata to choose the correct receipt type. Schema
version and the existing per-record bound remain unchanged.

Resolution uses the distinct `state_resolution` journal tag. Before actual resolution POST it retains
one exact conflict domain/ID, plan revision, choice, original provenance, prior choices and reviewed
verified outcome. Scope and local input arguments bind the intent hash; local paths and file bytes
are absent from request metadata. A pending intent is recovered before capture, even if the source
file has changed or vanished. Supersession preserves prior choices/revision instead of claiming the
submitted choice applied. Other accepted receipts must match the reviewed candidate and identities,
ignoring only Server-assigned publication IDs. Pending here means an accepted incomplete plan,
not a deployment queue; update --all skips validated resolution journals.

Explicit revision migration uses `state_migration`, retaining the original selector, resolved immutable
version IDs, complete expected preconditions and reviewed candidate metadata. Recovery precedes fresh
selection. The immutable original result is validated against that review; current supersession is
separate. The existing 4 MiB per-record bound and schema 4 remain unchanged. Batch package updates
skip validated migration journals. No runtime files, credentials or local source paths are stored.

Prune uses the distinct `state_prune` tag, storing the original supplied selector/mode for intent
matching, exact compact `{idempotency_key, confirmation}` command, reviewed canonical summary and
complete disclosure count. The signed confirmation is command metadata, not a login/bearer token;
Server live-user authentication and current plan checks remain mandatory. It is retained only in
the existing owner-private journal and never printed in preview/status output. No file bodies,
full manifests or full loss rows enter SQLite; schema 4 and the existing 4 MiB limit are unchanged.
Complete preview/detail display uses an owner-private temporary metadata spool, removed on drop.
Unknown acceptance keeps its original key; no fresh preview or key substitutes for recovery.

Deployment retries use the `deployment_retry` command tag in the existing journal, retaining only
original operation/generation, exact failed account/attempt IDs, sequence numbers and plan digests.
Pending recovery precedes current status selection. Receipt validation requires the same operation
and generation plus later attempts on the original plans. No new SQLite schema, source bytes,
credentials or runtime paths are introduced. Read-only `status --last` does not acknowledge journals.

Backend recovery commands require a caller-retained nonzero UUID --request-id and exact original
logical task ID. They never generate a replacement key after uncertainty. The Server persists
that immutable request; status is a read-only lookup by the supplied original key. This command
uses the existing administrator user credential without a device-token fallback or new local
credential/journal store. A transport failure retains unknown acceptance and directs the user to
query the same key before repeating it.
