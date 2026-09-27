# 10 Remote Operations

- The API client owns authentication headers, versioned endpoints, typed payloads, timeouts, and public errors.
- Clients display server-selected runtime backends but do not silently override scheduling policy.
- SSH attach uses server authorization and node forced commands; do not enable arbitrary remote command injection or forwarding.
- Workspace sync preserves managed ignore rules and waits for server-side workspace preparation.
  `sync ensure` re-confirms the idempotent control-plane workspace and sync relationship, replacing
  stale local SQLite mappings and their old managed Mutagen session when remote resources changed.
- External dependency invocation uses resolved argument vectors, checks exit status, and never interpolates server text into a shell command.
- Interrupted sessions are not attachable; replacement behavior must not replay commands.
- Session deletion is limited by the control plane to `stopped`, `interrupted`, and `failed` sessions. The CLI may delete one resolved session ID or request collection cleanup, but it must not broaden the allowed states locally.
- `agent-remote device launch` verifies the fixed signed APP bundle and an unexpired shared device
  credential before launching it. Candidate listing, claim/rebind, local permission checks, and
  application approval remain inside the Device APP and control plane, not the CLI.

Keep retry and polling bounded and cancellable. Contract changes must update server schemas, CLI types, relevant node behavior, contract tests, and user documentation together.

Managed fclaude stop prints the original snapshot operation ID before a bounded saving wait (default
60 seconds). The owner/device-authenticated finalization endpoint, not stop-task replay, supplies
current evidence. `fclaude stop-status` is read-only and remains available after session deletion.
A retained Ctrl+C future and one deadline cover all status requests and sleeps. Timeout returns 3,
interruption 130, reviewable terminal outcomes 1, and published 0. No new stop/upload is submitted
by status polling. See README for legacy compatibility and non-waiting query exit behavior.

Initial takeover waiting lives in session_creation and its typed api/session_takeover transport.
Only an exact MIGRATION_PENDING 409 with reservation_committed=true, session_created=false, original
account and canonical operation UUID permits a retry path. One deadline and Ctrl+C future cover
initial admission, read-only progress and exactly one resumed creation. Reuse the complete original
creation input after committed authority; never retry an uncertain POST. Timeout exits 3, interruption
130 and recovery/identity failure 1. No new credential store or local mutation journal is introduced.

Skill operation targets preserve optional attempt ID/number and per-target retryability. A supplied
attempt must have a canonical identity, positive sequence and original plan digest; retryable
observations require a classified transient failure. Reject malformed metadata without submitting
anything. Preparing remains a pending wait phase, and old missing attempt metadata stays unknown.

`skill retry OPERATION_ID` selects only ended transient failed attempts from the original operation.
It uses a distinct `deployment_retry` journal shape in the existing user/Server-bound local state.
The saved generation, account/attempt identities and original plan digests precede POST. Recovery
queries the original operation's retry-key endpoint, never the library acceptance-key endpoint;
only an absent receipt allows resending identical bytes. `status --last` uses that same read-only
receipt protocol. Successful targets are never selected, and no Git/local acquisition or upload runs.

Frozen Node export uses only the fixed `agent-remote-skill-export --snapshot UUID --protocol 1`
forced command, with forwarding, local commands and SSH configuration execution disabled.
The short-lived original user grant is stdin-only; SSH stderr is discarded to prevent private
remote diagnostics from entering output. Key synchronization polling is bounded to 60 seconds;
initial metadata and final verification each have a 15-minute scan budget. Object/frame reads
reset a 30-second progress timeout after each partial read. Node independently rechecks the original
user/device/key and renews the current grant through the exact predecessor chain. Complete transfer
has no separate fixed deadline; original token expiry and earlier caller cancellation still apply. Server quota exhaustion does not
require an upload bypass: bytes travel directly from the original Node through SSH. The Helper may read either a complete
frozen capture or independently proven stopped work after copy admission failed. The receiver
requires the same complete wire, verified objects, footer, EOF and successful process exit.
Export follows the complete manifest size, including bytes above runtime capture quota; it does not
apply a second fixed 10 GiB byte ceiling. The signed byte-count overflow, 100000-entry and frame
limits remain enforced, with bounded streaming buffers and unchanged authorization deadlines.

## Explicit passive migration recovery contract

Explicit passive backend migration recovery uses a separate administrator-selected request UUID
and exact original logical task ID. Server pins the original task-record UUID itself, preserves
that task/result, and creates recover_tool_account_runtime:<account UUID>:<request UUID>. The
payload is a version-1 binding of recovery task/record, original task/record, Node/user/account,
tool and source/target. Only a terminal original migration still owning the recovery-required
profile can admit a new recovery. Same-key replay is read-only; another key waits for the previous
recovery to end. User content locks serialize acceptance, fresh Node authorization and results.
The current active owner, affinity, legacy directory, no active sessions, source and profile must
still match. A live recovery task lease and exact poll attempt are required before Helper access
and first result acceptance. Success echoes the exact authorization and recovered=true; failure is
fixed content-free metadata. Original failure remains immutable; recovery success advances only
that original profile and preserves account disable. Failed recovery keeps admission closed.
The Helper operation recover_account_migration bypasses generic caches and uses existing
version-2 receipts. Same-boot recovery may settle completed metadata but cannot begin/copy/chown/ACL/
stop anything. Previous-boot recovery requires an already durable whole-migration succeeded receipt,
complete original copy/target phase and ownership evidence, no rollback, and repeated absence of
all recorded current units and cgroups. It rechecks the original account, backup, unchanged receipts
and current boot without rewriting old-boot metadata. A started old-boot migration cannot be promoted
from phase receipts. Missing/old-version evidence, failed/incomplete rollback, foreign/live services,
invalid account, managed fence or absent backup remain recovery-required. Completed target evidence
is rechecked even if the local whole result already says succeeded. This does not authorize
interrupted ownership repair, rollback attestation or backend advertisement.

A stopped runtime whose capture failed reports capture_pending with a finite capture_error.
CLI displays the original operation and a snapshot export command, and ends --wait with exit 1.
This is retryable capture failure, never local durability; later queries may observe successful saving.

## Renewable export transport lifetime

Gateway continuation exchanges the current memory-only grant through `/renew`, retaining exact
predecessor linkage, original binding and all learned capture facts. A successor is accepted only
while the old connection-local window is still live; a late response cannot revive it. Original
user-token expiry/revocation still ends export. `/verify` remains the initial check and the legacy
authority fallback; fallback permissions cannot advance expiry. No uncertain POST is replayed.

A complete transfer no longer has an independent fifteen-minute ceiling. Initial metadata/scanning
and stopped-work final verification remain bounded phases of fifteen minutes each, and earlier
caller cancellation/deadlines win. Gateway and Helper bound each output write block (at most 32 KiB)
to thirty seconds and close transport on failure. CLI bounds gaps between incoming bytes to thirty
seconds and retains separate fifteen-minute initial/final scan waits. Each scan wait ends when
its first prefix byte arrives; the remaining prefix bytes use the ordinary progress bound. Frozen descriptor readers
rotate between objects after ten minutes; a replacement is acquired before the old reader closes,
and the outer immutable manifest hold remains throughout. Complete hashes, exact source recheck,
private staging and required footer/EOF/process success are unchanged. No capabilities are enabled.


Explicit `recovery_version:1` export negotiation now enables the separate bounded-metadata
stopped-work recovery format above 100,000 entries. Manifest v1 remains capped. Source retains
original sealed authority and complete scan comparisons; files stream before their verified hash
trailer to avoid silent prehash stalls. Gateway retains exact live authorization and complete EOF
verification; CLI uses private hash-addressed disk metadata, validates whole topology/content and
requires footer/EOF/SSH success before publication. Old gateways reject unsupported negotiation.
See the negotiated recovery wire contract in the Node `docs/skill-node-export.md`; actual complete
recovery acceptance remains tracked separately, with no production capability advertisement.


## Explicit source restoration verification

`recover-runtime --verify-source` submits `action: "verify_source"`. Its immutable binding is
version 2 with exactly twelve fields, including that action. Default recovery retains version 1
and its original eleven fields; an absent action is never serialized as null. Request keys cannot
change actions. Authorization, renewal and successful results echo the exact versioned binding.
The Helper only verifies an already terminal whole-version-2 failed original with its pre-copy
baseline, immutable failure attestation, copied backup, target/source ownership intents and all
three successful source rollback phases. Repeated complete content/permission/parent checks and
writer quiescence are mandatory; previous-boot records additionally require current unit/cgroup
absence. Verification never repairs permissions or settles incomplete receipts.
Only a fresh matching successful verification marks the original Server profile `rolled_back`,
keeps the source backend and releases that profile's admission gate. Original task/result and
account disable remain unchanged. Failure retains the gate; terminal replay cannot change a newer
profile. This does not implement interrupted repair or enable any runtime capability.


`account recover-runtime --repair-source` explicitly repairs interrupted source permissions from
the original retained backup. It is mutually exclusive with `--verify-source`. Submission carries
`action: "repair_source"`; the immutable twelve-field binding and JSON output use version 3.
Success reports `source_restoration_confirmed`, leaves target confirmation false and preserves
original task failure and account disable. The Helper independently journals and revalidates repair;
completed retries cannot write permissions again. Failed submissions retain the selected action and
unknown confirmation. Versions 1 and 2 and their exact field sets remain unchanged.
