# WireGuard protected execution foundation

This document describes the protected configuration and operation-record
foundation shared by the Rust CLI and desktop control. The desktop
`wireguard.tunnel.apply` method now performs a frozen-plan recheck, reads the
configuration at ordinary user authority, sends only validated bytes and
digests through a fixed platform broker client, and observes the target again
before returning a receipt. The client implements strict caller identity and
one-shot execution-permit contracts; when the protected broker service is not
installed or its response is not independently bound, execution fails closed.
This does not prove that a three-platform installation, authorization, or
restart recovery has passed native validation.
`wireguard.tunnel.plan` remains read-only. Existing human-facing CLI up/down
behavior is unchanged.

Each native broker now persists one-shot request reservations in a fixed
append-only journal and loads that journal before accepting calls after a
restart. The reservation is synced before the privileged tool starts; a
malformed, duplicate, unsafe, or full journal keeps the broker offline. Host
restart recovery still requires native platform evidence.

## Caller-authentication contract

The CLI now contains the version 1 challenge/response contract used by the
platform protected broker clients and services. A broker creates a 32-byte random challenge ID and
nonce, binds them to its installation identity and a maximum 30-second expiry,
and sends only those public fields. The caller computes an HMAC-SHA256 proof
over the protocol label, challenge ID, nonce, expiry, broker identity, the
authenticated caller digest and the exact request digest. The response carries
the two digests and the proof in strict lowercase hexadecimal fields; unknown
fields, wrong protocol versions, malformed digests, clock skew, expired
challenges, and mismatched context are rejected.

The broker compares the proof in constant time and keeps a bounded, in-memory
replay guard. The broker registers each challenge before sending it and rejects
responses for an unissued or altered challenge. A challenge is consumed only
after its proof and independently obtained OS caller identity match; reuse
returns a fixed replay error, while a full guard fails closed instead of
evicting a live challenge. The credential is
accepted only as in-memory key material and never appears in JSON, logs,
operation records, or command arguments. This contract authenticates the
connection and request context only. It does not authorize a tunnel action,
prove target ownership, establish a protected installation, or make the
current `wireguard.bridge.status` report a ready broker. Native IPC must still
bind the expected caller digest to platform peer facts before invoking it.

### Linux D-Bus and polkit boundary

The Linux implementation defines the narrow observation and authorization contract
implemented by the privileged broker service. The broker obtains the D-Bus connection's
unique sender, UID, PID, and process-start timestamp from the system bus, then
asks polkit for the exact `dev.agentremote.wireguard.manage` action. The polkit
Unix-process subject must match all three process facts, return `result: yes`,
and be non-interactive with a result no older than 30 seconds. The CLI hashes
the complete sender/process tuple into `caller_sha256` before it can bind an
execution request.

The CLI does not probe `busctl`, `pkcheck`, or a user-session bus, since a
PATH-selected command or an unprotected user process cannot establish a
privileged boundary. It connects only to the fixed system-bus service; until a
native service is installed and its peer observations are supplied, Linux
broker status remains `unavailable` and execution remains fail-closed. A
matching UID, effective UID zero, or `sudo` environment is never treated as
polkit authorization. The observation structs reject unknown fields,
well-known (non-unique) senders,
PID reuse, mismatched subjects, interactive challenges, stale/long-lived
decisions, and missing components.

The broker's read-only `Status` call also binds its projection to the current
D-Bus sender and a fresh non-interactive polkit decision. A healthy root
service therefore reports `authorized`/`ready` only for the caller that passed
that check; an unauthorized caller receives `not_authorized`, and missing
peer or polkit observations remain unavailable.

Before a Linux broker invokes `wg-quick`, it checks the fixed root-owned,
non-linked regular files for `bash`, `wg-quick`, `wg`, and `ip`. Group/other
writable files, hard links, missing execute bits, or absent dependencies stop
the operation before configuration bytes are staged. The broker uses a fixed
PATH only after these checks; it never resolves a replacement dependency from
the caller's environment.

The human CLI keeps its existing helper path and permission behavior. Desktop
apply does not use that helper or a sudo/runas fallback; the platform client
fails closed when the protected service is unavailable.

## Private configuration transfer

The unprivileged CLI reads the selected configuration once under the source
user's filesystem authority. `ExecutionConfig` retains those exact bytes in a
zeroizing buffer and compares their file identity, content SHA-256 and derived
public key with the confirmed `ConfigBinding`. It rejects unsupported directives
and unstable or unsafe source files. The platform broker receives bytes, not a
source path to reopen with higher privileges. It independently bounds and parses
the transferred bytes and checks content SHA-256 and public key. A transferred
file-identity string is request metadata; bytes alone do not prove source-file
identity or caller authorization.

Private bytes have no `Debug`, `Serialize` or `Clone` implementation and never
pass through Go, the desktop JSON protocol, or an operation record. The protected
configuration file necessarily contains the private configuration; its directory
and file protections must be established before any secret bytes are written.

## Request binding

`ExecutionRequest` is a strict typed object with these fields:

| Field | Meaning |
| --- | --- |
| `version` | Exactly 1 |
| `request_id` | 64 lowercase hexadecimal characters; never reused |
| `caller_sha256` | Digest of the authenticated caller identity |
| `plan_sha256` | Digest of the complete confirmed plan |
| `target_scope_sha256` | Digest of the actual host or network namespace scope |
| `action` | `up` or `down` |
| `logical_name` | Validated platform tunnel name; preserves the confirmed configuration basename |
| `config` | Exact `ConfigBinding`: `file_identity`, `content_sha256`, `public_key` |

Digest fields use 64 lowercase hexadecimal characters. Unknown fields and invalid
bindings are rejected. The authenticated bridge computes caller, plan
and scope bindings from authenticated context and the exact confirmed plan;
accepting hashes supplied by the UI would not establish any of those facts.
Scope observation, target validation and execution must refer to the same host
or namespace. Hashes and this storage API do not grant execution authority.

## Protected storage and locks

`ProtectedDirectory` is rooted in system-protected storage, independently of the
user's CLI home. Each request has a separate directory containing exactly named
`<logical_name>.conf`, a non-secret `record.json`, and an append-only
`submission.log`. Randomizing the surrounding
directory must not change the configuration basename used by WireGuard to select
an interface or service. Protected files reject unsafe links, ownership,
permissions and path replacement according to the platform implementation.
Unix production storage requires root ownership, safe ancestors and private leaf
modes. macOS additionally rejects extended ACLs, whose grants are independent of
mode bits. Windows applies a protected SYSTEM/Administrators descriptor at native
handle-relative creation, before writing bytes; conservative ancestor validation
still requires installation-path checks on a real Windows host. Test authority
exists only in test builds and explicitly protects an isolated temporary root.

Acquire the request lock before the target lock. The request lock serializes all
uses of an ID, including attempts to bind it to different targets. The target lock
is keyed by scope plus logical name, independently of caller and CLI home. Both
guards remain held by a new operation lease through its state transitions;
different homes or callers cannot bypass the same target lock.
Windows and macOS fold the ASCII logical name to lowercase for locking so service
or mapping-file case aliases cannot acquire independent locks; Linux preserves
case. The recorded name and configuration basename remain exactly as confirmed.

`begin` grants a new lease only when the request ID has never existed. An existing
ID with the identical request returns only its original record, in every phase.
An existing ID with a different request is rejected. An existing directory with a
missing, malformed or contradictory record is rejected and retained; it is not
deleted to make the ID reusable. This includes crashes during initial preparation.
Neither a recovered `prepared` record nor an old failed operation grants another
execution opportunity.

## Operation records and transitions

`OperationRecord` contains exactly `version: 1`, the complete `request`,
`snapshot_identity`, `phase`, `observation` and `failure`. The snapshot identity
binds the protected configuration copy, separately from the original source-file
identity in the request. The last two fields are required nullable fields;
unknown fields are rejected. The journal uses one canonical JSON encoding;
duplicate fields, missing nullable fields and noncanonical records are rejected.
Observations contain only the existing non-secret
`TargetObservation` data. Failure codes are limited to `cancelled`, `tool_failed`,
`observation_failed` and `target_changed`, never arbitrary tool output.

| Phase | Observation | Failure | Meaning |
| --- | --- | --- | --- |
| `prepared` | null | null | Protected configuration and initial record prepared; no submission recorded |
| `submitted` | null | null | Submission boundary recorded; actual system outcome may be unknown |
| `observed` | Required observation | null | Observation recorded; this is not itself a success verdict |
| `failed` | null | Required fixed code | Failure recorded; this does not establish rollback or absence of side effects |

The only transitions are `prepared -> submitted -> observed` or
`prepared -> submitted -> failed`. Each transition first publishes the
canonical projection and then appends one canonical JSON line to
`submission.log`. Every line contains a sequence number, the complete
non-secret `OperationRecord`, the previous event hash, and its own SHA-256
hash. The first line is `prepared` with an all-zero previous hash; sequence
gaps, phase rewrites, duplicate keys, extra blank lines, malformed hashes,
record/projection disagreement, and non-canonical JSON are rejected. The log
is opened with append-only semantics through a protected directory handle and
the file is synced before the containing directory is synced. A failed append
or projection leaves the request reserved and recovery fails closed rather
than repairing or replaying it.

Submission must publish and sync both the record and its journal event before a
platform broker can receive the execution request. The API reports the
combined durability result. In particular, Windows directory synchronization
reported as `Unsupported` is not a complete durable submission and must not
produce an execution permit, even though the protected file handles are
flushed. The journal is durable recovery evidence, not an execution permit; the platform
broker client and service perform the one-shot permit exchange and target execution.

A leftover `submitted` record and matching journal tail means the operation may
have changed the system.
The internal `ExecutionStore::submitted_records` query enumerates these records
after restart in stable request-id order, revalidating each canonical record and
protected configuration snapshot. It is read-only and returns no execution
permit. Recovery reads each record and separately observes the target; it never
resubmits the operation. The broker client persists submission before dispatching the request, and the
platform service independently verifies trusted tools, target identity, authorization
and runtime ownership. Storage serialization alone cannot establish these properties.

Dropping a lease releases its locks but deletes no configuration, record, or
journal lines.
Windows tunnel services may reopen their configuration after the worker exits or
the host restarts. The current slice has no public cleanup API. Any cleanup release must confirm
that no live service needs the configuration and retain a protected request tombstone
so cleanup cannot erase replay protection.

## Validation and remaining integration

### macOS broker observation and IPC boundary

The macOS slice has a Rust observer and a bounded Unix-socket client for the
protected WireGuard LaunchDaemon. It uses only the fixed service label
`dev.agentremote.wireguard.broker`, `/Library/LaunchDaemons/` plist path and
`/Library/PrivilegedHelperTools/` executable path, and the root-owned,
admin-group-readable (`gid 80`, mode `0660`) `/var/run/agent-remote-wireguard.sock`
endpoint. It rejects links,
non-regular files, non-root ownership, multiple links, and group/other-writable
modes before asking `/bin/launchctl print system/dev.agentremote.wireguard.broker`
for a bounded lifecycle snapshot. `/usr/bin/codesign --verify --strict` and its
fixed bundle identifier, community authority, team identifier, and optional
CDHash pin are checked separately. Missing compile-time identity pins,
malformed command output, a missing service, or any disagreement produces an
unavailable/invalid projection.

The Unix-socket protocol is newline-delimited canonical JSON with a strict
versioned envelope and a 128 KiB frame bound. The native broker must bind each
connection to `LOCAL_PEERCRED`, `LOCAL_PEERPID`, and the peer process start time
(`proc_pidinfo`); the caller digest includes all four values and is never taken
from an untrusted request. Execute requests transfer the reviewed config bytes
in base64 together with the exact plan, target, and config digests. The response
must carry a broker identity and a 30-second, single-use execution permit bound
to the caller and request; malformed, stale, mismatched, or replayed permits
are rejected before a desktop receipt is returned.

The client does not install a LaunchDaemon, call `launchctl bootstrap`, start or
stop a service, use `SMAppService`, or treat Device.app's
`AgentRemoteNetworkBroker.xpc` as this privileged endpoint. A missing endpoint
or unavailable native service remains fail-closed. `wireguard.bridge.status`
reports `unix_socket`/`kernel_peer` only after the fixed endpoint answers a
strict status probe; a status result never acts as an execution permit.

Focused tests must exercise immutable request binding, same-ID races across
different targets, same-target contention across homes/callers, replay of every
phase, malformed or orphaned records, exact protected configuration bytes and
basename, failed writes/synchronization, invalid transitions, and preservation on
drop. Tests also terminate a separate process after prepared/submitted persistence
without running Rust destructors and reopen its records. This demonstrates process
exit recovery, not disk power-loss durability. Failure injection at preparation and submission boundaries must demonstrate
that uncertainty never yields another execution opportunity. Tests use isolated
directories and do not create real tunnels or prompt for elevation.

The repository now includes protected service implementations and installation
materials for all three supported platforms. This contract does not imply
native platform validation has passed. Per-platform
ownership/ACL and synchronization evidence must be reported separately from
cross-compilation. The challenge/response message, authenticated IPC transport,
service installation materials, trusted tool/dependency provenance and fresh
target checks are implemented and unit-tested. Runtime ownership/generation, actual execution and recovery are implemented in the
broker paths; native Go confirmation/apply acceptance and target-host evidence remain
release gates for Windows, macOS and Linux. FreeBSD is not planned. See the desktop
[implementation status](../../agent-remote-desktop/docs/implementation-status.md)
for actual validation evidence and the
[read-only plan contract](desktop-wireguard-tunnel.md) for the available method.
