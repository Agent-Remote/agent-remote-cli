# Desktop control protocol, version 1

`agent-remote --desktop-control` is a standalone machine entry point. Select the
configuration through `AGENT_REMOTE_HOME`; existing CLI command names and flags
remain supported. Logout now reports incomplete local cleanup as a failure instead
of silently declaring success. `--desktop-schema` separately describes syntax. Neither discovery
interface grants authorization.

Start one process per operation, write one UTF-8 JSON object to stdin, then close
stdin. Input is limited to 64 KiB. By default the CLI emits one terminal JSONL
record and exits: 0 for a result, 1 for an error or failed transport. A caller
may set the optional boolean `stream_events` request field to `true` to opt in
to a bounded progress stream. In that mode the CLI flushes one `started`
progress record before running the operation; `login.device_code` may then emit
one `awaiting_approval` progress record. The stream always ends with one
terminal record. Each progress record is bounded to 4096 bytes plus newline.
Desktop recognizes the version 1 phase names `started`, `running`,
`awaiting_input`, `input_required`, `awaiting_confirmation`,
`confirmation_required`, `confirming`, `retrying`, `waiting`, `stage`, and
`awaiting_approval`; a progress phase never proves completion.
Terminal output is limited to 4 MiB including its newline. Callers must bound
waiting/output, validate IDs and versions, and reject unexpected event types,
phases, extra records, or inconsistent exit status. No human tables or raw
diagnostics enter this stream.

The `capabilities` result also carries the exact-session attachment bridge
declared by this CLI build. Desktop may use it only together with the
`sessions.attach` terminal capability; the remote Node and Server still verify
the session, device, SSH key and lease on the dedicated transfer channel.

```json
{"attachment_transfer":{"supported":true,"protocol_version":1,"max_bytes":268435456,"max_entries":32}}
```

```json
{"protocol_version":1,"request_id":"query-123","method":"context","params":{}}
```

The opt-in stream form adds `stream_events: true`; omitting it preserves the
single-record behavior for existing clients.

```json
{"protocol_version":1,"request_id":"query-123","method":"context","stream_events":true,"params":{}}
```

The first event for an opted-in request is flushed before operation execution:

```json
{"protocol_version":1,"request_id":"query-123","type":"progress","phase":"started","progress":{"operation":"context","stage":"started"}}
```

Request IDs contain 1–128 ASCII letters, digits, underscores or hyphens. Unknown
request fields/parameters are rejected. Unsupported versions/methods and invalid
input are rejected before reading configuration or credentials.

```json
{"protocol_version":1,"request_id":"query-123","type":"result","phase":"completed","result":{"home":"/selected/home","server_url":null,"active_device_id":null}}
```

```json
{"protocol_version":1,"request_id":"query-123","type":"error","phase":"failed","error":{"code":"permission_denied","retryable":false,"http_status":403}}
```

Unparseable/oversized requests or invalid IDs have `request_id: null`; valid IDs
are echoed for version, method, parameter and execution errors. Errors use fixed
codes and never include server messages, raw input or credentials.

The `terminal_operations` capability list also declares native managed-terminal
command paths that do not have a structured control method. Current dedicated
paths include `agent-remote node install`, the macOS-local `agent-remote device`
install/status/launch/diagnose paths, the selected Skills maintenance and
query paths (`skill check/info/status/list/retry` and `skill state
prune/reset/migrate/resolve/restore/export`), and the
`agent-remote ego-browser` family. The desktop must treat these declarations as
CLI implementation support only: it freezes the exact schema-derived argv,
obtains explicit user confirmation for mutations, and launches the reviewed
command in a managed PTY. The normal command remains responsible for
device/server authorization, its final exit status, and its original CLI
receipt. Desktop operation-center state is process-local until a durable
receipt journal is added.

For `skill state export`, the desktop review must include one explicit
`--output` destination. Desktop rejects NUL bytes, missing values and `..`
parent traversal in that reviewed value; the CLI remains responsible for
requiring an absent or empty real directory and a writable parent before
publishing the export bundle.

Skill state repair capabilities may include `effect`, `credential`,
`confirmation`, and a stable `workflow` label. In protocol version 1,
`skill_state_migrate`, `skill_state_resolve`, and `skill_state_restore` are
write workflows with `exact_request` confirmation; `skill_state_conflicts` is
read-only. These labels describe the reviewed PTY boundary and do not carry
branch inputs, conflict paths, file content, digests, or credentials. A
desktop may prefill only an exact conflict ID or safe account/Skill scope from
the metadata-only conflict query. The CLI schema and CLI itself remain the
authority for required revisions, resolution side/path, checkpoint ownership,
authorization, and the final receipt.

| Method | Parameters | Result | Credential |
| --- | --- | --- | --- |
| `capabilities` | `{}` | Protocol/CLI version, platform, implemented operations with effect and credential requirement | None |
| `context` | `{}` | Effective home, configured server URL/device ID | None |
| `accounts.list` | `{}` | `items`: account ID, tool, display name, status, region, timezone, locale, backend | Existing device credential |
| `credentials.list` | `{}` | `items`: profile ID, display name, status, GitHub CLI/SSH modes and timestamps; user ID, Git identity and unknown fields are omitted | Existing device credential |
| `credentials.create` | `confirmed: true`, exact context, display name, optional Git identity metadata and allow-listed GitHub CLI/SSH modes | Accepted profile receipt with metadata-only projection; unknown fields (including token/private key) are rejected before network access | Existing device credential |
| `credentials.bind` | `confirmed: true`, exact context, full tool-account ID and profile ID | Accepted binding receipt with metadata-only profile projection; no credential material crosses the boundary | Existing device credential |
| `credentials.unbind` | `confirmed: true`, exact context and full tool-account ID | Accepted unbinding receipt with no profile secret or identity fields | Existing device credential |
| `skills.list` | Optional `tool` or UUID `account_id` scope (mutually exclusive), `effective` and `include_system` booleans | Catalog generation, safe Skill summaries, and account-local status projections; content, source locator, tracking, revision metadata and credentials are omitted | Existing user session |
| `skills.state.conflicts` | Exact account UUID, `scope` (`item` with a Skill UUID or `account-directory`), bounded independent cursors and limit | Context-bound publication/migration conflict status metadata and cursors; paths, saved branch inputs, digests, source and resolution choices are omitted | Existing user session |
| `skills.state.info` | Exact checkpoint UUID | Metadata-only checkpoint status, retention and digest projection; expired checkpoints have no payload | Existing user session |
| `skills.state.diff` | Either an exact current account/scope selector or a checkpoint UUID, with bounded limit and checkpoint cursor | Metadata-only changed paths, entry kind, size, mode, content classification and digest; file contents, manifests and source paths are omitted | Existing user session |
| `skills.change` | `confirmed: true`, exact context, non-negative catalog generation, canonical Skill UUID, `action` (`enable`/`disable`) and sorted explicit scope | Context-bound public receipt with protocol operation ID, action, Skill ID, resulting generation and changed flag; content, source, tracking, node targets and credentials are omitted | Existing user session |
| `accounts.create` | `confirmed`, exact context, tool/name/region/timezone/locale/tags | Accepted account receipt; uncertain submission is not retried | Existing device credential |
| `accounts.status` | Exact context and full account ID | Separate account and binding observations | Existing device credential |
| `accounts.bind` / `accounts.verify` | `confirmed`, exact context and full account ID | Binding task acceptance; not agent login completion | Existing device credential |
| `accounts.disable` | `confirmed`, exact context and full account ID | Disabled account receipt; does not delete or stop sessions | Existing device credential |
| `accounts.default.get` | Exact `expected_home`, `tool` | Local default ID or null, tool and configuration context; no initialization | None |
| `accounts.default.set` | `confirmed: true`, exact `expected_context`, required nullable `expected_account_id`, `tool`, exact `account_id` | Local compare-and-set receipt; validates the account through the current device | Existing device credential |
| `accounts.default.clear` | Same confirmation/context/previous default and tool, without `account_id` | Local compare-and-set receipt; does not disable or delete the account | None |
| `sessions.list` | Optional `tool_type` and `statuses` array | `items`: session ID, tool, account/workspace/node IDs, paths, project key, status, backend, runtime resource, stop task and save operation IDs, timestamps | Existing device credential |
| `sessions.stop` | `confirmed: true`, schema 1, exact context, full session/node/backend binding, optional existing stop task, `reason: "user_requested"` | Caller-key stop receipt with frozen session/node/backend/runtime identity, task IDs/status, process stop and Skill-save observations | Existing device credential |
| `sessions.stop.request` / `sessions.stop.status` | Original `request_id`, exact context, optional `wait` and bounded `timeout` | GET-only observation of that original stop request; no new task or retry | Existing device credential |
| `sessions.delete` | `confirmed: true`, schema 1, exact context, sorted full `session_ids`, frozen `selection`, both digests, `reason: "user_requested"` | Caller-key receipt for exactly that collection, including frozen session context and per-session deletion status | Existing device credential |
| `sessions.delete.request` / `sessions.delete.status` | Original `request_id`, exact context, optional `wait` and bounded `timeout` | GET-only observation of the original fixed collection; no re-selection, expansion or retry | Existing device credential |
| `diagnostics.inspect` | Optional `online`, `deep_check`, `verify_versions` booleans, all default false | Home/platform, per-check state and suggestion, dependency/version inventory | None by default; reads stored credentials only for explicit deep checks |
| `dependencies.inspect` | Optional `verify_versions` boolean, default false | Dependency manifest and inventory using the same report schema | None |
| `status.inspect` | Optional `online` boolean, default false | Versioned status projection with the passive checks, dependency inventory, and separate server/device observations | None for local checks; stored device credential only when `online` and an active device are configured |
| `doctor.inspect` | Optional `online`, `deep_check`, `verify_versions` booleans, default true | Doctor observation projection using the same bounded checks as the human doctor command | None by default; explicit deep checks inspect stored credentials |
| `doctor.repair` | `confirmed: true`, exact `expected_home`; optional doctor flags | Local setup receipt followed by a fresh doctor observation; incomplete setup remains incomplete | None |
| `deps.inspect` | Optional `verify_versions` boolean, default true | Managed dependency manifest, path/status/license and bounded version observations | None |
| `deps.repair` | `confirmed: true`, exact `expected_home`; optional `verify_versions` | Dependency metadata repair receipt followed by a fresh dependency observation | None |
| `ssh.inspect` | Optional exact UUID `session_id` with matching `expected_server_url` and `expected_device_id` | Local SSH availability/version; optional exact-session authorization observation with metadata-only task projection | None for local check; stored device credential for the optional session observation |
| `setup.local` | `confirmed: true`, exact absolute `expected_home` | Local preparation receipt with eight ordered steps and `complete` | None |
| `wireguard.config.plan` | Exact `expected_home`, optional absolute `output` | Local context and destination identity snapshot; no writes | None |
| `wireguard.config.apply` | `confirmed: true`, complete unchanged `expected_plan` | Separate key, enrollment and file publication stages | Existing device credential |
| `wireguard.check` | Exact `expected_home`, optional absolute `config` | Private configuration validation and passive tool inventory | None |
| `wireguard.status` | Exact `expected_home` | Bounded, sanitized local WireGuard runtime observation; no elevation | None |
| `wireguard.tunnel.plan` | Exact `expected_home`, `action` (`up`/`down`), required nullable absolute `config` | Stable configuration/tool snapshots, native target observation, fixed blocking issues; no execution | None |
| `wireguard.tunnel.apply` | `confirmed: true`, exact `expected_home`, `action`, required nullable absolute `config`, and unchanged `expected_plan` returned by `wireguard.tunnel.plan` | Rechecks the read-only plan binding, reads validated configuration bytes at user authority, sends them through the fixed platform broker client, then reobserves target and returns an observed receipt | None; missing broker, identity mismatch, permit failure or protocol error fails closed |
| `login.password` | Confirmed server/account/device settings and transient password/MFA input | Secret-free operation ID, server, registered device ID, credential backend, lifetime | Password, optional MFA |
| `login.device_code` | Confirmed server/device settings and current context | One approval progress event, then the same login receipt | Browser approval; polling credential remains in CLI |
| `logout` | Confirmed current context and `revoke_remote` choice | Separate local cleanup and remote revocation outcomes | Existing user/device credentials, when available |

Account defaults share the normal CLI's per-home, per-tool selection. The exact
confirmation, compare-and-set semantics, local-only clear and uncertainty rules are
defined in the [account-default contract](desktop-account-defaults.md).

`capabilities` does not access state or the server. `context` reads existing
configuration without initializing state or asserting authentication. List queries
reuse typed `ApiClient` calls used by `account list`, `credentials list`, `skill list`
and `fclaude list`; account/credential lists use the device credential while
`skills.list` uses the user session. Credential refresh may update CLI secure storage. Explicit
projections prevent future server fields being automatically forwarded. The server
enforces authorization; advertised operations can still fail with HTTP 401/403.

`skills.state.conflicts` uses the same user session and independently queries
the publication and migration conflict endpoints. The selector, account UUID,
scope, page limits and cursors are validated before credentials are loaded. The
desktop-control projection is deliberately metadata-only; conflict resolution,
migration and restore remain separate write workflows.

`skills.state.info` and `skills.state.diff` use the same user session. `info`
reads one exact checkpoint UUID, while `diff` accepts either a current account
selector or an immutable checkpoint plus its opaque continuation cursor. The
diff response is bounded and metadata-only: it exposes changed portable paths,
entry kind, mode, size, content classification and SHA-256 summaries, while
file contents, manifests, source locators and credentials remain inside the
CLI/API boundary. Current-head queries are single observations; only checkpoint
diffs may continue with a cursor.

Each list result also contains `context: {server_url, active_device_id}` from
the selected configuration. The desktop compares it with the displayed context
and discards mismatched data, so a concurrent CLI environment switch cannot mix
lists from different servers/devices under one heading. A Skill scope cannot provide
both `tool` and `account_id`; malformed or unknown fields are rejected before
credentials are loaded.

Session filter values use the request ID alphabet/length, with at most 16 statuses.
An omitted tool filter requests all tools. Desktop attachment is currently offered
for running Claude sessions through an explicitly confirmed `fclaude attach` PTY.

`sessions.stop` generates a UUID v4 caller key inside the Rust CLI and journals only
the public session binding, intent digest and task identifiers. The Server checks the
digest against the current session under its lifecycle lock and retains the immutable
receipt after deletion. A lost POST response returns `SESSION_STOP_SUBMISSION_UNKNOWN`
with the original key; callers recover it through `sessions.stop.request` (or
`fclaude stop-status <request-id>`). This GET path never submits, resets or guesses a
latest session. Failed or unresolved tasks are not physical termination evidence;
the receipt is terminal only when `process_stopped` is true or deletion was guarded by
a settled stop.

`sessions.delete` evaluates a collection once and sends every selected canonical
session UUID in the request. The selection summary is limited to the tool, the
allowed terminal statuses and an optional project key; `selection_digest` covers
the schema version, sorted IDs and summary, while `intent_fingerprint` additionally
covers `reason`. The Server verifies the same snapshot under its lifecycle lock and
returns one context record per frozen session (account, workspace, project, node and
runtime backend). A collection mismatch or unsettled Skill retention is a rejection;
the CLI never broadens `--all` after submission. A lost POST response returns
`SESSION_DELETE_SUBMISSION_UNKNOWN` and the Rust journal keeps only the caller key,
context, IDs, digests and task identity. `sessions.delete.request` and
`fclaude delete-status` query that key only, including after the sessions have been
deleted.

Known errors: `invalid_request`, `unsupported_version`, `unsupported_method`,
`invalid_params`, `configuration_unavailable`, `authentication_required`,
`credential_unavailable`, `permission_denied`, `rate_limited`,
`server_unavailable`, `timeout`, `response_too_large`,
`confirmation_required`, `wireguard_plan_stale`, `wireguard_precondition_failed`, `wireguard_execution_failed`, `wireguard_outcome_unknown`, `skill_generation_conflict`, `skill_rejected`.

Query execution is bounded to 75 seconds after input. `retryable` is advice for a later
user-initiated query, not an automatic retry instruction. Canceling the process
stops local waiting; it does not stop remote Agents. The query methods do not
mutate remote business resources. Password login and logout are separate confirmed mutations,
described below. The opt-in stream currently exposes the generic `started`
event plus the explicitly allowlisted browser-login approval event; operation
stage events, remote cancellation and recoverable mutation journals are not yet
implemented.
Unsupported methods must not fall back to human-output parsing or blind retries.

Contract tests use isolated configuration and loopback HTTP fixtures to check
shared credentials, filters, authorization errors, projections, correlation and
rejection without state changes. They never use the developer's real credentials.

## Diagnostics and dependencies

`diagnostics.inspect` and `dependencies.inspect` are advertised as `effect: "read"`.
They do not run repair, install dependencies, initialize missing configuration or
migrate metadata. Opening the desktop diagnostics page sends only passive checks.
The page's **Run checks** action explicitly sets `deep_check: true` and the current
server-connectivity choice. **Run version checks** additionally sets `verify_versions: true`.
The server-connectivity checkbox starts enabled but navigation alone sends no HTTP.

### Command projections

The desktop command projections use the exact method names declared in
`capabilities.operations`:

* `status.inspect` is a read-only projection of local status. It includes the
  passive `checks`, `dependencies`, `manifest_source`, `home`, and `platform`
  fields, plus `remote.server` and `remote.device` observations. An online
  request may inspect the stored device credential to observe the active remote
  device; failure to load that credential is reported as `unknown` and never as
  an authenticated or disconnected claim.
* `doctor.inspect` runs the same bounded checks with `online`, `deep_check`,
  and `verify_versions` enabled by default. It never initializes missing local
  state. `doctor.repair` requires `confirmed: true` and an absolute
  `expected_home` equal to the selected `AGENT_REMOTE_HOME`; it invokes the
  existing typed `setup::initialize` service once and returns its complete
  `setup` receipt followed by a fresh observation. A partial setup is returned
  as `complete: false` and is not converted into success.
* `deps.inspect` reports the managed dependency inventory and performs bounded
  `--version` checks by default. `deps.repair` has the same exact-home and
  confirmation boundary and invokes only `setup::initialize_dependencies`;
  it does not initialize credentials, the database, or the network.
* `ssh.inspect` always performs a bounded local `ssh -V` check. A session
  observation requires a full UUID and both exact server/device context
  bindings. It uses the existing attach authorization path and returns only
  UUIDs, task status, and expiry; SSH commands, host names, credentials, and
  upstream diagnostic text are omitted. An unknown task status is returned as
  `unknown`, never as authorization success.

* `device.local.status` is a read-only local projection of the macOS Device
  application. It accepts only `expected_home`, rebinds that path against the
  active CLI configuration, and returns installation, pinned community
  signing, Gatekeeper, Network Broker XPC, GUI Executor XPC, and process
  state. It never returns certificates, tokens, or raw command output. Builds
  on Windows and Linux return `platform_unsupported`; Device install,
  uninstall, launch, and diagnose remain human CLI workflows.

All projections use `schema_version: 1` and an `operation` field in their
result object. Unknown request fields are rejected before filesystem or
credential access. Repair errors use fixed `confirmation_required`,
`context_mismatch`, `invalid_params`, or `repair_failed` codes; the protocol
never forwards local error strings or secret material.

```json
{"protocol_version":1,"request_id":"inspect-123","method":"diagnostics.inspect","params":{"online":true,"deep_check":true,"verify_versions":false}}
```

The report contains `home`, `platform`, the three requested booleans, `checks`,
`dependencies`, and `manifest_source` (`default`, `file`, or `unavailable`).
Each check contains `id`, `status`, nullable `path`, and a stable `suggestion` key.
Check statuses distinguish `present`, `missing`, `inaccessible`, `invalid`,
`not_checked`, `reachable`, and `unavailable`; no raw configuration or credential
contents appear in the report. The desktop validates the selected home and requested
probe flags before applying a result and translates labels/status/suggestions through
its catalog. Paths, component names, license information, and version output remain
original diagnostic data.

Passive checks inspect directory/file types, bounded configuration and manifest
contents, and executable permission bits. A missing manifest uses release defaults
without creating a file. Invalid/unreadable manifests are reported separately and
never replaced with a successful empty inventory. Manifest reads are limited to
256 KiB and 128 entries; configuration reads to 64 KiB. Non-regular files are rejected
without waiting for FIFO writers. Paths in dependency manifests must be normal relative
paths under the selected CLI home.

Explicit deep checks use the existing CLI credential stores and validate Broker
server/device binding; they do not return tokens, refresh credentials, or claim server
authorization. An OS credential store can request access. A denied/unavailable system
store is distinct from an absent fallback credential. Existing SQLite metadata is
opened read-only and its schema catalog is read; no database is created and no migration
runs. SQLite may use its normal WAL coordination files. A readable schema catalog is
not a full database integrity scan. Passive reports instead mark credentials
`not_checked` and SQLite presence as `presence_only`.

Credential inspection uses a bounded diagnostic reader without changing normal login
fallback behavior. Fallback files must be regular files of at most 64 KiB; FIFO and
oversized inputs report `inaccessible`. Unix credential tools have a 3-second bound,
64 KiB stdout and 4 KiB stderr limits, and private process groups cleaned up on timeout
or cancellation. Only macOS `security` exit 44, or Linux `secret-tool` exit 1 with empty
stdout and stderr, identifies a missing system credential. Other failures remain
inaccessible unless a readable, nonempty fallback credential exists. Neither stream
is returned in the diagnostic report. Windows checks the credential blob's size and
pointer before reading it. Presence still does not establish server authorization.

`online: true` calls the existing unauthenticated `ApiClient::healthz` implementation.
No request is sent when offline or when there is no configured server. Reachability
does not establish user/device authorization. Connection failures are structured states;
raw server error bodies never become UI messages.

Each dependency contains `name`, `path`, `status`, `required_version`, `license`,
`license_notice`, `version_status`, nullable `version_output`, and nullable
`version_exit_code`. Presence and successful version execution remain separate facts.
Version probes run only when explicitly requested, directly as `binary --version`
without a shell. They reject canonical paths outside the CLI home and skip installer
MSI artifacts. Each command is bounded to 3 seconds and 4 KiB for each output stream
(8 KiB total), with a 20-second total probe budget. Output follows the normal CLI's
trimmed stdout-first/stderr-fallback convention, and nonzero exit codes remain visible
as failed probes. No output is persisted by the desktop.

`version_status` is one of `not_checked`, `ok`, `failed`, `timeout`, `output_limit`,
`unsafe_path`, `unsupported`, `missing`, `budget_exhausted`, or `inaccessible`.
The query has the normal 75-second operation bound, including optional health checks.
On Unix each version command owns a process group. The desktop cancels diagnostic
operations with SIGTERM and allows two seconds for the CLI handler to drop the query
and kill those groups before a forced fallback. The handler also signals synchronous
credential inspection and allows up to one second for its process cleanup before
returning `canceled`. A contract test exercises real Go to
Rust cancellation and verifies both the version process and its child exit. An external
unconditional SIGKILL can bypass Unix cleanup and is not a graceful cancellation API.
On Windows each probe starts suspended, joins a kill-on-close Job Object, and only then
resumes its initial thread; closing the CLI also closes the job. The Windows helper has
been cross-compiled independently, but actual Windows process-tree behavior still needs
native runtime validation. The full CLI Windows cross-check on the macOS development
host is currently blocked by missing MSVC C headers for ring/SQLite dependencies.

These operations provide GUI diagnostics and explicit version inspection. They do not
run repair themselves. Local preparation is a separate confirmed operation below;
it does not claim to implement the complete human `init` or `doctor` workflow.

## Local preparation

`setup.local` is advertised with `effect: "write"`, `credential: "none"`, and
`confirmation: "exact_request"`. Review the selected CLI home before confirmation:

```json
{"protocol_version":1,"request_id":"setup-123","method":"setup.local","params":{"confirmed":true,"expected_home":"/selected/home"}}
```

Confirmation and an exact match with the effective absolute CLI home are required
before any filesystem write. Invalid parameters, missing confirmation, changed home,
or an unavailable home selection return `invalid_params`, `confirmation_required`,
`configuration_changed`, or `configuration_unavailable`. The operation does not read
configuration or credentials, contact the server, probe versions, launch subprocesses,
or call `Doctor::run`. A malformed `config.toml` therefore does not block preparation.
It creates local directories and prepares SQLite metadata and the dependency manifest;
it does not authenticate, enroll a device, download tools, or configure WireGuard.

The result contains `operation_id` equal to the request ID, the absolute `home`,
`complete`, and exactly eight `steps` in this order:

| Step ID | Path relative to home |
| --- | --- |
| `home` | Home itself |
| `bin` | `bin` |
| `dependencies` | `dependencies` |
| `secrets` | `secrets` |
| `wireguard` | `wireguard` |
| `ssh` | `ssh` |
| `database` | `state.sqlite3` |
| `manifest` | `dependencies/manifest.json` |

Each step contains `id`, absolute `path`, `status`, and `code`. `ready` and `applied`
use code `none`; `skipped` uses `dependency_failed`. Failed steps use `path_invalid`,
`state_unavailable`, `unsupported_state_version`, `manifest_invalid`, or `local_io`.
`complete` is true only when every step is `ready` or `applied`. A failed home skips
all remaining steps; a failed dependencies directory skips its manifest. Database and
manifest preparation otherwise proceed independently, preserving partial progress.
A partial receipt is a normal result with `complete: false` and process exit 0, not
a protocol error or a rollback claim. The desktop must inspect every step.

Existing valid metadata and configuration bytes are preserved. Corrupt/future SQLite
schemas and invalid/future manifests fail without replacement or schema downgrade.
Controlled home/subdirectories reject symlinks and special types; metadata files also
reject Unix hardlinks. System ancestor aliases such as macOS `/var` are supported.
New directories are mode 0700 and metadata files mode 0600 on Unix; Windows inherits
the parent ACL. This is not a guarantee against a hostile same-user process replacing
arbitrary ancestor directories while preparation runs.

CLI execution has a 120-second bound; desktop waiting is bounded to 150 seconds.
Timeout, interruption, or a lost receipt leaves the outcome unknown and must not be
automatically retried. The CLI reports `setup_outcome_unknown` with `retryable: false`
when it can still return an error; a client synthesizes the same outcome after losing
the process/receipt. Local work may have partially completed; inspect before requesting
another explicitly confirmed preparation.

Human `agent-remote init` and `doctor --fix` use this same metadata preparation before
continuing their normal interactive/diagnostic work. They now stop with failure when
metadata preparation is incomplete, including corrupt or future databases, instead
of attempting to continue or lower a schema version. `deps status --fix` shares only
the dependency preparation and does not initialize a database or configuration.

WireGuard configuration is a separate reviewed mutation, shared with ordinary
`wireguard config` and `init`. Its exact plan, stage combinations, strict credential
access and unknown-outcome rules are defined in the
[WireGuard configuration contract](desktop-wireguard.md).

Read-only configuration checks and runtime observations use separate
[`wireguard.check` and `wireguard.status` contracts](desktop-wireguard-inspection.md).
They do not authorize or implement tunnel start/stop.

## Password login and device registration

`login.password` is advertised with `effect: "write"` and
`confirmation: "exact_request"`. The GUI reviews the server URL, username, selected
home and device options before sending one request. Password and MFA values go only
through stdin, never command arguments, logs or desktop persistence.

```json
{
  "server_url": "https://agent.example.com",
  "username": "alice",
  "password": "<transient input>",
  "totp_code": null,
  "device_name": "Workstation",
  "ssh_public_key": "/selected/key.pub",
  "wireguard_public_key": null,
  "skip_device_registration": false,
  "confirmed": true,
  "expected_context": {"server_url": null, "active_device_id": null}
}
```

These are `params` inside the normal request envelope. Nullable fields may be
omitted. The two booleans and `expected_context` are required; the latter contains
the previously displayed CLI server/device, not the new destination. An absent
server/device is represented by null. Unknown fields, unconfirmed requests,
invalid URLs/public keys and stale context are rejected before authentication.
An empty SSH key path should be sent as null to use the CLI's default public key.
Only bounded single-line OpenSSH public key records are accepted, never private
key files. The validated SSH public-key contents are captured before authentication
and carried through publication; changing the source file while awaiting browser
approval cannot change the enrolled key. Ordinary CLI login/setup use the same
preparation path. WireGuard input is a base64-encoded 32-byte public key.

Login reuses `auth::login::finalize` with normal CLI login, device credential
storage, user session exchange and local device metadata. Existing device IDs are
reused only on the same server. User-only login does not register a device; an
existing same-server selection is preserved for CLI compatibility, while a device
from another server is cleared. Configuration is atomically replaced after
credential publication and only if the original context is still current.
Login publication, logout, device refresh, revoke and rotation share a process
lock; the existing per-server user credential lock remains in use.

Success includes `operation_id` equal to `request_id`, `server_url`, nullable
`registered_device_id`, `credential_backend` (`system` or `file`) and `expires_in`.
No access/refresh token is returned. Password login has a 120-second execution
deadline. The desktop allows 150 seconds for the process and never retries it.

Additional errors: `confirmation_required`, `configuration_changed`,
`ssh_public_key_required`, `login_rejected`, `registration_rejected`,
`registration_outcome_unknown`, `login_outcome_unknown`,
`login_persistence_incomplete`. All use `retryable: false`. A timeout, lost process
or uncertain server response does not prove rollback. A persistence failure can
mean that a device and/or credentials exist even though the final configuration
was not published.

When device registration is enabled, the CLI creates a UUID caller key and saves
only the public registration intent in its local SQLite state before the first
POST. The Server binds that key to the complete intent and stores a short-lived,
encrypted copy of the original device-token receipt. A transport failure queries
`GET /api/v1/devices/registration-requests/{request_id}` using that exact key; a
new process reuses the retained key and intent. The Server returns the original
receipt for an identical key and rejects a changed intent with
`DEVICE_REGISTRATION_KEY_REUSED`. The CLI never infers success from the current
device list, rotates a token to recover a lost response, or submits a new key
while an unresolved key is retained. The local key is removed only after all
credential, device-state and configuration publication succeeds. The recovery
window is bounded by the original token lifetime; revoked, expired or damaged
receipts remain `registration_outcome_unknown`.

## Browser and device-code login

`login.device_code` is advertised with `effect: "write"`, `credential: "browser"`
and `confirmation: "exact_request"`. Its parameters are the password method's
`server_url`, `device_name`, `ssh_public_key`, `wireguard_public_key`,
`skip_device_registration`, `confirmed` and `expected_context`; username, password
and MFA fields are not accepted. Review the selected home, destination server and
registration choices before sending the request. The same preflight and publication
checks apply, and the context is checked again before each completion poll.

The CLI starts the existing server device-code flow. On a valid start receipt it
flushes exactly one `awaiting_approval` event before polling (in addition to the
generic `started` event when `stream_events` was requested):

```json
{"protocol_version":1,"request_id":"login-123","type":"progress","phase":"awaiting_approval","progress":{"user_code":"ABCD-EFGH","verification_url":"https://agent.example.com/cli?code=ABCD-EFGH","expires_in":600,"interval":5}}
```

This event is only allowed for this method, at most once and before the terminal
record. There are no heartbeat or repeated pending events. A failure before approval
metadata is available produces only the terminal error. The CLI never opens a browser
itself. The GUI shows the destination and opens it only on explicit user action;
it may copy the user code. The `device_code` used to poll, issued access/refresh
tokens, and server error messages never enter the event stream or desktop state.

The user code is 1–64 ASCII letters, digits or hyphens. The URL is bounded to
2048 bytes, permits HTTP/HTTPS without user information or a fragment, and accepts
only optional `code=<user_code>` query values matching the current server contract.
URLs containing the internal polling credential are rejected, including nested
percent-encoded copies that a browser or web application could decode.
API and web origins may differ. The server lifetime must be 1–1800 seconds and
the interval 1–60 seconds. Invalid metadata produces `login_outcome_unknown`
without forwarding it or polling. Time spent obtaining the start receipt counts
toward its lifetime; progress `expires_in` reports the remaining lifetime rounded
up to the next second. The GUI anchors its countdown to receiving that event, even
if the window is hidden or the view is temporarily inactive.

Only the server's existing explicit pending response permits another poll of the
same code at its interval. Start, uncertain completion and registration are never
replayed. A confirmed server expiry or reaching the local deadline between requests
returns `login_expired`. Rejection returns `login_rejected`. Transport loss or an
in-flight completion reaching the deadline returns `login_outcome_unknown`, because
the server may already have consumed the code and issued a token. These errors and
all login errors have `retryable: false`.

After approval the CLI uses the same credential publication and optional device
registration as password login. The final result has the identical login receipt;
it never repeats approval metadata. Publication has a 120-second timeout and the
entire request has a 1950-second timeout; the desktop allows 1980 seconds for process
startup and exit. Closing/killing the local process cancels waiting, not browser
approval or a possible registration. A lost terminal receipt is an unknown outcome,
not proof of rollback. Registration recovery uses the retained registration key as
described above. The CLI generates a caller-owned UUID for completion and stores
only public metadata (`server_url`, UUID, user code, interval and expiry) in local
state. The server stores the access-token receipt encrypted and never stores the
plaintext device code or token. If completion transport is lost, the CLI performs
one exact-key `GET /api/v1/auth/cli/completions/{uuid}`. A completed receipt is
replayed verbatim; a missing, expired, revoked, malformed or otherwise unknown
receipt remains `login_outcome_unknown`. A second process can use the saved UUID
for that same GET, but it cannot poll, generate a replacement code or infer a
result from device listings.

Loopback contract tests exercise pending/approval, user-only and device registration,
expiry/rejection, disconnected completion, explicit cancellation, context changes,
untrusted progress metadata, secret non-disclosure and single-attempt publication.


## Logout

`logout` is advertised with `effect: "write"`, `credential: "stored"` and
`confirmation: "exact_request"`. Parameters are:

```json
{
  "confirmed": true,
  "revoke_remote": true,
  "expected_context": {
    "server_url": "https://agent.example.com",
    "active_device_id": "device-id"
  }
}
```

Both booleans and `expected_context` are required. The scope is the current server's
user credential and selected device credential in the chosen CLI home. The GUI
reviews that home, server, device and revocation choice before submission. The
context is compared before work and again under the shared login/device lock;
a stale selection returns `configuration_changed` without clearing credentials.
Configuration publication also compares the original snapshot before writing.

The operation shares `auth::logout::execute` with ordinary `agent-remote logout`.
`revoke_remote: false` corresponds to `--no-revoke-remote`: it performs local
cleanup without token refresh, user-session exchange or server calls. The default
GUI choice is true, matching the CLI default. Remote revocation attempts are not
retried. Local cleanup is still attempted if revocation fails. The server address
is retained; the active device selection is cleared only after device credential
cleanup is confirmed, so failed cleanup retains a target for explicit repair. Other servers' credentials,
SSH/WireGuard private keys, workspaces and Agent history are outside this scope.
Logout does not send a stop-session request; an existing connection may lose its
authorization. It does not revoke every device or every user session on the server.

CLI home selection isolates configuration and file-fallback storage, not the OS
credential namespace: existing system-store keys are scoped by server/device and
can be shared by multiple CLI homes. Logout may therefore affect those other
homes using the same keys. Current publication locks are scoped to one home;
cross-home keychain concurrency is not serialized by this protocol. An explicitly
selected `AGENT_REMOTE_SECRET_BACKEND=file` only cleans that file backend.

A terminal result means the operation produced a receipt, **not** that every step
succeeded. `operation_id` must equal the request ID. The result contains the
original `server_url` and `active_device_id`, plus:

- `user` and `device`: `{local_removed: boolean, remote: string}`.
- `broker_removed`, `refresh_metadata_removed`, `config_cleared`: independent booleans.
- `local_complete`: true only when all local fields are true. True removal includes
  a credential already absent from the selected store. System-store failures are
  not hidden by successful file-fallback cleanup.

Remote values are `confirmed` (server acknowledged revocation), `unconfirmed`
(including renewal/transport/rejection failures), `not_requested`, or `not_present`
(no local credential available to submit). `not_present` does not assert that no
remote sessions exist. Inspect server security settings for unconfirmed revocation;
local deletion may have removed the only credential available to retry it.

Execution is bounded to 120 seconds; the desktop process deadline is 150 seconds.
Timeout returns `logout_outcome_unknown`, with `retryable: false`. Transport loss,
local cancellation or a malformed receipt also leaves the outcome unknown. The GUI
must not claim rollback, silently retry, or infer successful revocation from local
cleanup. There is currently no durable logout journal or recovery of a lost receipt.
Normal human CLI logout preserves the success message when local cleanup completes,
warns on unconfirmed revocation, and exits with an error on incomplete local cleanup.

Tunnel planning and execution are specified in [desktop-wireguard-tunnel.md](desktop-wireguard-tunnel.md).
`wireguard.tunnel.plan` requires no credential and performs no tunnel mutation.
`wireguard.tunnel.apply` is advertised as an exact confirmed write: it regenerates
and compares the complete plan, rejects unmet issues, sends the validated
configuration bytes and digests through the fixed platform broker client, and
only returns after a second target observation confirms present/absent. A changed
plan returns `wireguard_plan_stale`; broker failure and lost post-observation
return fixed failure/unknown codes. There is no sudo, runas or helper fallback
for this desktop-control endpoint.

## Remote accounts and native binding terminal

`accounts.create/status/bind/verify/disable` are structured account operations;
see [their exact confirmation, projection, and unknown-outcome contract](desktop-accounts.md).
The native `account attach` flow is separately advertised through
`terminal_operations: [{"method":"accounts.binding.attach","protocol_version":1}]`.
It is not a stdio `operations` method. See the [typed, generation-bound terminal contract](desktop-account-binding.md).

Administrator runtime recovery uses six `accounts.runtime_recovery.*` methods, an independent
user context, and the same Rust service/public caller-key registry as the human CLI. Device
credentials never supply this authority; machine reads do not refresh user credentials.
See [reviewed runtime recovery](desktop-runtime-recovery.md) for exact original projections,
nullable historical-key queries, immutable receipts, and explicitly confirmed local forget.
