# Desktop workspace sync protocol v1

`sync.status` receives `expected_context` (required home/server_url/active_device_id)
and a canonical absolute `local_path`. It reads existing shared CLI mappings, fetches
the exact remote sync, and inspects Mutagen without creating a workspace or restarting
its daemon. The reply contains `context`, `target`, `sync` (nullable), and `mutagen`.

`target` contains `local_path`, `project_key`, required nullable `workspace_id`,
`sync_session_id`, and `fingerprint`. The fingerprint is SHA-256 over fixed JSON fields:
sync ID, workspace ID, node ID, local path, remote path, sync mode, Git inclusion,
exclusions, Mutagen name, and remote endpoint. Status strings are intentionally excluded.
Mutations refetch and compare the complete reviewed target. A changed directory,
context, mapping, or remote destination requires a new review.

`sync.ensure`, `sync.pause`, `sync.resume`, `sync.resolve`, and `sync.reset` receive
`confirmed:true`, `expected_context`, `expected_target`, and `dry_run` (all required).
Dry run retains historical CLI semantics: **Server and SQLite changes still occur**;
only local Mutagen mutations are skipped. It is not a read-only preview.

Receipts contain `operation_id`, `context`, `method`, original `target`, `result_target`,
`dry_run`, `outcome` (`completed`, `partial`, or `unknown`), ordered `stages`, nullable
`sync`, nullable `mutagen`, and nullable fixed `error_code`. Stage names are `workspace`,
`server`, `mutagen`, and `persist`; names may repeat. Stage state is `completed`, `skipped`,
`failed`, or `unknown`. A completed stage only describes that operation, not transfer
completion. Unknown or partially completed operations are never replayed automatically.

The sync projection contains id, workspace_id, nullable node_id, local_path, remote_path,
status, conflict_status, sync_mode, sync_git, exclude, nullable mutagen_session_id and
nullable remote_endpoint. Mutagen contains `state` (`missing`, `session_missing`,
`available`, `unavailable`) and `conflicts` (`unknown`, `detected`, `none_observed`),
plus required nullable `paused`, `status`, and `conflict_count`.
No raw tool output, conflict file content, credentials, or server diagnostic text is emitted.

Ensure creates/reconfirms the workspace and sync relationship, persists verified mappings,
waits at most 30 seconds for preparation, then ensures the managed local session. Existing
reviewed mappings are not silently replaced when Server returns a different resource.
Pause changes Mutagen before Server; resume changes Server before Mutagen. Resolve flushes
Mutagen and checks for an observed completed cycle with both endpoints scanned/connected,
no reported conflicts and no errors before asking Server to clear its conflict marker.
It does not select a winning file version or promise that no future conflict will arise.
Reset changes Server then terminates/recreates
the managed Mutagen relationship; rebuilding the baseline may rediscover conflicts or
restore previously deleted files. Files are not explicitly deleted by the reset command.

Context locks prevent cooperating local configuration switches during execution. SQLite
writes compare the reviewed snapshot in one transaction; no SQLite transaction is held
across HTTP or external process waits. These guards are not a distributed transaction:
concurrent remote changes and process termination can leave partial or unknown results.
Use fresh status to inspect the exact original target before deciding the next action.

Conditional action POSTs add `expected_target` to the existing optional-note body. It
contains the full immutable sync destination listed in the fingerprint. Updated Server
versions lock and compare the sync/node target before applying the action; legacy callers
may omit this additive field. A mismatch is a 409 rejection. Clients additionally validate
returned identity and destination before publishing shared metadata. Before mutating an existing sync, the CLI requires `target_precondition_version:1`
in the GET reply. Conditional action replies additionally require
`target_precondition_checked:true`. An older Server is rejected before the action POST;
a missing check receipt after submission is an unknown outcome.

Human `sync status` now uses the same structured observations: it does not refresh SQLite
records or restart/migrate the Mutagen daemon. `--fail-on-conflict` fails when conflicts are
unknown as well as when they are detected. Obsolete remote mappings use the confirmed recovery workflow below; the confirmed workflow
does not silently replace a reviewed resource.

Mutagen inspection preserves the existing daemon namespace and never automatically starts,
stops, or migrates it. Mutation preparation refuses an existing daemon state directory whose
managed SSH environment marker does not match this CLI installation, including when that
daemon is stopped; it does not stop unrelated project
syncs. Use the separately confirmed [global environment recovery](desktop-mutagen-environment.md)
to review all affected sync and forwarding sessions before repairing the managed environment.

Queries pin the existing Mutagen data directory explicitly, including on Windows to avoid
upstream default-path hidden-attribute writes. No local command or file names from conflicts
are exposed. Transient clients have time/output limits and descendant cleanup; explicitly
started daemons persist independently. The native v0.18.1 probe uses an isolated temporary
daemon. With `AGENT_REMOTE_TEST_MUTAGEN` and `AGENT_REMOTE_TEST_MUTAGEN_AGENT` pointing to
the official CLI and agent binaries, it additionally exercises create/flush, bidirectional
file transfer, pause/resume, reset, and preservation of conflicting file contents. Its SSH
shim executes only the local test agent and never opens an SSH connection. This is real
Mutagen protocol/file behavior, not a real Node authentication or file-transfer acceptance test.

Ensure treats `active`, historical `healthy`, and `conflicted` resources as already prepared.
It preserves the returned status and conflict marker instead of waiting for them to become
`active` or implicitly resolving files. This preparation fact is separate from Mutagen's
current connection, completed-cycle, and conflict observations.


## Obsolete mapping recovery

`sync.recovery.preview` accepts required `expected_context` and canonical `local_path`.
It captures the complete existing SQLite workspace/sync snapshot, then reads the exact sync ID.
Only its HTTP 404 can establish a missing sync; 401/403, transport failure, 5xx and malformed
success never authorize cleanup. It next reads the exact workspace: a matching same-device,
same-project workspace is retained; its 404 permits removal of that obsolete workspace mapping.
A live remote sync returns `sync_recovery_not_required` without touching local state.

The plan contains `context`, `target` (old IDs with `fingerprint:null`), `mapping`,
`mapping_fingerprint` (SHA-256 of serialized complete mapping), `server_state`
(`sync_not_found` or `workspace_not_found`), `mutagen`, `recoverable` and nullable `error_code`.
`mapping.workspace` projects all saved id/server_url/project_key/local_path/display_name/remote_path
fields; `mapping.sync` projects all saved id/server_url/workspace_id/node_id/status/conflict_status/
mutagen_session_id/remote_endpoint fields. Null fields remain explicit. This is saved metadata,
not a fabricated current Server resource. A missing sync row or incomplete old destination is
blocked because it cannot identify an old local session safely.

Recovery Mutagen observations contain `state` (`available`, `session_missing`, `missing`,
`unavailable`, `blocked`), `recoverable`, nullable `error_code`, nullable
`namespace_fingerprint`, and nullable `target`. A present target contains identifier, name,
local_path, remote_path, endpoint and configuration_fingerprint. It freezes the actual immutable
session configuration without exposing raw configuration/environment, conflict contents or errors.
The namespace fingerprint binds the canonical Mutagen data directory and its full native directory
identity, so replacing a directory at the same path invalidates confirmation. The configuration
fingerprint includes every public-model field except documented runtime state; unknown future
configuration fields are retained in the digest.
Only a successful bounded query of the running daemon proves `session_missing`; a missing binary
or stopped/unreachable daemon is not absence. Preview does not autostart, migrate or stop a daemon.

`sync.recovery.apply` requires `confirmed:true`, `expected_context`, and the complete
`expected_plan`. It revalidates context, complete SQLite snapshot, exact remote absence, namespace,
actual Mutagen identifier and configuration. It terminates only that exact verified local identifier
(or observes exact absence), verifies absence, then compare-and-removes the old sync row. It removes
the workspace row only when that workspace also returned 404. It never deletes project files or
remote resources. Multiple historical sync rows are ambiguous and blocked before local actions.

The independent receipt contains operation_id, context, method (`sync.recovery.apply`), original
plan, result_target, outcome, ordered stages, nullable mutagen and nullable error_code. Its stages
are `server` (absence observation), `mutagen` and `persist`; completed is local recovery completion,
not a new remote relationship. Non-atomic failure retains the original plan and partial/unknown
receipt. An uncertain termination is not retried automatically, and metadata remains until fresh
observation and a new confirmation. A concurrent SQLite change is retained after failed CAS even
if the original local session has already been terminated. Reusing the original completed plan
fails because its old mapping no longer exists. A SQLite write/commit error is conservatively
unknown; it is not reported as proof of rollback. External Mutagen clients do not participate in
the local configuration/SQLite locks, so remote observation, daemon termination and SQLite commit
are not a distributed transaction. Recovery has no dry-run mutation mode.

After success, refresh status and review a separate `sync.ensure` action to create or reuse the
replacement. Human `sync ensure` encountering an obsolete sync offers the same preview and an
explicit cleanup prompt, including when `--yes` is set; `--yes` covers ordinary creation only.
The recovery invocation stops after cleanup and asks the user to run ensure again, so it cannot
silently create a new target. With `--dry-run`, it displays the obsolete target and stops without
performing recovery. The original public command names and flags remain available.
