# Account configuration import protocol

The desktop methods use desktop-control version 1 and reject unknown request fields.
The Rust service is shared with `account import-config`. Source bytes remain in Rust
memory only; they never enter desktop JSON, SQLite, logs, or a private snapshot file.

## Local review

`Selection` has required `tool:"claude"`, `include_resume_history:bool`, and
`exclude_skills:bool`. Both options default to false in the UI/human command. History
adds projects, sessions, history.jsonl, file-history, plans, tasks and session-env.
Excluding skills omits only the account `.claude/skills` root before inspecting it;
plugin and project scopes retain their original semantics.

- `accounts.import.discover {selection}` returns `{source_home,selection,include,exclude}`.
  It reads local directory metadata, no file contents, credentials, or Server endpoints.
  Missing `.claude` is an empty selection. Source home is the actual OS-user home,
  independent of `AGENT_REMOTE_HOME`. Paths use `~/.claude/...`; exclusions also
  include `~/.claude.json`. Include/exclude arrays are sorted.
- `accounts.import.prepare {expected_context,account_id,selection,expected_source_home}`
  reads selected contents locally without credentials, initialization or network calls.
  Result: `{context,account_id,selection,source_home,include,exclude,manifest,total_bytes,
  source_fingerprint,intent_fingerprint,digest}`. Manifest entries are
  `{path,size,sha256,mode:384}` in path order. All hashes use `sha256:` plus 64 lowercase
  hex characters. The plan digest binds the context, source identities, selected roots,
  complete manifest and Server intent fingerprint. Empty manifests are valid previews
  but cannot be submitted.

All traversal is descriptor-relative and rejects links, Windows reparse points, hardlinked
regular files, special entries, unsafe names, changes/replacements, and source growth.
Limits: 64 selected roots, 2,048 traversed entries, depth 32, path 1,024 UTF-8 bytes,
1 MiB per file, 8 MiB total, and 256 KiB aggregate traversed path text. Capture is followed by a complete metadata/identity rewalk.
Preparation is a review snapshot, not upload authority.

## Explicit remote operations

`accounts.import.validate` accepts `{confirmed:true,expected_context,account_id,selection,
expected_source_home,expected_include}`. It rechecks the exact metadata selection without
reading content, then uses the existing Server dry-run endpoint. This writes a Server
audit record. Result fields are `{context,account_id,selection,source_home,include,exclude,
audit_written:true,accepted,rejected,warning_codes,operation_id}`. `audit_written:true`
only follows a verified successful response; an interrupted/ambiguous request remains
unknown. Server validation is optional and does not authorize a later import.

`accounts.import.apply` accepts `{confirmed:true,expected_context,account_id,selection,
expected_source_home,expected_digest,request_id}`. The caller retains a canonical nonzero
UUID before submission. Rust recaptures the entire source, compares the confirmed full
plan digest, locks device/login/configuration context, and durably reserves the original
request key in SQLite before one POST. It never retries a POST, reuses a key locally,
or substitutes a new key for an unknown result. Empty imports are rejected.
The complete plan is not an input: requests stay within the 64 KiB transport bound.

Apply result: `{context,account_id,request_id,digest,intent_fingerprint,task_id,phase:
"accepted",accepted:true,file_count,warning_codes,operation_id}`. The operation ID is the
outer desktop request ID, distinct from the retained import request UUID. Acceptance is
not task completion. Warnings are limited to `CONFIG_IMPORT_EXECUTABLE_REVIEW_REQUIRED`
and `CONFIG_IMPORT_CUSTOM_MARKDOWN_REVIEW_REQUIRED`; raw Server/Node prose is not forwarded.

## Recovery and retention

`accounts.import.pending {expected_home}` reads existing SQLite metadata without creating
or migrating it. Result `{home,items}` contains at most 256 records. A record has required
`context,account_id,request_id,digest,intent_fingerprint,task_id,phase`; task_id is explicitly
null until accepted. It contains no source path, manifest or content. The CLI journal is
the sole authoritative local intent store; Desktop does not create a second journal.
Original contexts survive Server/device switches.

`accounts.import.status {expected_context,account_id,request_id,expected_digest,
expected_task_id:null|string}` requires the original retained record and strict current
device context. It first queries the immutable receipt by caller key, independently
validates its complete intent manifest, then queries only its exact task. Result uses
the apply fields without operation_id; phase is pending/leased/running/succeeded/failed/
cancelled/expired. Counts are bounded by the accepted manifest. No raw error or files_written
paths are returned. Status does not write the local journal. A 404 cannot disprove an
in-flight original POST and never clears the record.

`accounts.import.forget` accepts the status fields plus `confirmed:true`. A known terminal
task requires fresh exact-key/status verification; pending/unknown/404 cannot be removed.
A record marked rejected after its only POST received an explicit 400/401/403/404/422 can
be forgotten locally without credentials or Server access. Other statuses, including
408/409/429, remain uncertain. The sole explicit 409 exception is structured
`SKILL_MANAGER_OWNS_PATH`: it marks the request rejected and returns the fixed code
`account_import_skills_managed`. The user explicitly forgets the rejection and changes
the selection before preparing again; the CLI never excludes skills automatically. Forget deletes only the exact unchanged local record.
Result `{context,account_id,request_id,digest,task_id:null|string,forgotten:true,operation_id}`.
At the journal limit, unresolved records are never evicted silently.

Local discovery/preparation/pending and forget advertise credential none; the remote
terminal branch of forget still requires device authorization. Validate/apply/status
require device credentials. Only validate/apply/forget advertise effect write.

The human command retains its selection flags. `--request-id UUID` selects an explicit
key; `--request-id UUID --status` recovers it after restart; `--request-id UUID --forget`
removes a settled receipt after confirmation (`--yes` is supported). A generated key
and recovery command are printed before submission.

## Server binding

New POST `/api/v1/tool-accounts/{account}/config-import-requests` and GET the same route
plus `/{request_id}` preserve the existing legacy endpoint. New imports are all-or-nothing.
The request supplies `schema_version:1,request_id,expected_intent_fingerprint,tool_type,
source:"local_cli",include,exclude,files,include_resume_history,dry_run:false`.

Intent fingerprint is SHA-256 of UTF-8 canonical JSON (sorted object keys, no whitespace,
non-ASCII retained) containing exactly schema_version, tool_account_id, tool_type, source,
include, exclude, include_resume_history, dry_run and files. Files here are sorted manifest
entries `{path,sha256,size,mode}`, not base64 content. Include/exclude order is preserved.
Server checks the expected fingerprint and atomically binds the caller key, authenticated
owner, exact intent and created task. Repeated conflicting intent is rejected. CLI verifies
the immutable receipt and fingerprint before trusting task acceptance or status.
