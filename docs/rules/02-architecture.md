# 02 Architecture

## Module Layout

```text
src/api.rs          Control-plane HTTP client and payload types
src/auth.rs         Authentication token lifecycle
src/cli.rs          Clap command and argument definitions
src/config.rs       Paths and user configuration
src/local_state.rs  SQLite metadata
src/secrets.rs      Credential-store and secure-file access
src/dependencies.rs Managed external tools
src/device.rs       Signed macOS device app install, status, and diagnostics
src/ssh.rs          SSH command construction
src/wireguard.rs    WireGuard helper orchestration
src/workspace.rs    Local workspace identity
src/terminal.rs     Stable terminal presentation
src/bin/            Auxiliary and tool-specific binaries
```

Network calls belong in `api.rs`; persistent metadata belongs in `local_state.rs`; secrets belong behind `secrets.rs`. Keep platform-specific behavior isolated and testable. Entry points orchestrate modules but should not duplicate their domain logic.

The reviewed root skill-manager design adds `skills/` for local source acquisition, canonical
manifests and command orchestration, with Clap definitions under `cli` and all control-plane
requests behind `api`. Skills are installed into the authenticated remote user's library; local
directories are source snapshots, not an alternative local installation target. Tool/account rules,
revisions, operation state and authorization remain authoritative on the Server.

The device installer accepts an explicit local `.app` bundle or ZIP release archive. It bounds and
validates archive contents before extracting exactly one fixed-name app bundle into a private
temporary directory, then verifies its fixed bundle ID, embedded XPC services, complete code
signature, and the signing identity pinned into the CLI. The Apple profile additionally requires
Gatekeeper acceptance. The community-local-trust profile pins the project's self-signed
leaf-certificate fingerprint, verifies it on the app and both XPC bundles, then removes quarantine
from the already verified staging bundle before atomic installation. It must not execute an endpoint
or installer path from project data or an unverified API response.

Skill source acquisition is split into `skills/discovery.rs` (bounded scanning and explicit
selection), `skills/metadata.rs` (display metadata), `skills/source_fs.rs` (capability-relative reads
and file identity checks), and `skills/snapshot.rs` (complete private packages). A selected skill
is fully copied before an upload plan is requested. Uploads read only staged digest-addressed
objects, never live source files. Source symlinks are represented in manifests, not followed during
packing; metadata resolution uses the complete manifest. These blocking filesystem operations must
run on a blocking worker when called by asynchronous CLI orchestration.

`account import-config --exclude-skills` removes the account-level `~/.claude/skills` discovery
root before preview, confirmation or file collection and includes it in the request's existing
exclusion list. It does not exclude plugin-provided skills or project history. The option does not
change the Server API schema or itself establish managed directory ownership; Server planning and
Node execution must independently enforce managed ownership when that workflow is connected.

Library target receipts preserve the optional immutable configuration `plan_digest` in JSON output.
Missing historical digests remain absent; the CLI never reconstructs them from current rules.
This receipt field does not authorize runtime deployment or enable the future `skill retry` command.

Skill library queries (`skill list`, `skill info`, `skill status`) use typed versioned responses in
`api::skills`; HTTP, user-token headers and bounded body parsing remain inside `api`. The command
layer reads the existing user credential lifecycle, never substitutes a device token, and renders
one stable skill envelope for JSON mode. Querying rules does not prove model loading or runtime
readiness. Status waiting preserves the original operation ID, uses a monotonic bounded deadline,
stops on terminal failure/conflict/supersession and reports pending timeout with exit 3. It never
cancels or resubmits the remote operation. Local/auth/transport failures use bounded CLI messages.

Skill rule/remove/rollback commands resolve names to exact source IDs and capture the current
library generation before confirmation. Before any POST, SQLite records a secret-free exact request,
random idempotency key, logical intent digest, Server URL and authenticated `/users/me` UUID. A unique
pending intent prevents concurrent invocations from replacing uncertain input. Recovery queries the
original key before replaying identical input; it never refreshes the generation or silently replans.
Received operation IDs persist separately from target readiness. Dry runs perform reads only and
create no mutation journal. Mutation confirmation is required once unless --yes is explicit;
noninteractive missing confirmation fails with exit 2. Waiting does not change the stored plan.

SQLite skill-journal calls run on blocking workers and close their connections before HTTP awaits.
`skill status --last` locates the latest Server/user-bound local ID or key and only queries it.
Unknown acceptance preserves its key and explicit unknown commitment; authentication/protocol failures
are never labeled automatically retryable.

Skill details resolve the original user-supplied name on the Server before the CLI stores a stable
ID, so library/local name collisions cannot be hidden by client-side library filtering. Explicit
account lists include separate local entries, and local rule commands require that exact account.
The CLI rejects local pin/unpin/revision inheritance before confirmation or journal creation;
local inherit restores enabled=true. Existing journals continue to replay their exact saved IDs.

Skill installation stages complete local packages before confirmation or upload. Content HTTP methods
live in `api::skill_content`, verify returned upload/tree/file identities and exact manifests, and use
a separate bounded 64 MiB content-envelope ceiling; ordinary metadata queries keep their 1 MiB cap.
Only staged digest objects supply upload bytes. File reads/digest verification run on blocking workers.
Every selected package must complete before one atomic multi-item installation request can be sent.
Content persistence does not imply configuration acceptance. Before installation POST, the existing
Server/user-bound command journal retains its exact generation, items and key; uncertain acceptance
recovers the original receipt before replay and never reacquires changed source bytes for that request.

Git skill acquisition separates source/ref parsing, local credential access and Git transport. Source
URLs are credential-free HTTPS repositories (or GitHub owner/repo shorthand); refs resolve explicitly
to a complete commit before packaging. `api::skill_git` owns remote Git calls; `auth::git` obtains
existing native credential-helper material without logging it. Transport ignores project/global Git
execution configuration, disables redirects and non-HTTPS protocols, and supplies authentication only
through child-process environment configuration for the exact repository URL.

Acquisition uses a private bare repository and raw tree/blob objects, never checkout, archive export
substitution, hooks or smudge filters. Metadata/process output, time and expanded content are bounded.
Submodule entries and unresolved LFS pointers are reported rather than silently treated as complete
content. Source provenance keeps branch/tag/commit separate from the immutable full commit. Local
source behavior and already recorded installation recovery remain independent of fresh Git fetching.

Git object parsing/discovery uses `skills::git_objects` and `skills::git_catalog`. Complete manifests
are built from raw modes/links without host filesystem extraction; hashing and durable object writes
run on blocking workers. Metadata, expanded bytes and process output have hard bounds. Git fetch disk
usage has a sampled 512 MiB/100000-entry guard plus a final check, not a hard aggregate network bound.
Unix process groups and Windows kill-on-close jobs accompany per-process and source deadlines.
`--ref` is optional in journal intents to retain old local digest compatibility; pending legacy local
owner/repo intents are checked before the new Git shorthand path can acquire anything.

Check/update reuse immutable source acquisition and the existing Server update endpoint. Checks never
upload, journal or mutate configuration. Fixed Git tracking and local sources are reported separately;
only tracked branches are fetched automatically. Update plans retain the exact installation ID,
source identity, captured content, expected generation, explicit tracking switch and stage flag.
Local --from is a fresh explicit snapshot, preserving the installed opaque local identity so another
device can update it. Git updates must retain the installed name and repository-relative subpath.

Single updates share exact-request acceptance/recovery. Batch updates remain independent per-skill
transactions, collect one result envelope, continue after individual failures and retain original keys
for uncertain results. Pending automatic Git updates are recovered before fresh batch acquisition,
including items no longer present in the current listing. Each fresh batch item reads its own current
generation; no request is silently rebased after submission. Retained matching revisions already
prove Server content availability, so candidate activation can reuse them without another upload.

State history uses separate typed checkpoint and pending-finalization pages under `api::skill_state`.
Queries preserve all revision/epoch identities and expose independent continuation cursors; pending
Node content is never presented as a restorable Server checkpoint. Diff continuation can select the
returned immutable checkpoint ID rather than silently moving to a new current head.

State exports are portable bundles: `checkpoint.json`, the exact `manifest.json`, and verified file
bytes in `objects/<sha256>`. Original names, permissions, empty directories and link targets remain
lossless manifest metadata; no source-controlled filesystem path or link is instantiated locally.
Export checks account/source/scope against the selected checkpoint, refuses cross-item dependencies
for item scope, and publishes from private sibling staging only after every object is verified.
The destination must be absent or empty. Export uses the complete authorized manifest byte count,
not a fixed 10 GiB runtime-admission ceiling. Canonical validation checks signed size overflow and
the 100000-entry bound; transfers retain bounded buffers and deadlines. File transfer remains in `api`; filesystem
verification, staging and publication run on blocking workers. Export does not initialize branches,
or change heads. The separate frozen snapshot export below handles Node-only pending bytes.

State reset/restore previews use Server /state/current and dry-run /state/commands, retaining the
complete generation, directory head/epoch, target source/revision/installation/state identities and
per-branch data changes. Item names resolve before confirmation and the retained selector uses the
stable source UUID. Actual state requests share the owner/origin-bound metadata journal but have a
separate typed acceptance path: only original-key OPERATION_NOT_FOUND permits identical replay.
State receipts are atomic published results, not library deployment operations. Generic status/--last
routes these to their typed receipt endpoints; update --all skips validated pending state commands.
Read/preview cancellation submits nothing. Submission cancellation retains unknown acceptance and the
original key. No-wait/timeout options never turn an HTTP timeout into proof that state was unchanged.

Conflict reads preserve separate publication/migration pages and cursor protocols. Name selection
resolves once to a stable source. Conflict diff first identifies the domain, falling back only after
explicit publication CONFLICT_NOT_FOUND; it fetches saved inputs and keeps live migration drift
separate. Typed validation binds source/revision/reference identities and migration cursor digests
to the original attempt. Metadata-only queries never save choices or initialize/recompute branches.

Custom resolution inputs use `skills::state_snapshot`, sharing only the bounded copier and no-follow
filesystem primitives with package acquisition. State capture includes every `.git` entry and treats
LFS-looking bytes as ordinary data. Limits use state quotas (1 GiB item, 10 GiB directory, 100000
entries), with no package file cap. A file input contributes exactly one `content` entry. Capture
preserves ordinary relative links and fails explicitly for absolute links whose runtime dependency
identity cannot be derived from a local directory. It never infers a skill name or unpacks an export
bundle. Blocking capture is cooperatively cancellable and returns no partial tree.

`api::skill_state` keeps publication and migration content routes explicitly scoped by conflict ID.
Metadata previews contain only the captured manifest, never file bytes or a mutation key; their
candidate completeness never implies verified content or publication permission. Upload leases,
streamed staged objects and completed trees retain exact manifest/digest identity. State bodies use
64 KiB chunks with backpressure and retain private staging for the duration of transfer. Upload
completion is storage acceptance, not a saved resolution choice or a published checkpoint. Command
confirmation, journal recovery and actual resolution submission must remain separate orchestration.

Explicit state migration is orchestrated in `skill_commands/state_migrations/`, with typed HTTP and
receipt validation in `api/skill_state/migration_command*`. Selection fixes both revisions before one
confirmation; the exact original request and candidate are journaled before submission. Incremental
receipts have their own key and ID endpoints and remain distinct from preparation and resolution.

State prune uses `api::skill_state::prune*` for bounded typed preview, exact command, immutable
receipt/detail queries and independent physical deletion progress. The command traverses every
signed page and validates the unchanged summary, continuous offsets, total and terminal credential
before one confirmation. Complete disclosure is staged in a private temporary metadata spool,
never inserted into the 4 MiB request journal. Blocking spool I/O runs off the async runtime;
interruption while reading/displaying cannot submit. A spool limit failure rejects the entire
preview, never truncates the confirmed loss list. The temporary spool is capped at 2 GiB.

`skill_commands/state_prune/` owns selection, review, original-request acceptance and rendering.
Pending `state_prune` intent recovery precedes all new preview requests. The journal holds the exact
small command plus reviewed summary/count; acceptance validates the original confirmation hash,
key, summary and disclosure count. Only definite original-key OPERATION_NOT_FOUND permits identical
replay. A pending dry-run queries acceptance only and, if not found, explicitly shows the saved
summary as an unverified original request, without claiming to reconstruct its missing disclosure.
Generic status/--last routes prune to its own original receipt, complete persisted disclosure and
separate current deletion progress. Accepted logical cleanup is terminal; waiting flags never imply
that the disk worker has finished. Batch package update skips validated prune journals.

Prune display uses an output-only detached thread with cooperative row cancellation. The async caller
tracks active display: interruption or deadline during streaming exits without competing for the same
output lock or appending a second envelope. Before display, ordinary structured errors remain intact.
Blocked output cannot acquire journal/submission authority or keep runtime shutdown waiting.

`skill status --storage` uses a separate typed read-only storage endpoint; it is mutually exclusive
with operation identity/last/wait and never edits a command journal. Skill/checkpoint info renders
optional Server retention diagnostics and user-wide quota/deletion observations. Missing optional
fields from an older Server are unknown, not zero or infinite. Current storage observations never
replace or extend immutable acceptance receipts. SQL remains Server-authoritative; HTTP remains in
`api`, and output labels distinguish cumulative deletion evidence from Node disk availability.

Effective queries add `api::skill_effective` for bounded original-session pages and optional account
state/system metadata. Session views use saved selections and never current rules. Session pagination
is explicit and preserves the original cursor; reads never journal, prepare or dispatch. Missing
older account/system diagnostics remain absent. CLI validation binds returned identities to the
requested session/account and rejects inconsistent saved revisions or false loading claims.

Configuration add/rule commands separate cancellable preparation (authentication, recovery lookup,
source selection/capture, review and content upload) from acceptance. Preparation cannot call the
configuration POST or create a command journal; cancellation exits 130 and never claims to cancel an
older pending operation. The completed preparation hands an owned submission to the existing exact-key
acceptance/recovery path, whose interrupted POST continues to report unknown commitment. Interactive
selection and confirmation use bounded, detached input/output-only threads; those threads have no
HTTP, journal or submission authority. Updates share this confirmation primitive.
The configuration command retains one scoped Ctrl-C listener from startup through acceptance and
waiting. A signal received between phase futures remains observable, including during SQLite journal
work. Submission checks cancellation before polling the POST; after a verified response, interruption
preserves that response's commitment. Other command families keep their existing cancellation scopes.
Source catalog and configuration dry-run display use detached output-only workers. A command-scoped
result-start marker prevents cancellation from appending another JSON envelope while a pipe is
blocked; output can be partial and exits 130. Review/selection warnings remain stderr-only and do not
mark a result envelope as started. Human configuration/update cancellation emits no additional result,
so it cannot contend with an unfinished prompt/warning writer. Verified receipts remain in the journal.

Final configuration acceptance and single/batch update rendering also use owned output-only workers.
The retained signal bounds their final output, including interruption diagnostics, to a 250 ms drain
allowance after cancellation; blocked stdout/stderr cannot hold command shutdown. No second envelope
is appended. Verified receipt persistence precedes rendering, and status --last can retrieve that
original operation after partial output. Read-only check rendering keeps its existing behavior.

State reset/restore, migrate and resolve now share `interruption::scope` from command entry. A single
retained signal covers authenticated reads, review, bounded confirmation, content preparation,
journaling, acceptance, receipt persistence and final output. Their acceptance paths poll cancellation
before submitting, and verified results are journaled before rendering even when cancellation arrives
during that local write. Unknown acceptance still uses the original immutable request/key.

`skill_commands/output.rs` owns detached output-only workers shared by configuration and these state
commands. Review workers own only display metadata and write stderr; they cannot submit or journal.
Final result workers set the irreversible result-start marker and have a 250 ms drain allowance after
interruption. Human cancellation emits no additional output; JSON reports planning interruption only
before result streaming begins. State resolution retains its cooperative filesystem capture guard.
State list/info/diff/conflicts/export now use this retained signal and output boundary as well,
including pre-result failures. They retain read-only HTTP behavior. Export checks cancellation before
publication and observes any already-started atomic publication to completion; cancelling display
cannot discard a published bundle. Prune and general skill queries/status retain separate scopes.

Frozen snapshot export (`--snapshot`, explicit account-directory scope) uses
`api::skill_node_export` for user-token authorization and a bounded SSH stream. It reads local
device/key metadata without loading a device token. The original snapshot binding must match
every response and stream header; current account rules never reconstruct it. SSH arguments
belong in `ssh.rs`; authorization grants travel only through stdin and stay out of debug output,
journals and bundle metadata. Complete-directory exports preserve cross-skill links without
instantiating any original paths. Item checkpoint export retains its existing workflow.
The receiver stages on blocking workers and verifies exact manifest digest, every distinct
object, explicit completion, EOF and successful SSH exit before publication. Cancellation kills
the SSH child and drops unpublished staging. No export acknowledges upload or deletes Node state.

Node export can also receive a verified stopped-work stream when the Helper independently proves
that the original tree is quiescent and no frozen capture exists. This does not create a durable
Node checkpoint. Initial scan and final rescan waits each have an independent 15-minute budget;
partial object/frame reads reset a 30-second progress timeout. Live grant continuation permits
longer complete transfers under the same original token and binding. Publication requirements and
bundle format are unchanged.

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

`runtime_recovery_commands::failure` retains validated caller identities before local preparation
and renders recovery errors separately from device admission. Only explicit 4xx submission errors
mean this invocation was rejected; transport, 5xx and malformed success responses leave acceptance
unknown. Status errors never establish absence of a previous request. Diagnostics use fixed codes
and messages, and never incorporate remote bodies or credential/configuration error chains.

Ordinary session/account API calls may reach Skill retention/admission guards. The shared HTTP error
parser accepts both the existing API error envelope and a validated version-1 failed Skill envelope,
preserving its stable code and bounded message. It never renders Skill details or a malformed raw
body, and cannot interpret committed/successful payloads as rejection. This lets launcher commands
report `STATE_PENDING` while retaining their existing nonzero exit behavior.


Explicit `recovery_version:1` export negotiation now enables the separate bounded-metadata
stopped-work recovery format above 100,000 entries. Manifest v1 remains capped. Source retains
original sealed authority and complete scan comparisons; files stream before their verified hash
trailer to avoid silent prehash stalls. Gateway retains exact live authorization and complete EOF
verification; CLI uses private hash-addressed disk metadata, validates whole topology/content and
requires footer/EOF/SSH success before publication. Old gateways reject unsupported negotiation.
See the negotiated recovery wire contract in the Node `docs/skill-node-export.md`; actual complete
recovery acceptance remains tracked separately, with no production capability advertisement.
