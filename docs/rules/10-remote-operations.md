# 10 Remote Operations

- The API client owns authentication headers, versioned endpoints, typed payloads, timeouts, and public errors.
- Clients display server-selected runtime backends but do not silently override scheduling policy.
- SSH attach uses server authorization and node forced commands; do not enable arbitrary remote command injection or forwarding.
- Workspace sync preserves managed ignore rules and waits for server-side workspace preparation.
  `sync ensure` re-confirms the idempotent control-plane workspace and sync relationship.
  Obsolete mappings require exact Server 404 evidence and a separate reviewed local recovery:
  terminate only the verified old Mutagen identifier, then compare-and-remove exact SQLite rows.
  Retain an existing Server workspace mapping. Missing tools, stopped daemons, permission failures
  and transport failures cannot prove session absence. Creating or reusing a replacement target
  requires fresh review and confirmation after recovery; never silently replace an old relationship.
- Global Mutagen environment repair has separate namespace-wide preview and confirmation. Include
  synchronization and forwarding sessions, even when only persisted stopped-daemon metadata is
  available; do not guess an empty inventory. Revalidate tools, namespace/home/marker and full
  session configuration/pause state. Preserve partial/unknown receipts and never replay a project
  operation automatically after daemon recovery. No Server credential is needed for this local action.
- External dependency invocation uses resolved argument vectors, checks exit status, and never interpolates server text into a shell command.
- Interrupted sessions are not attachable; replacement behavior must not replay commands.
- The library's [verified synchronization flush](../verified-session-sync.md) operates only
  on an initialized, reviewed relationship and already running bound namespace. It cannot
  ensure, repair, resume or create a session. Flush completion is an instantaneous observation;
  cancellation or failed revalidation never proves rollback or grants automatic retry.
- Desktop native session attach binds full session UUID, expected Server and device before
  credential refresh, then submits one exact authorization and polls only its original task
  record. The Node verifies the expected device against the forced SSH key identity; incompatible
  gateways fail closed. See [exact session attach](../desktop-session-attach.md). Ordinary CLI
  attachment without the paired expectations retains its compatibility behavior.
- Session deletion is limited by the control plane to `stopped`, `interrupted`, and `failed` sessions. The CLI may delete one resolved session ID or request collection cleanup, but it must not broaden the allowed states locally.
- `agent-remote device launch` verifies the fixed signed APP bundle and an unexpired shared device
  credential before launching it. Candidate listing, claim/rebind, local permission checks, and
  application approval remain inside the Device APP and control plane, not the CLI.

Keep retry and polling bounded and cancellable. Contract changes must update server schemas, CLI types, relevant node behavior, contract tests, and user documentation together.

## Skill Operations

Follow the [Skill architecture rules](02-architecture.md#skill-manager) and shared contract.
Managed stop reports the original snapshot operation; stopped, capture_pending, persisted and
published remain distinct. A timeout does not cancel saving or prove rollback. Takeover retries
require the exact committed reservation and bounded cancellation-aware waiting.
Deployment retry selects only original ended transient failures and journals the exact attempt set.
Node exports use the fixed SSH forced command, stdin-only grant, no forwarding or arbitrary SSH
configuration, online reauthorization and complete atomic destination verification. Initial/final
scans are bounded; an authorized progressing transfer has no independent fifteen-minute ceiling.
Over-entry recovery is separately negotiated and cannot masquerade as a manifest-v1 checkpoint.
Backend recovery and source repair keep exact original task/request/action identity; a failed status
query or uncertain submission cannot imply rejection. Preserve the original recovery command.
