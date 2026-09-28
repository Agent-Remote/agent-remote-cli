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
