# 10 Remote Operations

- The API client owns authentication headers, versioned endpoints, typed payloads, timeouts, and public errors.
- Clients display server-selected runtime backends but do not silently override scheduling policy.
- SSH attach uses server authorization and node forced commands; do not enable arbitrary remote command injection or forwarding.
- Workspace sync preserves managed ignore rules and waits for server-side workspace preparation.
  `sync ensure` re-confirms the idempotent control-plane workspace and sync relationship, replacing
  stale local SQLite mappings and their old managed Mutagen session when remote resources changed.
- External dependency invocation uses resolved argument vectors, checks exit status, and never interpolates server text into a shell command.
- Interrupted sessions are not attachable; replacement behavior must not replay commands.
- Session deletion is limited by the control plane to `stopped` and `interrupted` sessions. The CLI may delete one resolved session ID or request collection cleanup, but it must not broaden the allowed states locally.

Keep retry and polling bounded and cancellable. Contract changes must update server schemas, CLI types, relevant node behavior, contract tests, and user documentation together.
