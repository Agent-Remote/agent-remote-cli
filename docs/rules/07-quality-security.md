# 07 Quality And Security

CI, pre-commit, and pre-push enforce shell parsing, rustfmt, Clippy with warnings denied, all Cargo tests, and whitespace checks. Ubuntu CI also enforces at least 45% line coverage. Behavior changes require focused tests; platform-specific changes require the relevant installer or contract coverage.

- Never commit or log access tokens, passwords, tool credentials, cookies, SSH private keys, or WireGuard private keys.
- Treat API responses, local config, current directory contents, archives, and external command output as untrusted.
- Bound imported file sizes and validate archive paths before extraction.
- Redact secrets from error context and diagnostic output.
- Do not weaken filesystem permissions or credential-store behavior for convenience.
- Do not bypass certificate validation or execute shell text assembled from server data.

Reject changes that silently alter public commands, persist remote login state locally, or send private keys to the server.
