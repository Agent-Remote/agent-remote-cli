# agent-remote-cli Agent Guidelines

This repository contains the Rust local CLI for agent-remote.

## Scope

- Keep `agent-remote` focused on local configuration, identity, device state, diagnostics, and managed dependency orchestration.
- Keep tool launchers such as `fclaude` separate from the generic management command.
- Do not store access tokens, tool account credentials, browser cookies, or remote tool login state in SQLite.
- Prefer platform credential storage for secrets; use the file fallback only when the platform store is unavailable or explicitly requested.
- Treat WireGuard, Mutagen, SSH, and tool launch behavior as replaceable implementation modules behind narrow interfaces.

## Rust Style

- Keep modules small and domain-oriented.
- Return `anyhow::Result` at command boundaries; keep typed structs for API and local state boundaries.
- Avoid panics in command handlers.
- Keep network calls in `api.rs` and local persistence in `local_state.rs`.
- Keep output stable enough for later scripting, but do not expose undocumented machine contracts without tests.

## Checks

Run before committing:

```sh
scripts/run-quality-checks.sh
```
