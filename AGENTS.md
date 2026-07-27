# AGENTS.md

This document is the primary instruction set for AI agents and automated coding tools working in this repository. Repository-local rules take precedence over general assumptions.

## Task-To-Documentation Mapping

Before making changes, identify the task domain and read the matching rule document.

| Task Domain | Primary Reference |
| --- | --- |
| Project purpose and repository boundary | `docs/rules/01-project-overview.md` |
| Runtime architecture and module boundaries | `docs/rules/02-architecture.md` |
| Rust toolchain and dependencies | `docs/rules/03-tech-stack.md` |
| Rust style, errors, typing, and tests | `docs/rules/04-code-style.md` |
| Comments, user-visible output, and documentation | `docs/rules/05-comments-output.md` |
| Local commands and developer workflow | `docs/rules/06-commands.md` |
| Quality and security gates | `docs/rules/07-quality-security.md` |
| Git, commits, hooks, and pull requests | `docs/rules/08-collaboration.md` |
| Local state, credentials, and private keys | `docs/rules/09-local-state-secrets.md` |
| Control-plane, SSH, WireGuard, and sync behavior | `docs/rules/10-remote-operations.md` |

## Mandatory Gates

- `bash -n`, `cargo fmt --check`, Clippy with warnings denied, tests, and `git diff --check` must pass before commit.
- Command behavior and user-visible output changes must include focused contract or unit tests.
- API contract changes must remain compatible with the server or update affected repositories together.
- Commit messages must follow Conventional Commits.
- Access tokens, tool credentials, cookies, private keys, and remote login state must never be committed or logged.

## Implementation Rules

- Keep network calls in `api.rs`, credential handling in `secrets.rs` and `auth.rs`, and SQLite access in `local_state.rs`.
- Keep `agent-remote` focused on local device management; tool launchers remain separate binaries.
- Preserve stable command names, flags, exit behavior, and script-consumable output unless a breaking change is intentional and documented.
- Use platform credential storage first and owner-only file fallback only when required.
- Never send WireGuard or SSH private keys to the control plane.
- Prefer narrow modules and explicit data types over speculative abstractions.

## Hook Setup

Install repository hooks after cloning:

```sh
scripts/install-githooks.sh
```

Run the full local quality gate:

```sh
scripts/run-quality-checks.sh
```

## Conflict Resolution

If existing code conflicts with these rules:

1. Stop before editing the conflicting area.
2. Identify the file and rule that disagree.
3. Ask for the intended current standard.
