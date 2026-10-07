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
src/app/             `agent-remote` command orchestration by workflow

tests/unit/src/     Unit-test modules mirroring `src/`
tests/              Contract, integration, installer, and fixture tests
```

Network calls belong in `api.rs`; persistent metadata belongs in `local_state.rs`; secrets belong behind `secrets.rs`. Keep platform-specific behavior isolated and testable. Entry points orchestrate modules but should not duplicate their domain logic.

The binary entry point in `src/main.rs` only initializes Tokio and delegates to `app::run_entry`;
command dispatch and orchestration live under `src/app/` (`entry.rs`, `device_node.rs`,
`account.rs`, `sync.rs`, and `support.rs`). This keeps process startup separate from
workflow logic while preserving the existing command module boundaries. Unit-test implementations
are kept under `tests/unit/src/` and included with path attributes from their original parent module;
this separates test code physically without widening production visibility or changing command behavior.

The device installer accepts an explicit local `.app` bundle or ZIP release archive. It bounds and
validates archive contents before extracting exactly one fixed-name app bundle into a private
temporary directory, then verifies its fixed bundle ID, embedded XPC services, complete code
signature, and the signing identity pinned into the CLI. The Apple profile additionally requires
Gatekeeper acceptance. The community-local-trust profile pins the project's self-signed
leaf-certificate fingerprint, verifies it on the app and both XPC bundles, then removes quarantine
from the already verified staging bundle before atomic installation. It must not execute an endpoint
or installer path from project data or an unverified API response.

## Skill Manager

Read the [shared Skill contract](https://github.com/Agent-Remote/agent-remote/blob/main/docs/skill-manager-wire-v1.md) before changing Skill behavior.

- `skills/` owns bounded source discovery, canonical manifests and private source/state snapshots;
  `skill_commands/` owns review, acceptance/recovery and output; `api/` owns typed bounded HTTP.
- Capture complete packages before review. Read raw Git objects without hooks, checkout or filters;
  credentials stay local. State capture preserves `.git` and treats LFS-looking bytes as ordinary data.
- User login authorizes library/state commands; device credentials cannot substitute for it.
  Account-local identities and scopes remain distinct. `import-config --exclude-skills` excludes the
  owned account discovery root before preview or collection, while preserving other selection rules.
- Queries/dry-runs never submit state/configuration changes or create mutation journals. Metadata-only
  conflict preview uploads no bytes and is not verified publication authority.
- Mutations journal exact Server/user-bound input and key before POST. Recover pending original intent
  before fresh selection, never silently rebase a confirmed generation or retry unknown writes with a new key.
- Configuration committed, target readiness, persisted state and model loading remain separate output facts.
  Cancellation is retained through preparation, acceptance and bounded output; blocked stdout must not hang shutdown.
- Export verifies complete original identity, manifest and bytes into private staging before atomic publication;
  no source-controlled paths/links are instantiated. Node recovery requires live renewable original authority.
- Backend recovery uses caller-retained original task/request IDs and distinct immutable v1/v2/v3 actions;
  default and verify-source remain passive. Unknown acceptance retains the same key and status instruction.
