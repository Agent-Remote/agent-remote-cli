# agent-remote-cli

<p align="center"><img src="assets/agent-remote-icon.svg" alt="Agent Remote icon" width="80" height="80"></p>

<p align="center">
  <a href="https://github.com/Agent-Remote/agent-remote-cli/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Agent-Remote/agent-remote-cli/actions/workflows/ci.yml/badge.svg"></a>
  <a href="https://codecov.io/gh/Agent-Remote/agent-remote-cli"><img alt="Codecov" src="https://codecov.io/gh/Agent-Remote/agent-remote-cli/graph/badge.svg"></a>
  <a href="https://github.com/Agent-Remote/agent-remote-cli/stargazers"><img alt="GitHub Stars" src="https://img.shields.io/github/stars/Agent-Remote/agent-remote-cli?style=flat&logo=github"></a>
  <img alt="Rust 2021" src="https://img.shields.io/badge/Rust-2021-000000?logo=rust&logoColor=white">
  <a href="LICENSE"><img alt="License: GPL-3.0" src="https://img.shields.io/github/license/Agent-Remote/agent-remote-cli"></a>
</p>

English | [中文](README.zh-CN.md)

`agent-remote-cli` is the Rust local client for Agent Remote. It owns local configuration, credentials, device enrollment, WireGuard, SSH, Mutagen, remote session operations and the structured control contracts consumed by desktop clients.

## Binaries

- `agent-remote`: configuration, login, device, account, workspace, network, diagnostics, Skills and session administration.
- `fclaude`: Claude session creation, listing, attachment, stop/delete and port forwarding.
- `agent-remote-wireguard`: user-side WireGuard helper.
- `agent-remote-wireguard-broker`: protected host broker for approved tunnel operations.
- `agent-remote-ssh`, `agent-remote-scp`: managed SSH and file transfer helpers.

The current package version is recorded in `Cargo.toml`. Keep command names, flags, exit codes and machine-readable output compatible unless a coordinated change updates the Server, Node and desktop contracts.

## Command families

```sh
agent-remote init
agent-remote login
agent-remote status
agent-remote doctor
agent-remote sync status
agent-remote sync ensure
agent-remote wireguard check
agent-remote account list
agent-remote device status
agent-remote skill list
fclaude list
fclaude new
fclaude attach <session-id>
fclaude forward <remote-port>
```

Use `--help` for the exact current schema. `agent-remote` owns shared state; `fclaude` owns the remote Claude launcher and session-facing commands. Passwords, tokens, MFA codes and private keys use controlled input or the platform credential store and are never placed in argv or desktop state.

## Shared state and operation safety

The selected `AGENT_REMOTE_HOME` (or `--home`) is the authority for configuration, local SQLite state and credential references. The CLI persists caller-generated request keys and bounded public receipts for operations that can outlive a process. After a transport failure, status queries use the original key and exact context; mutations are never replayed by guessing the latest object or generating a replacement key.

Session, account, configuration-import, runtime-recovery, sync, port-forward and device operations bind their request to the relevant user, server, device, workspace, node and generation fields. Unknown outcomes remain observable and require an explicit query or recovery action.

## Desktop integration

The desktop uses two versioned CLI interfaces:

- `--desktop-schema` describes command nodes, parameters, client platforms and terminal capabilities.
- `--desktop-control` exchanges JSONL requests, bounded progress events and one final result/error for structured read and mutation operations.

Sensitive flows such as login, device-code approval, credentials, account import and WireGuard execution remain inside the CLI. Desktop receives only the approved public projection. Commands without a dedicated structured page use a reviewed managed terminal workflow; schema discovery alone is not a claim that the remote operation succeeded.

## Remote operations

The CLI coordinates WireGuard, SSH, Mutagen and the server/node APIs. A remote Claude session is selected by exact session identity and attaches through the authorized Node gateway. Workspace synchronization distinguishes Server state, local Mutagen state, conflicts and Agent state. Port forwarding uses an owner-scoped caller key, a bounded local listener and a short-lived server connection authorization.

The WireGuard execution path is fail-closed: configuration bytes and plan/target digests are reviewed before an approved platform broker can perform `up` or `down`. The client does not fall back to sudo, runas, PATH helpers or an unverified process.

## Development

Rust 2021 and the toolchain pinned by the repository are required. Run the full gate from the repository root:

```sh
bash -n scripts/*.sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
scripts/run-quality-checks.sh
```

Use temporary homes, loopback fixtures and disposable server/node data. Never run acceptance against a production credential or persist a real private key in test output.

## Install and package

Install the latest published CLI on Unix-like hosts:

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

Pin a version or choose the home and link directory explicitly:

```sh
VERSION=VERSION_TO_INSTALL
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version "$VERSION" --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

On Windows, download `scripts/install.ps1` and run it in PowerShell. Use
`-InstallPrerequisites` only when the OpenSSH Client or the packaged WireGuard
dependency is missing; it may require elevation. To build a release archive:

```sh
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
```

Install a downloaded release archive with its bundled script:

```sh
./install.sh
```

On Windows, the equivalent installer invocation is:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallPrerequisites
```

The archive contains the CLI, managed helpers, dependency manifest, checksums
and third-party notices. Installation never replaces a production home without
the user's explicit choice.

## Release

`prepare-release.sh` and the package workflows build the CLI and managed helpers. Release artifacts must include their exact version, source commit, dependency notices and checksums. Native broker acceptance is separate from contract tests and must run on the target host. Do not publish a release until coordinated Server, Node and desktop gates are green.

## Documentation

Current contracts are grouped under `docs/`:

- `desktop-control.md`, `desktop-schema.md`: structured desktop APIs.
- `desktop-accounts.md`, `desktop-account-binding.md`, `desktop-account-import.md`, `desktop-account-defaults.md`: account flows.
- `desktop-session-attach.md`, `desktop-sync.md`, `desktop-port-forward.md`: session and workspace flows.
- `desktop-wireguard*.md`, `linux-wireguard-broker.md`, `macos-wireguard-broker.md`: network and broker flows.
- `desktop-runtime-recovery.md`, `desktop-mutagen-environment.md`: recovery and shared service state.
- `exact-session-attachment-transfer.md`, `verified-session-sync.md`: attachment and synchronization boundaries.

These documents describe current contracts. Tests and code take precedence if a document is stale.

## Script entry points

The repository keeps the following installation, build, packaging and host
acceptance entry points:

```sh
# Build managed Mutagen and WireGuard helper inputs.
scripts/build-managed-tools.sh
# Prepare versioned release metadata and run release checks.
scripts/prepare-release.sh
# Build Unix release archives.
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
# Install the Linux/macOS broker and run native broker acceptance.
scripts/install-macos-wireguard-broker.sh
# Install the Linux broker when running the protected system service.
scripts/install-linux-wireguard-broker.sh
scripts/native-wireguard-broker-acceptance.sh
# Install repository hooks for local development.
scripts/install-githooks.sh
# Repository quality and focused test gates.
scripts/run-static-checks.sh
scripts/run-tests.sh
scripts/run-quality-checks.sh
```

On Windows, use the PowerShell packaging and broker acceptance entry points:

```powershell
./scripts/package-release.ps1 -Version $version
./scripts/native-wireguard-broker-acceptance.ps1
```

`install.sh` and `install.ps1` are the end-user installers documented above;
the other scripts are build or host verification tools and do not publish a
release by themselves.

## License

GPL-3.0-only. See `LICENSE` and `THIRD_PARTY_NOTICES.md`.
