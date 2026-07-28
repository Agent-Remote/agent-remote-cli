# agent-remote-cli

<p align="center"><img src="assets/agent-remote-icon.svg" alt="Agent Remote icon" width="80" height="80"></p>

English | [中文](README.zh-CN.md)

Rust CLI for agent-remote local device management.

The package provides the `agent-remote` command. Tool-specific launchers such as `fclaude` are intentionally separate so regular `claude` usage remains untouched.

## Commands

```sh
agent-remote init
agent-remote login --server-url https://agent-remote.example.com --username alice
agent-remote status
agent-remote doctor --fix
agent-remote deps status
agent-remote wireguard config
agent-remote wireguard check
agent-remote sync ensure
agent-remote sync status
agent-remote account create --tool claude --name "Claude US" --region US --timezone America/Los_Angeles --tag us
agent-remote account list
agent-remote account bind <account-id>
agent-remote account verify <account-id>
agent-remote account status <account-id>
agent-remote ssh check --session-id <session-id>
agent-remote attach <session-id> --print-only
agent-remote logout [--no-revoke-remote]
```

Every command and nested command provides `--help`. Runtime output supports
`--color auto|always|never`; `auto` also honors `NO_COLOR` and `TERM=dumb`.
Errors, warnings, successful actions, section headings, details, and status
tables use consistent terminal styling.

`agent-remote init` is the recommended first-run path. It guides the user through:

- selecting the control-plane API URL
- logging in with an existing agent-remote user account
- registering the local device and SSH public key
- checking managed external dependencies
- fetching the default WireGuard configuration when available

The CLI initialization flow does not create users. Administrators create regular users from the admin console after the server has been bootstrapped.

`agent-remote login` stores tokens in the platform credential store when available:

- macOS: Keychain through the `security` command
- Linux: Secret Service through `secret-tool`
- Windows: Windows Credential Manager through the native Win32 API

If the system credential store is unavailable, the CLI falls back to files under the agent-remote home directory with owner-only permissions. SQLite stores only local metadata and never stores access tokens or tool account login state.

## Local Paths

By default the CLI uses `~/.config/agent-remote/` on macOS and Linux, and
`%LOCALAPPDATA%\agent-remote\` on Windows:

```text
~/.config/agent-remote/
```

Override it for tests or custom installs:

```sh
AGENT_REMOTE_HOME=/path/to/state agent-remote doctor --fix
```

Managed external dependencies are expected under:

```text
~/.config/agent-remote/bin/
~/.config/agent-remote/dependencies/manifest.json
```

The four macOS/Linux release targets bundle managed `mutagen`, `tmux`, `wg`, and `wg-quick` binaries. macOS packages additionally bundle `wireguard-go`. Windows x64 and ARM64 packages bundle native CLI executables, Mutagen, an `scp.exe` compatibility proxy, and the architecture-specific official WireGuard for Windows MSI. That MSI provides the Windows equivalents of `wg`, `wg-quick`, and the tunnel backend (the tunnel manager, `wg.exe`, and Wintun driver). `tmux` runs on the remote Linux node and has no native Windows client role.

The current implementation records and checks the manifest for Mutagen and WireGuard helpers. Release packages include the managed Mutagen binary and WireGuard helper for each supported platform.

## WireGuard and SSH

`agent-remote wireguard config` creates or reuses a local X25519 private key, stores it in the platform credential store (with a `0600` file fallback), enrolls only its public key with the control plane, and writes `wireguard/agent-remote.conf` under the local agent-remote home. The generated tunnel uses an MTU of `1380` to avoid silent SSH key-exchange stalls on paths whose effective MTU is lower than WireGuard's platform default. The config uses `0600` permissions on Unix; on Windows, only the current user has full control and the WireGuard `LocalSystem` tunnel service has read access. Running the command repairs devices that were registered without a WireGuard peer. The private key is never sent to the server.

`agent-remote wireguard check|up|down` calls the managed `agent-remote-wireguard` helper and supports `--dry-run` for diagnostics. On macOS and Linux, release packages provide the required managed WireGuard tools. On Windows, the release includes the official WireGuard for Windows MSI and the helper controls its tunnel service with `/installtunnelservice` and `/uninstalltunnelservice`; run tunnel changes from an elevated terminal.

`agent-remote attach <id>` asks the control plane for a session-specific SSH authorization, waits up to 30 seconds for device-scoped SSH key synchronization to finish on the node, and then uses local `ssh` to run the node-side forced command. Windows uses the built-in OpenSSH Client optional feature. The former `--session-id <id>` form remains supported for compatibility.

## Workspace Sync

`agent-remote sync ensure` identifies the current directory, asks before creating a new remote sync relationship, registers the workspace with the control plane, creates a sync session, and starts the managed Mutagen session.

Before starting Mutagen, the CLI waits for the node to finish preparing the remote workspace. Managed sync sessions use directory mode `0770` and file mode `0660` so the account-specific Native Runtime identity can access the workspace without making it world-accessible.

Useful commands:

```sh
agent-remote sync ensure --yes
agent-remote sync status --fail-on-conflict
agent-remote sync pause
agent-remote sync resume
agent-remote sync resolve
agent-remote sync reset
```

The CLI uses the managed `bin/mutagen` binary from the agent-remote home or a sibling packaged binary. `.git` sync is enabled by default for project workspaces, while the machine-local Git index, lock files, hooks, worktrees, and common build/cache directories are excluded. Mutagen creation includes an initial flush so the remote runtime can build its own Git index from a complete workspace snapshot.

## Tool Accounts

`agent-remote account create` creates a remote tool-account record with region, timezone, locale, and preferred node tags. The control plane pins each account to an available runtime backend; clients display that backend but cannot silently switch it. `agent-remote account bind` asks the control plane to create a temporary remote tmux login session on the selected node, and `agent-remote account verify` schedules the verifier task after login is complete. The CLI only stores the agent-remote device token; tool login state remains on the remote node account archive.

`fclaude` displays the selected runtime backend when it creates or resumes a session. If the control plane reconciles a lost Native Runtime session as `interrupted`, `fclaude` creates a linked replacement session instead of attaching to the stale resource or replaying the previous command.

`fclaude list` prints a compact, space-aligned table with 12-character session and node IDs and a suffix-preserving working directory. Use `fclaude list --no-trunc` for complete values. The displayed short session ID can be passed directly to `fclaude attach <id>`, `fclaude stop <id>`, or `fclaude delete <id>`; ambiguous prefixes are rejected. Deletion is restricted to stopped or interrupted sessions. `fclaude delete --all` deletes all sessions in those two states for the current user.

`agent-remote account list` and `agent-remote credentials list` use the same compact ID convention and support `--no-trunc`. Displayed account and credential profile IDs can be used anywhere those IDs are accepted, including account binding, status, configuration import, default selection, and credential binding. `fclaude --account-id <id>` accepts the same account prefixes. Prefixes must contain at least four hexadecimal characters and must uniquely identify one item.

## Development

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

or:

```sh
scripts/run-quality-checks.sh
```

## Release Packaging

Build macOS and Linux CLI archives:

```sh
VERSION=0.0.5-fix.4 scripts/package-release.sh
```

Build a Windows x64 archive from PowerShell on Windows (pass `-Target aarch64-pc-windows-msvc` for ARM64):

```powershell
./scripts/package-release.ps1 -Version 0.0.5-fix.4
```

The release archive includes:

- `agent-remote`
- `fclaude`
- `agent-remote-wireguard`
- managed `mutagen`
- dependency manifest and third-party notices

The packaged files should be installed into the agent-remote home or placed on `PATH` by the platform installer.

GitHub Actions runs the same packaging flow for `v*` tags and uploads the archives to the GitHub Release. The `install-smoke` workflow also builds and installs native packages in isolated directories on Windows, Linux, and macOS, verifies every manifest checksum and dependency file, and executes the installed CLI binaries. On Windows it additionally installs the packaged WireGuard MSI and verifies both its command-line entry point and the `agent-remote-wireguard` integration.

Install the latest release directly:

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

Install a specific version or customize paths:

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version 0.0.5-fix.4 --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

Install a downloaded release archive:

```sh
./install.sh
```

Install on x64 or ARM64 Windows from PowerShell:

```powershell
Invoke-WebRequest https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.ps1 -OutFile install.ps1
.\install.ps1 -InstallPrerequisites
```

`-InstallPrerequisites` installs the Windows OpenSSH Client optional feature and the bundled official WireGuard package when they are missing, and may require an elevated PowerShell. WireGuard installation does not require `winget` or another network download. Omit the option when both are already installed. The installer adds `%LOCALAPPDATA%\agent-remote\bin` to the user `PATH`; open a new terminal after installation.

The installer copies managed binaries into `AGENT_REMOTE_HOME/bin`, writes the dependency manifest, and links `agent-remote`, `fclaude`, and `agent-remote-wireguard` into `~/.local/bin` by default. It can also override the GitHub repository, version, target, OS, architecture, home directory, link directory, and symlink/copy behavior.

## License

agent-remote-cli is licensed under GPL-3.0-only. See `LICENSE`.

Third-party dependency notices are listed in `THIRD_PARTY_NOTICES.md`.
