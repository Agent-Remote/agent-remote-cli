# agent-remote-cli

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
agent-remote attach --session-id <session-id> --print-only
agent-remote logout
```

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

If the system credential store is unavailable, the CLI falls back to files under the agent-remote home directory with owner-only permissions. SQLite stores only local metadata and never stores access tokens or tool account login state.

## Local Paths

By default the CLI uses:

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

The four release targets bundle managed `mutagen`, `tmux`, `wg`, and `wg-quick` binaries. macOS packages additionally bundle `wireguard-go`.

The current implementation records and checks the manifest for Mutagen and WireGuard helpers. Release packages include the managed Mutagen binary and WireGuard helper for each supported platform.

## WireGuard and SSH

`agent-remote wireguard config` creates or reuses a local X25519 private key, stores it in the platform credential store (with a `0600` file fallback), enrolls only its public key with the control plane, and writes `wireguard/agent-remote.conf` under the local agent-remote home with `0600` permissions. Running the command repairs devices that were registered without a WireGuard peer. The private key is never sent to the server.

`agent-remote wireguard check|up|down` calls the managed `agent-remote-wireguard` helper and supports `--dry-run` for diagnostics. Every CLI release bundles `wg`, `wg-quick`, and `tmux`; macOS releases also bundle the required `wireguard-go` userspace backend. The helper uses these managed binaries directly, without Homebrew or other system packages. Bringing the tunnel up may require `sudo`.

`agent-remote attach --session-id <id>` asks the control plane for a session-specific SSH authorization, schedules SSH key synchronization on the node, and then uses local `ssh` to run the node-side forced command.

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

The CLI uses the managed `bin/mutagen` binary from the agent-remote home or a sibling packaged binary. `.git` sync is enabled by default for project workspaces, while lock files, hooks, worktrees, and common build/cache directories are excluded.

## Tool Accounts

`agent-remote account create` creates a remote tool-account record with region, timezone, locale, and preferred node tags. The control plane pins each account to an available runtime backend; clients display that backend but cannot silently switch it. `agent-remote account bind` asks the control plane to create a temporary remote tmux login session on the selected node, and `agent-remote account verify` schedules the verifier task after login is complete. The CLI only stores the agent-remote device token; tool login state remains on the remote node account archive.

`fclaude` displays the selected runtime backend when it creates or resumes a session. If the control plane reconciles a lost Native Runtime session as `interrupted`, `fclaude` creates a linked replacement session instead of attaching to the stale resource or replaying the previous command.

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
VERSION=0.0.4-fix.6 scripts/package-release.sh
```

The release archive includes:

- `agent-remote`
- `fclaude`
- `agent-remote-wireguard`
- managed `mutagen`
- dependency manifest and third-party notices

The packaged files should be installed into the agent-remote home or placed on `PATH` by the platform installer.

GitHub Actions runs the same packaging flow for `v*` tags and uploads the archives to the GitHub Release.

Install the latest release directly:

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | bash
```

Install a specific version or customize paths:

```sh
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version 0.0.4-fix.6 --home ~/.config/agent-remote --bin-dir ~/.local/bin
```

Install a downloaded release archive:

```sh
./install.sh
```

The installer copies managed binaries into `AGENT_REMOTE_HOME/bin`, writes the dependency manifest, and links `agent-remote`, `fclaude`, and `agent-remote-wireguard` into `~/.local/bin` by default. It can also override the GitHub repository, version, target, OS, architecture, home directory, link directory, and symlink/copy behavior.

## License

agent-remote-cli is licensed under GPL-3.0-only. See `LICENSE`.

Third-party dependency notices are listed in `THIRD_PARTY_NOTICES.md`.
