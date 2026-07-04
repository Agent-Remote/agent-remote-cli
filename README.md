# agent-remote-cli

Rust CLI for agent-remote local device management.

The package provides the `agent-remote` command. Tool-specific launchers such as `fclaude` are intentionally separate so regular `claude` usage remains untouched.

## Commands

```sh
agent-remote login --server-url https://agent-remote.example.com --username alice
agent-remote status
agent-remote doctor --fix
agent-remote deps status
agent-remote logout
```

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

The current implementation records and checks the manifest for Mutagen and WireGuard helpers. Release packaging will place the actual platform binaries there.

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

## License

agent-remote-cli is licensed under GPL-3.0-only. See `LICENSE`.

Third-party dependency notices are listed in `THIRD_PARTY_NOTICES.md`.
