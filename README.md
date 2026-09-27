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
agent-remote wireguard status
agent-remote sync ensure
agent-remote sync status
agent-remote account create --tool claude --name "Claude US" --region US --timezone America/Los_Angeles --tag us
agent-remote account list
agent-remote account bind <account-id>
agent-remote account verify <account-id>
agent-remote account status <account-id>
agent-remote ssh check --session-id <session-id>
agent-remote attach <session-id> --print-only
agent-remote node install --node <node-id-or-prefix> [--enable-ego-browser] [--yes]
agent-remote device install --source "/path/to/agent-remote-device-macos-0.2.12.zip"
agent-remote device uninstall [--yes]
agent-remote device status
agent-remote device launch
agent-remote device diagnose
agent-remote device revoke [--device <device-id>] [--yes]
agent-remote device rotate-token [--yes]
agent-remote ego-browser setup
agent-remote ego-browser connect [<tool-session-id-or-prefix>]
agent-remote ego-browser status [<binding-id>]
agent-remote ego-browser repair|upgrade
agent-remote ego-browser pause|resume|stop [<binding-id>] [--binding-generation <generation>]
agent-remote ego-browser remove
agent-remote ego-browser forget-this-mac
agent-remote ego-browser register --signer-certificate-sha256 HEX [--server-url URL] # advanced compatibility
agent-remote ego-browser requests <binding-id>
agent-remote ego-browser cancel-request <binding-id> <request-ledger-id> [--yes]
agent-remote ego-browser revoke [<binding-id>] [--binding-generation <generation>] [--yes]
agent-remote ego-browser delete-binding <binding-id> [--yes]
agent-remote ego-browser delete-device <device-id> [--yes]
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

On Servers supporting CLI sessions, user commands migrate a still-valid login to a
remembered session and automatically rotate its short-lived access token. The default
session lifetime is 30 days; expiry, revocation, or account disablement requires login
again. Both credentials remain in the credential store, and logout revokes the session.
Device registration also retains the user login needed for browser management. Older
Servers retain their existing short-lived login behavior. Browser connect/resume still
requires a separate full-trust confirmation.

- macOS: Keychain through the `security` command
- Linux: Secret Service through `secret-tool`
- Windows: Windows Credential Manager through the native Win32 API

When the configured server and active device registration are unchanged, logging in again reuses
that device, refreshes its metadata and SSH public key, and replaces its device token. A new device
is registered only when no active local registration is configured. This keeps existing workspaces
bound to the same device across CLI upgrades.

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

The four macOS/Linux release targets bundle managed `mutagen`, `tmux`, `wg`, and `wg-quick` binaries plus SSH/SCP wrappers for managed host verification. macOS packages additionally bundle `wireguard-go`. Windows x64 and ARM64 packages bundle native CLI executables, Mutagen, `ssh.exe` and `scp.exe` compatibility proxies, and the architecture-specific official WireGuard for Windows MSI. That MSI provides the Windows equivalents of `wg`, `wg-quick`, and the tunnel backend (the tunnel manager, `wg.exe`, and Wintun driver). `tmux` runs on the remote Linux node and has no native Windows client role.

The current implementation records and checks the manifest for Mutagen and WireGuard helpers. Release packages include the managed Mutagen binary and WireGuard helper for each supported platform.

## Local Device Control

`agent-remote device install` accepts an explicit local release ZIP archive or an app bundle named `Agent Remote Device.app`. ZIP archives are size- and path-validated, copied into a private temporary directory, and automatically extracted; they must contain only the fixed app bundle at the archive root. The community release CLI then verifies the fixed bundle identifier, the self-signed certificate fingerprint pinned into the CLI, the Network Broker and GUI Executor XPC services signed by that same identity, and the complete code signature before and after staging. It removes quarantine only from the verified staging bundle and atomically installs it at `~/Applications/Agent Remote Device.app`. Reinstalling the same semantic version and upgrading are allowed; downgrades and missing or malformed bundle versions are rejected. It never downloads or executes an installer URL supplied by a project or API response. Community builds obtain the certificate fingerprint only from the protected `production-community-release` environment and report Gatekeeper as `manual trust`; they do not claim Apple notarization.

Use `agent-remote device status` for the installed version, signature, XPC, and process state. `agent-remote device launch` verifies the installed bundle and the shared device credential before opening the local APP; the APP then lists the owning user's running Claude sessions and performs claim, rebind, and local approval itself. `agent-remote device diagnose` performs the same strict checks and exits non-zero when the installation is not trusted. `agent-remote device uninstall` requires the app to be stopped, removes its fixed app bundle, shared Broker credential, TCC grants, and bundle-owned sandbox data, but does not revoke the remote registration. It refuses to proceed while hidden-application recovery state remains. `agent-remote device revoke` requires a stored user token, asks for confirmation unless `--yes` is supplied, revokes the selected or active device through the control plane, and removes its local device credential and refresh state. `agent-remote device rotate-token` rotates only the active device through the control plane, never prints the returned token, and immediately replaces the local platform credential and shared Network Broker credential; stop active device-control sessions before using it.

## Node Enrollment

`agent-remote node install --node <node-id-or-prefix>` authenticates the fixed Node release checksum
and Sigstore workflow identity on the control workstation, transfers its archive over a dedicated SSH
stdin, runs the staged installer, and only then asks the control plane for a short-lived join code. The
code is sent over a separate SSH stdin and never enters argv, environment variables, URLs, logs, or
terminal output. A retry may reuse a byte-identical staged archive, but it always reruns the installer
before issuing a code. The pinned `0.2.23` release is accepted only with its tag-bound assets
and Sigstore evidence.

## Ego Browser Bridge Control

The normal flow is `agent-remote ego-browser setup`, followed by `agent-remote ego-browser connect` when the user is ready to select and authorize one remote session. `setup` reuses the server and credential from `agent-remote login`, discovers the verified release profile and certificate pin, ensures the existing Device identity, and never claims a session. Ordinary use does not require a Server URL, registration token, Device ID, or certificate digest.

Running `setup`, `repair`, or `upgrade` pauses this Mac's existing executable bindings before restarting the Bridge and preserves their recovery generation. If a paused binding remains, follow its `resume` instruction; otherwise use `connect`. A failed pause stops installation. Repeating `claim` or `connect` checks the retained binding before changing local admission: a live binding remains usable, and a paused binding offers `resume`. If Server state is active but local execution is closed, `status` directs you to `pause` that binding before `resume`. The advanced `register` command requires a verified 64-character certificate fingerprint through its flag or `EGO_BROWSER_SIGNER_CERTIFICATE_SHA256`; missing or malformed values produce `signer_certificate_required` or `signer_certificate_invalid` in both text and JSON output before loading login credentials.

With an existing verified installation, `setup` and `repair` run only that release's owner-only
installer and never upgrade it. A missing installation or an explicit `upgrade` uses a bootstrap
pinned by commit and SHA-256; that bootstrap may request only the Bridge version, repository,
profile, and signing certificate selected by `release-dependencies.json`. It receives no Server URL,
token, session ID, or full-trust claim. Missing or invalid release assets and Sigstore evidence
fail closed.

Repair pauses through the Device Client so the local handoff retains the new binding generation.
Lifecycle recovery verifies the same binding, device, and tool session before using a newer Server
generation; explicit stale generations still fail closed.

After installation, `upgrade` explicitly re-enrolls the retained device to update the Server's
release metadata without changing its ID, generation, or keys. The Server must support canonical
same-identity re-enrollment; ordinary `setup` and `repair` cannot update release metadata.

Local trust is stored owner-only against the exact profile ID, profile version, Bridge version, and
certificate pin. Routine `repair` reuses an exact match without `--yes`; first use or any tuple change
requires confirmation, and non-interactive use returns `trust_confirmation_required` unless the
caller explicitly supplies `--yes`.

`connect` and `resume` show the full-trust warning and require explicit confirmation. `pause` is recoverable: it preserves the paused binding for a separately confirmed `resume` at a new binding generation. `stop` is terminal and requires a fresh `connect`. These lifecycle commands resolve the active handoff or one unambiguous candidate when IDs are omitted and fail closed instead of guessing. Browser scripts run as the current macOS user without an App Sandbox and can access files, network, login data, subprocesses, and any ego lite Tab or Task Space; cancellation stops supervised work but cannot undo side effects or guarantee cleanup of deliberately detached processes.

`register`, explicit `--server-url`, and `--signer-certificate-sha256` remain advanced compatibility surfaces for custom or older releases. `register` still passes the stored token to the Device Client over stdin, so it never appears in process arguments or CLI output. `status` shows local Bridge devices and bindings, while `status <binding>` also shows that binding's active requests. Use `requests <binding>` to refresh the active request ledger and `cancel-request <binding> <request-ledger-id>` to stop only that exact execution without invalidating the binding. Binding, request, claim-session, and deletion identifiers accept unique hexadecimal prefixes; `--no-trunc` prints full values. `delete-binding` permanently removes a terminal binding and its retained request ledger after revocation delivery has completed. `delete-device` permanently removes a revoked device after all of its binding history has been deleted. Both deletion commands ask for confirmation unless `--yes` is supplied.

Deletion before revocation or termination returns `device_not_revoked` or `binding_not_terminal`
with a recovery action, even with `--yes`. Rejected identity operations report the observed local
admission without closing it; unverified connection and availability fields remain `null`.

Add global `--json` for machine-readable lifecycle output. Successful mutations, status, binding
lists, and request lists each emit exactly one JSON document; JSON mode never prompts or guesses a
candidate. The projection deliberately excludes credentials, keys, scripts, page data, cookies,
URLs, and relay ciphertext.

## WireGuard and SSH

`agent-remote wireguard config` creates or reuses a local X25519 private key, stores it in the platform credential store (with a `0600` file fallback), enrolls only its public key with the control plane, and writes `wireguard/agent-remote.conf` under the local agent-remote home. The generated tunnel uses an MTU of `1000` to avoid silent SSH key-exchange stalls on paths whose effective MTU is lower than WireGuard's platform default. The config uses `0600` permissions on Unix; on Windows, only the current user has full control and the WireGuard `LocalSystem` tunnel service has read access. Running the command repairs devices that were registered without a WireGuard peer. The private key is never sent to the server.

`agent-remote wireguard check|up|down` calls the managed `agent-remote-wireguard` helper and supports `--dry-run` for diagnostics. `agent-remote wireguard status` displays the active interfaces and peer runtime state reported by `wg show`, including endpoints, latest handshakes, transfer counters, and keepalive settings. On macOS and Linux, it automatically retries through `sudo` when the kernel denies an unprivileged status query. Release packages provide the required managed WireGuard tools. On Windows, the release includes the official WireGuard for Windows MSI and the helper controls its tunnel service with `/installtunnelservice` and `/uninstalltunnelservice`; `status`, `up`, and `down` automatically request elevation through a UAC prompt when needed.

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

The CLI uses the managed `bin/mutagen` binary from the agent-remote home or a sibling packaged binary. Mutagen and direct attach SSH connections use an agent-remote-managed `known_hosts` file and automatically trust new WireGuard endpoint keys while continuing to reject changed keys. After an upgrade introduces a new managed SSH environment, the CLI restarts the Mutagen daemon once so that it inherits the managed proxy path. `.git` sync is enabled by default for project workspaces, while the machine-local Git index, lock files, hooks, worktrees, and common build/cache directories are excluded. Mutagen creation includes an initial flush so the remote runtime can build its own Git index from a complete workspace snapshot. `sync ensure` recreates a missing local Mutagen session when the control-plane relationship is still active. It also repairs stale local Workspace and Sync IDs after their control-plane resources were deleted.

## Session Port Forwarding

Forward one Native session loopback TCP port to this device without publishing a node or container port:

```sh
agent-remote forward 5173 --session <session-id> --local-port auto --open
fclaude forward 3000
agent-remote forward list
agent-remote forward stop <forward-id>
agent-remote forward stop --session <session-id> --all
```

The local listener binds only `127.0.0.1` and, when available, `::1`. The default local port matches the remote port; use `--local-port auto` when it is occupied. One restricted SSH stdio tunnel multiplexes HTTP, WebSocket/HMR, SSE, gRPC, and ordinary TCP connections. OpenSSH `-L/-R/-D/-W`, arbitrary targets, public binds, and token persistence remain disabled. A disconnected tunnel obtains a new one-time token and reconnects while preserving the local listener; existing streams are not replayed.

Run the remote application on its runtime loopback, for example `npm run dev -- --host 127.0.0.1`. The current release supports Native Runtime sessions only and reports a clear capability error for Docker Sandbox sessions.

## Tool Accounts

`agent-remote account create` creates a remote tool-account record with region, timezone, locale, and preferred node tags. The control plane pins each account to an available runtime backend; clients display that backend but cannot silently switch it. `agent-remote account bind` asks the control plane to create a temporary remote tmux login session on the selected node, and `agent-remote account verify` schedules the verifier task after login is complete. The CLI only stores the agent-remote device token; tool login state remains on the remote node account archive.

`fclaude` displays the selected runtime backend when it creates or resumes a session. If the control plane reconciles a lost Native Runtime session as `interrupted`, `fclaude` creates a linked replacement session instead of attaching to the stale resource or replaying the previous command.

`fclaude list` prints a compact, space-aligned table with 12-character session and node IDs and a suffix-preserving working directory. Use `fclaude list --no-trunc` for complete values. The displayed short session ID can be passed directly to `fclaude attach <id>`, `fclaude stop <id>`, or `fclaude delete <id>`; ambiguous prefixes are rejected. Deletion is restricted to stopped, interrupted, or failed sessions. `fclaude delete --all` deletes all sessions in those three states for the current user. Managed sessions whose Skill content is still pending return `STATE_PENDING` for both individual and bulk deletion. Keep the retained Node data and use `fclaude stop-status <operation-id> --wait` to observe saving before retrying deletion.

`agent-remote account list` and `agent-remote credentials list` use the same compact ID convention and support `--no-trunc`. Displayed account and credential profile IDs can be used anywhere those IDs are accepted, including account binding, status, configuration import, default selection, and credential binding. `fclaude --account-id <id>` accepts the same account prefixes. Prefixes must contain at least four hexadecimal characters and must uniquely identify one item.

`agent-remote account import-config --account <id>` waits for the selected node to finish writing the accepted Claude configuration and exits non-zero when the task fails, is cancelled, expires, or does not reach a terminal state within 120 seconds. The timeout message preserves the task ID because the remote task may still complete after the local wait ends. Use `--dry-run` to preview paths and `--include-resume-history` only when prompts, transcripts, and local paths are intentionally included. Add `--exclude-skills` to omit `~/.claude/skills` before file collection while importing other configuration. Plugin content and project history keep their existing selection rules; this option does not itself enable managed skill ownership.

`connect` accepts the same displayed 12-character session ID as `fclaude list`, a unique hexadecimal prefix, or a full UUID (case-insensitive). An ambiguous prefix requires a more specific ID. Rejected lifecycle commands report the observed local admission; an unobserved connection state remains `null` in JSON. `request_not_active` means the requested execution has ended or is absent from the active ledger: refresh with the suggested `requests` command instead of repairing the Bridge. Ambiguous or malformed request IDs are reported separately.

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
VERSION="$(cargo metadata --format-version=1 --no-deps | jq -r '.packages[] | select(.name == "agent-remote-cli") | .version')" \
  scripts/package-release.sh
```

Build a Windows x64 archive from PowerShell on Windows (pass `-Target aarch64-pc-windows-msvc` for ARM64):

```powershell
$version = ((cargo metadata --format-version=1 --no-deps | ConvertFrom-Json).packages | Where-Object name -eq "agent-remote-cli").version
./scripts/package-release.ps1 -Version $version
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
VERSION=VERSION_TO_INSTALL
curl -fsSL https://raw.githubusercontent.com/Agent-Remote/agent-remote-cli/main/scripts/install.sh | \
  bash -s -- --version "$VERSION" --home ~/.config/agent-remote --bin-dir ~/.local/bin
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

`-InstallPrerequisites` installs the Windows OpenSSH Client optional feature and the bundled official WireGuard package when they are missing, and may require an elevated PowerShell. WireGuard installation does not require `winget` or another network download. Omit the option when both are already installed. During an upgrade, the installer detects a Mutagen daemon running from the managed installation, stops it before replacing the locked executable, and restarts it afterward; unrelated Mutagen installations are not stopped. The installer adds `%LOCALAPPDATA%\agent-remote\bin` to the user `PATH`; open a new terminal after installation.

The installer copies managed binaries into `AGENT_REMOTE_HOME/bin`, writes the dependency manifest, and links `agent-remote`, `fclaude`, and `agent-remote-wireguard` into `~/.local/bin` by default. It can also override the GitHub repository, version, target, OS, architecture, home directory, link directory, and symlink/copy behavior.

## License

agent-remote-cli is licensed under GPL-3.0-only. See `LICENSE`.

Third-party dependency notices are listed in `THIRD_PARTY_NOTICES.md`.


### Install Git and local skill sources

```sh
agent-remote skill add owner/repo --list
agent-remote skill add https://example.com/team/skills.git --ref main --path one --yes
agent-remote skill add owner/repo --ref refs/tags/v1 --skill one --yes
agent-remote skill add ./skills --list
agent-remote skill add ./my-skill --dry-run
agent-remote skill add ./my-skill --yes
agent-remote skill add ./skills --skill one --skill two --yes
agent-remote skill add ./skills --all --tool claude --yes
agent-remote skill add ./skills --path one --account-id ACCOUNT_UUID --yes
```

Discovery lists names, descriptions, relative paths and invalid candidates without Server login or uploads.
Local listing uses no network; Git listing contacts the repository and may read its native credentials.
One valid skill is selected automatically. Multiple candidates require an interactive selection,
`--skill` or `--all`; `--yes` only confirms the selected plan. `--list`, `--all` and `--skill` are
mutually exclusive. Explicit subdirectories must stay within the source root.

Installation uses the authenticated remote user library. Every selected skill is completely captured
into a private temporary package before preview or confirmation; uploads read those captured bytes.
The preview shows names, digests, sizes, scope and expected generation. `--dry-run` uploads nothing
and records no new mutation. Local source locators are opaque fingerprints, not remote host paths.
Directly selecting a directory or selecting it through `--path` preserves its source identity.

All selected packages must be verified on the Server before one atomic installation request is sent.
A failed candidate cannot partially install the selection. Repeating unchanged source/scope is a
no-op; changed installed content requires update, and rule changes require enable/disable/inherit.
Content upload retries preserve their original plan in the current invocation. If the process ends
before configuration submission, repeating add creates a fresh confirmed capture; staged Server
content remains subject to its upload lease and retention policy.

Before installation POST, the local command journal saves exact items, generation and idempotency key.
After uncertain acceptance, repeat the same source argument, selection and scope (from the same working
directory for relative paths), or inspect `skill status --last`. Recovery uses already completed Server
content and never rereads changed/missing sources or refreshes the original generation. It follows the
same `--no-wait`, timeout, commitment and target-readiness behavior as rule commands.

Git acquisition requires native Git on PATH. Use GitHub `owner/repo` shorthand or a credential-free
HTTPS repository URL; prefix local two-component paths with `./`. Arbitrary webpage URLs and SSH/file
transports are not supported. `--ref` selects a literal branch, tag or full commit. Without it, the
current default branch becomes the tracking ref. A name shared by a branch and tag requires
`refs/heads/NAME` or `refs/tags/NAME`. Every package records its full commit and repository-relative
subpath; Git recovery also repeats the original `--ref` and does not depend on the current directory.

Private HTTPS repositories reuse native Git credential helpers noninteractively. Authentication stays
in local child-process memory; it never enters source URLs, the command journal or Server uploads.
Configure the helper with your usual Git login first. Transport ignores inherited Git execution
configuration, disables HTTP redirects and enforces TLS verification. Private CA certificates can be
supplied with `GIT_SSL_CAINFO`. Raw objects are read from a private bare repository: no checkout,
source hooks, smudge filters, archive substitutions or install scripts run. Executable modes, binary
bytes and internal links are preserved independently of the host filesystem. Selected unresolved
submodules and LFS pointers fail with `INCOMPLETE_SOURCE`; acquire complete assets locally if needed.

Git discovery/acquisition and each selected capture have a 240-second deadline, with shorter individual
process limits. Output, tree entries and expanded packages are bounded. Fetch staging is monitored
against 512 MiB/100000 entries every 100 ms and checked again on completion; this is not a hard limit
on downloaded network bytes and may overshoot between checks. Temporary objects are removed on normal
completion/cancellation. Ctrl-C during Git work returns 130.

### Check and update skill sources

```sh
agent-remote skill check
agent-remote skill check my-skill
agent-remote skill update my-skill --dry-run
agent-remote skill update my-skill --yes
agent-remote skill update my-skill --ref v2 --stage --yes
agent-remote skill update my-skill --ref v2 --yes
agent-remote skill update my-skill --from ./my-skill --yes
agent-remote skill update --all --yes
```

Checks compare complete branch packages with the current default revision. They upload nothing and
create no mutation journal. Results distinguish `up_to_date`, `update_available`, `pinned`,
`local_source` and failures. Fixed tags/commits and rollback-fixed policies are skipped; local sources
require an explicit `--from` for updates. Branch checks follow the recorded branch even if the remote
default changes or a same-named tag appears. Network/source failures return nonzero.

Single Git updates use the recorded branch unless `--ref` explicitly selects a new branch/tag/commit.
Fixed tracking requires `--ref`. `--from` is only for local sources: provide a complete directory with
the same skill name; the installed opaque source identity is preserved across devices. Changed Git
names or subpaths return `SOURCE_LAYOUT_CHANGED` with expected/observed details. Known moved tags
return `SOURCE_DRIFT`; the Server independently validates its complete observation history.

Every plan captures content before confirmation. `--stage` registers one candidate without changing
the default, upstream tracking or account state; its returned revision ID can be pinned. It cannot
be combined with `--all`. Retained matching revisions are reused without uploading their content
again, including staged-candidate activation. Updates preserve enabled rules and independent pins.
Before a configuration POST, the journal retains the exact skill, content, generation and key.
Repeat the same identifier, `--ref`, `--from` and stage choice to recover uncertain acceptance before
source access. Relative `--from` recovery needs the same working directory.

`update --all` handles skills independently, reports fixed/local sources as skipped, continues after
individual failures and exits nonzero on partial failure. It rejects `--ref`, `--from` and `--stage`.
Without `--yes`, each eligible plan is confirmed individually. Each fresh item reads its own current
generation; submitted requests are never silently rebased. Pending automatic Git updates are
recovered first, even if the current listing no longer contains them. A repeated batch re-evaluates
fresh items; it is not one global transaction or one global operation ID.

JSON checks and batches contain one version-1 envelope with `data.items`; each row includes the skill
ID/name, status, exit code and full item result. Batch `committed=true` means at least one item was
confirmed committed, and each row carries its own commitment and operation ID. Failures are also
collected in the outer `errors`. Successful checks/updates exit 0, batch partial failures exit 1,
argument errors exit 2, pending wait expiry exits 3 and interruption exits 130. An interrupted
configuration submission retains its original key and explicitly unknown acceptance; it is not a
rollback. `--no-wait` and `--timeout` apply to each accepted operation independently.

### Skill library queries

User-authenticated skill queries are available when the Server enables its skill manager:

```sh
agent-remote skill list
agent-remote skill list --tool claude
agent-remote skill info my-skill --account-id ACCOUNT_UUID
agent-remote skill list --account-id ACCOUNT_UUID --effective
agent-remote skill status OPERATION_UUID --wait --timeout 60
agent-remote --json skill status OPERATION_UUID
```

Tool and account scopes are mutually exclusive. Account listing requires `--effective`; IDs use
complete UUIDs. These commands use the existing **user login**, never a device token. List/info show
library revisions, rule overrides and field origins. Account-scoped views also include active local
entries, including disabled ones, with account/checkpoint identity and retained initial revisions.
This view does not yet include session-pinned snapshots, system entries, runtime checkpoints or
model-loading evidence.

JSON stdout contains one version-1 skill envelope with `operation_id`, `status`, `committed`,
`retryable`, `data` and `errors`; explanations go to stderr. An ordinary status query can report
pending without waiting. `--wait` follows only the original operation, exits immediately on known
failure/conflict/supersession, and returns 3 when its deadline expires with a last observed pending
result. Timeout does not cancel the remote operation. If a later refresh is denied or malformed,
the error result retains the last observed data, commitment and original operation ID. Successful queries/completed operations exit 0,
known failures exit 1, argument errors exit 2, and interrupted waiting exits 130. Missing credentials
and malformed/unavailable Server responses fail without printing private response details.
The remaining state commands and complete runtime integration are still under development.

### Account state history and exports

```sh
agent-remote skill state list my-skill --account-id ACCOUNT_UUID
agent-remote skill state list --scope account-directory --account-id ACCOUNT_UUID
agent-remote skill state info CHECKPOINT_UUID
agent-remote skill state info DIRECTORY_CHECKPOINT_UUID --members --limit 100
agent-remote skill state diff my-skill --account-id ACCOUNT_UUID --limit 100
agent-remote skill state diff --checkpoint CHECKPOINT_UUID --cursor PATH_FROM_PREVIOUS_PAGE
agent-remote skill state export my-skill --checkpoint CHECKPOINT_UUID --output ./skill-state
agent-remote skill state export --scope account-directory --account-id ACCOUNT_UUID --checkpoint DIRECTORY_CHECKPOINT_UUID --output ./directory-state
```

History includes all revisions and epochs, current-head flags, retained/expired content and source
finalization outcomes. JSON `data.checkpoints` and `data.pending` have separate `items` and
`next_cursor` fields; continue them with `--cursor` and `--pending-cursor`. Each page defaults to 100
records (maximum 200). Pending records identify their source Node and are not restorable checkpoints.
Info returns `data.checkpoint` and optional `data.members`; `--members` is directory-only and supports
`--limit`/`--cursor`. Inspecting an expired record succeeds with `status=state_expired`; exporting it fails.

Diff shows metadata, including file types, modes, sizes, digests and links, without semantic guesses
or file bodies. It identifies the original package/local initial revision or directory parent baseline.
Its limit is 1–500. Continue with the returned immutable `--checkpoint` and `--cursor`; a cursor cannot
be combined with a moving current-head selection. An uninitialized or expired current branch fails
explicitly. Names resolve on the Server; ambiguous library/local names require full skill UUIDs.

Export verifies account/source/scope, the complete manifest digest, and every unique object's size,
SHA-256 and text/binary classification. The destination must be absent or empty, with an existing
parent. Private sibling staging is renamed into place only after complete verification. The portable
bundle contains `checkpoint.json`, `manifest.json` and `objects/<sha256>`; original file paths, modes,
empty directories and links are preserved in the manifest, and no links or source-controlled paths
are instantiated locally. Read a manifest file entry's digest to locate its exact bytes. This is a
verifiable content bundle, not a prepared runtime directory or a direct `resolve --directory` input.

Item export infers its account from the checkpoint unless `--account-id` is supplied; directory export
requires it. Item checkpoints with cross-skill links require exporting their backing directory
checkpoint. Explicitly recorded local deletion can export an empty manifest with deletion metadata;
missing or Node-only pending bytes never create a successful empty bundle. Export follows the complete
manifest size, including bytes above the configured runtime quota, and requires enough destination
space. Downloads stream with a one-hour per-object deadline and 30-second header/idle deadlines.
Ctrl-C before publication exits 130 and discards staging; final atomic publication is observed to
completion. State query/export does not write a mutation journal or change skill configuration or
state heads. Frozen Node authorization may synchronize the already registered SSH keys.

To recover a stopped Native snapshot still held by its original online Node, including when Server
state quota prevents upload or local disk reserve prevents freezing:

```sh
agent-remote skill state export --scope account-directory --account-id ACCOUNT_UUID --snapshot SNAPSHOT_UUID --output ./frozen-state
```

Use the original `snapshot_id` from pending history or the managed stop operation ID. `--snapshot`
and `--checkpoint` are mutually exclusive. Snapshot export requires complete directory scope and an
explicit account; it preserves cross-skill links. The local device and SSH public key must be
registered, with the corresponding private key available to SSH (its default key or local agent).
It uses your live user login, waits at most 60 seconds for Node key synchronization, then connects
through the existing restricted SSH gateway. Custom SSH configuration and forwarding are disabled.

The source needs a complete frozen capture or the original stopped work with retained runtime
authority. If a full disk prevented saving termination evidence, a recorded original invocation
is required and the recovered content is marked unclean. For stopped work, the Helper must prove that all original writers exited and verify the
complete tree before and after reading. Existing corrupt captures cannot fall back to work. Export
never stops a running session, creates a durable capture, uploads content, advances heads, or
releases retained Node data. Frozen snapshots retain the 100000-entry manifest limit. Negotiated stopped-work recovery streams
all entries with bounded metadata memory, including trees above that limit. Signed counter overflow
checks remain; recovery has no separate fixed 10 GiB byte ceiling. An unavailable
Node, expired/revoked login/device/key, or missing content fails without publishing a bundle.
The gateway renews live authorization during transmission under the same original user token,
device, key and snapshot. The transfer can continue beyond fifteen minutes while authorized and
making progress. Initial and final tree scans each have a fifteen-minute limit; gaps between
incoming bytes are limited to thirty seconds. Renewal cannot outlive or replace the original token.

Frozen exports use `agent-remote-skill-node-snapshot-v1` with `manifest.json`. Stopped-work exports
use `agent-remote-skill-node-recovery-v1`: `recovery.jsonl` contains complete ordered entries,
`entries/` indexes their metadata by path hash, and `objects/` contains verified files by content hash.
`checkpoint.json` records the original binding, recovery digest, termination classification and counts.
JSON command output identifies the format; its `tree_digest` carries that format's digest. Recovery
bundles are distinct from importable manifest v1 checkpoints. Neither format proves Server publication.
Current recovery negotiation requires a matching Node/Helper; unsupported older gateways fail closed.
Complete runtime/backend acceptance remains under development.

### Inspecting conflicts

```sh
agent-remote skill state conflicts my-skill --account-id ACCOUNT_UUID
agent-remote skill state conflicts --scope account-directory --account-id ACCOUNT_UUID --limit 100
agent-remote skill state diff --conflict CONFLICT_UUID --limit 100
agent-remote skill state diff --conflict CONFLICT_UUID --cursor CURSOR_FROM_PREVIOUS_PAGE
```

Conflict lists return separate JSON `data.publications` and `data.migrations` pages, each with
`items` and `next_cursor`. Use `--cursor` for session publications and `--migration-cursor` for
version migrations; each page defaults to 100 records, maximum 200. Names resolve once to a stable
source ID. Session conflicts always cover the complete account directory; selecting a skill includes
attempts that observed its unchanged branch. Lists include unresolved and superseded attempts.

Conflict diff returns `data.kind` (`publication` or `migration`), `data.conflict` (details) and
`data.diff` (metadata page). The details identify each saved side's source, exact revision/reference
and digest. Publication details include original session branches and saved resolution choices.
Migration details retain the immutable original receipt and show current branch drift separately;
a later source head never replaces the saved incoming side. The command only tries the migration
endpoint after an explicit publication `CONFLICT_NOT_FOUND` response.

Diff pages contain 1–500 paths and no file bodies. Continue with the same conflict ID and the returned
cursor verbatim: publication cursors are paths, while migration cursors bind the attempt and all three
saved digests. Missing or expired input fails explicitly. A successful inspection returns 0 and
`status=ready`, `committed=false`, even when the inspected record is conflicted or superseded; inspect
`data.conflict.status` for that record's current status. Ctrl-C returns 130. These queries do not save
choices, recompute migrations, change heads, or create a local mutation journal.

### Resetting and restoring account state

```sh
agent-remote skill state reset my-skill --account-id ACCOUNT_UUID --dry-run
agent-remote skill state reset my-skill --account-id ACCOUNT_UUID --yes
agent-remote skill state restore my-skill --account-id ACCOUNT_UUID --checkpoint CHECKPOINT_UUID --yes
agent-remote skill state reset --scope account-directory --account-id ACCOUNT_UUID --dry-run
agent-remote skill state restore --scope account-directory --account-id ACCOUNT_UUID --checkpoint DIRECTORY_CHECKPOINT_UUID --yes
agent-remote skill status OPERATION_UUID
agent-remote skill status --last
```

A complete Server preview fixes the account, stable source, base revision, installation/state epochs,
directory head/epoch and library generation before confirmation. It shows changes against both the
current directory and each target's own prior branch, including an unavailable expired baseline.
Names resolve once and the submitted selector uses the exact source UUID. `--dry-run` sends a
read-only preview request, creates no mutation journal row and changes no remote state. JSON preview
uses `data.request`, `data.preview` and `data.recovering_original_request`. Interactive execution
confirms this exact plan once; noninteractive execution requires `--yes`.

Reset publishes original content while preserving historical checkpoints. Restore accepts retained
compatible history, including detached input; the Server checks owner/account/source/base revision
and allowed same-source installation-epoch recovery. Directory restore also requires the exact
current effective member set. A mismatch or changed head/epoch fails explicitly, without updating
rules or silently refreshing the confirmed plan. Item changes advance the selected state epoch;
directory changes advance directory and affected branch epochs. Existing sessions retain their fixed
snapshots; late old-epoch writes remain detached rather than resurrecting cleared data.

Before an actual POST, the shared private journal saves the exact request and confirmed result-tree
digest for this Server/user. After unknown acceptance, repeat the same action, identifier, account,
scope and checkpoint: recovery queries the original key before any fresh selection and only replays
identical input after an explicit OPERATION_NOT_FOUND. `skill status --last` uses this original state
receipt protocol; an explicit operation UUID also works from another logged-in device. Published
receipts remain immutable after later resets/restores. A dry-run of an uncertain command queries its
original receipt first and can report an earlier committed result without submitting anything.

State publication completes atomically on the Server, so successful responses already have
`status=published`, `committed=true` and an operation ID. Common `--no-wait`/`--timeout` options are
accepted; these state receipts have no subsequent deployment targets to wait for. `status --wait`
bounds its original query deadline. Interrupted planning/confirmation exits 130 without a new state
submission; interrupted submission retains the key and explicitly unknown commitment. Neither a
local timeout nor interruption implies rollback. Pending state journals do not trigger package
updates when running `skill update --all`.

### Skill rules and rollback

```sh
agent-remote skill disable my-skill --dry-run
agent-remote skill enable my-skill --yes
agent-remote skill disable my-skill --tool claude --yes
agent-remote skill pin my-skill --revision r2 --account-id ACCOUNT_UUID --yes
agent-remote skill unpin my-skill --tool claude --yes
agent-remote skill inherit my-skill --account-id ACCOUNT_UUID --field enabled --yes
agent-remote skill disable my-skill --all-scopes --yes
agent-remote skill rollback my-skill --revision r1 --yes
agent-remote skill remove my-skill --yes --no-wait
agent-remote skill status --last
```

Pin, unpin and inherit require a tool or account scope; omitted inherit fields restore both fields.
`disable --all-scopes` clears enabled overrides while preserving revision pins. Rollback without a
revision uses the Server's previous distinct activation, not arithmetic on revision numbers. These
commands change the user library and rules for new sessions, not existing session snapshots or
learning state.

Account-local skills support `info`, account-scoped `list --effective`, and `enable`, `disable` or
`inherit --field enabled|all` with `--account-id`. Local inherit restores enabled=true; it never
copies user/tool overrides. Local pin/unpin, revision inheritance, removal and package rollback are
unsupported; history recovery belongs to state restore. When library/local entries share a name,
use the full stable skill ID. The Server resolves the original input before the CLI stores an ID.

A mutation reads and confirms a concrete generation-bound request once, unless `--yes` is explicit.
Noninteractive commands without `--yes` return 2; `--dry-run` requires no confirmation and performs
only remote reads. Default waiting is 60 seconds, `--timeout` changes it, and `--no-wait` returns after
acceptance. Known conflicts or target failures still return 1 even if configuration was committed.

Before POST, SQLite retains the exact request and random idempotency key under the Server and user
identity. Transient failure recovery first queries that key, and replays only identical input when
no operation exists. Authentication failures and generation conflicts are not silently retried or
replanned. After an uncertain result, repeat the same command with the same scope to resume it;
`skill status --last` reads the latest locally recorded ID/key without submitting anything. If you
lost the successful output, use `--last` rather than issuing a new rollback. Credentials and source
file bytes are never stored in this journal.

Resolve a retained session-publication or migration conflict by its complete UUID:

```sh
agent-remote skill state resolve CONFLICT_ID --path learning/memory.md --use incoming --dry-run
agent-remote skill state resolve CONFLICT_ID --path learning/memory.md --file ./resolved-memory.md --yes
agent-remote skill state resolve CONFLICT_ID --directory ./resolved-discovery-tree --dry-run
agent-remote skill state resolve CONFLICT_ID --use current --yes
```

Exactly one of `--use current|incoming`, `--file` or `--directory` is required. `--file` requires
`--path` and applies only to ordinary file-content conflicts. Directory/type/deletion and opaque
linked-unit conflicts require a complete saved side or complete directory. Paths are relative to the
saved conflict scope, never inferred from a local directory name. Previews include the saved side
identities. Migration previews list all target/original-package overrides and the exact target
revision plus its modified flag.

Custom content is captured privately before review. `--dry-run` sends only manifest metadata and
uploads no file bytes, saves no plan and creates no mutation journal. Its `metadata_only` candidate
is explicitly unverified and not ready to publish. After one confirmation (or `--yes`), the CLI
uploads the staged bytes to that exact conflict, obtains a verified preview, requires agreement with
the reviewed candidate, then journals and submits the exact request. Content storage is separate
from resolution acceptance. A partial choice returns committed `pending` with exit 1; it saves the
plan but publishes no checkpoint. A complete choice publishes atomically and returns exit 0.
Superseded comparisons return exit 1 and retain the original identity; inspect any replacement first.
`--no-wait` and `--timeout` do not create a deployment queue for these synchronous receipts.

State capture preserves `.git`, LFS-looking text, binary bytes, ordinary relative links, modes and
empty directories. Local defaults are 1 GiB for a file/item input and 10 GiB for a directory, up to
100000 entries; the Server enforces its configured quotas and per-item limits. Uploads use bounded
64 KiB reads, with a one-hour transfer deadline and Ctrl-C support. Absolute links fail because a
local symlink does not encode a runtime dependency identity; choose an existing saved side to retain
that metadata. `--directory` expects a materialized tree and rejects recognized checkpoint export
bundles (`checkpoint.json`, `manifest.json`, `objects/`).

A lost or invalid acceptance response retains an original-key request with explicit unknown
commitment. Repeat the exact command to recover it before reading local files or selecting new
inputs; replay occurs only after an explicit original-key `OPERATION_NOT_FOUND`. `skill status ID`
and `skill status --last` also query the original typed receipt. A recovery `--dry-run` only queries
or previews that original request and does not acknowledge the local journal. A historical receipt
may therefore show committed=true during a later read-only invocation. File bytes and credentials
never enter the recovery journal. Ctrl-C before submission saves no choice; during submission it
returns exit 130 and preserves the unknown original request for recovery.

Migrate retained account state between two explicit revisions of the same installed skill:

```sh
agent-remote skill state migrate my-skill --account-id ACCOUNT_UUID --from-revision r2 --to-revision r3 --dry-run
agent-remote skill state migrate my-skill --account-id ACCOUNT_UUID --from-revision r2 --to-revision r3 --yes
```

Both revisions accept a UUID, `rN`, or positive registration number. The preview fixes both branch
heads/epochs and the directory head, identifies the original or last-migrated source baseline, and
shows target-branch changes separately from directory changes. The source needs a retained published
checkpoint; an uninitialized target starts from its original package. Older target revisions are
supported. Migration preserves pin/enabled rules and effective-use history. Repeating a migration
without a new source checkpoint preserves both heads and records a successful no-change receipt.

One confirmation precedes the exact metadata journal and submission; noninteractive execution needs
`--yes`. A confirmed conflict retains all comparison inputs with an operation ID, publishes no partial
checkpoint and exits 1 (including `--no-wait`). Use `skill state conflicts` and `skill state resolve`
to inspect and resolve it. Successful publication exits 0; a conflicted dry run exits 1 and writes
nothing. Publication is synchronous, so the common waiting flags do not create deployment work.

Unknown acceptance retains the original key: repeat the same command or use `skill status --last`.
Recovery never reselects newer heads. `skill status OPERATION_ID` and `--last` return the immutable
original migration under `data.result`, alongside `current_status`, replacement ID and supersession
reason. Superseded status exits 1. A recovery dry run queries or re-previews the original request
without replaying it or acknowledging the local pending record. Ctrl-C exits 130; once journaled,
the original key remains available for recovery.

Preview and permanently prune unreferenced account state history:

```sh
agent-remote skill state prune my-skill --account-id ACCOUNT_UUID --dry-run
agent-remote skill state prune my-skill --account-id ACCOUNT_UUID --yes
agent-remote skill state prune --scope account-directory --account-id ACCOUNT_UUID --dry-run
agent-remote skill state prune --scope account-directory --account-id ACCOUNT_UUID --all-unreferenced --yes
agent-remote skill status --last
```

The default mode respects retention deadlines. `--all-unreferenced` explicitly ends the waiting
period for eligible history; it does not override live references or protection. Prune may compact
shared directory views and permanently remove recovery history. It traverses and validates every
preview page, displays every candidate, dependency, loss group and compaction before one confirmation,
and submits nothing if the complete plan is blocked or changes. Even `--yes` displays the full review.
An account ID is required; item scope also requires a skill, while account-directory scope forbids one.

Disclosure uses an owner-private temporary file capped at 2 GiB; exceeding that limit fails the whole
preview without truncation or submission. Ordinary HTTP responses retain the 1 MiB limit. The local
journal stores the exact small command and reviewed summary, including its scoped confirmation
credential, but never the full disclosure or file content. That credential is never printed.

If acceptance is unknown, repeat the exact command or use `skill status --last`. Recovery queries the
original key before any new preview and replays only after definite `OPERATION_NOT_FOUND`; it does not
refresh the plan. A recovery dry run is read-only. If no original receipt is found, it reports unknown
acceptance and the saved summary with `disclosure_available=false`, without reconstructing a loss list.

For JSON output, a fresh dry run returns `data.summary`, `disclosure_rows`, complete `rows`, and
`recovering_original_request=false`. Actual commands send review output to stderr and return one
receipt envelope on stdout. `skill status OPERATION_ID` and `--last` return `data.receipt`, complete
`rows`, `disclosure_rows`, and separate `deletion_progress`. Logical acceptance remains `accepted`
even while physical deletion is pending or retrying; `--no-wait` and command `--timeout` do not wait for
disk deletion. Status `--wait --timeout N` bounds the complete receipt/detail/progress query and display.

Ctrl-C exits 130. Before submission it sends no cleanup command; during submission the original key
remains pending for recovery. An interruption or timeout during streamed display may leave incomplete
output; the CLI exits without appending another JSON envelope or waiting for a blocked output pipe.

Inspect current storage independently of any operation:

```sh
agent-remote skill status --storage
agent-remote --json skill status --storage
agent-remote skill info my-skill --account-id ACCOUNT_UUID
agent-remote skill state info CHECKPOINT_UUID
```

`status --storage` reports the current user's Server package/state bytes, separate upload
reservations, configured quotas and retention policy, and physical deletion counts/bytes. It is
mutually exclusive with an operation ID, `--last`, `--wait` and `--timeout`. This read creates no
journal and changes no retention clock. Limits may be below existing usage after an administrator
reduces them; diagnostics preserve the actual counts.

Skill info adds per-revision `retention` and user-wide `storage`; checkpoint info includes the same
fields under `data.checkpoint`. Retention distinguishes `protected`, `waiting`, `due`,
`release_unknown`, and `retired`, preserving the original release timestamp, configured days and
effective deadline. Missing legacy release evidence stays unknown. Protected or retired content has
no effective deadline. `due` only means that history's waiting period elapsed; complete dependency
review and revalidation are still required for cleanup. Older Servers may omit these optional detail
fields; absence is never interpreted as zero usage or unlimited retention.

JSON storage includes the full configured `policy`, `observed_at`, and `deletion` with
`pending_tasks`, `retrying_tasks`, `completed_tasks`, `pending_file_bytes` and
`cumulative_deleted_bytes`. Completed bytes sum the recorded sizes of completed deletion tasks, including later
re-upload and deletion of the same content. This is not a measurement of disk space reclaimed. They are not free disk space. These are user-wide Server
observations, not one skill's storage size or Node/session-copy disk usage. Operation status and its
immutable original receipt remain separate.

`skill list --include-system` adds the read-only system catalog. Effective account queries include
system references and known account-local skills automatically. Account list/info diagnostics show
the exact selected branch, current checkpoint, version selection reason, preparation/expiry state,
separate publication/migration conflict counts and latest IDs, and the last recorded complete content
sync. Conflict counts span all revisions/epochs; they are not a claim that every conflict blocks the
next start. Historical sync times may be unknown. Device system selection remains conditional until
startup verifies the selected Node's capabilities; a catalog entry does not prove deployment.

Use `skill list --session SESSION_ID --effective` to inspect the original saved selection, including
fixed system references, revisions, epochs and starting checkpoints. It accepts `--limit 1..200`
(default 100) and `--cursor ORIGINAL_NAME`; repeat with the displayed next cursor to read more members.
Session scope conflicts with account/tool scope. Deleted sessions with retained snapshot metadata
remain queryable; retired content is labeled separately. Legacy sessions without a snapshot report
`legacy_unrecorded`, never a reconstruction from current rules. Project discovery remains
`not_inspected`, and this view does not prove model loading. Older ordinary list/info responses without
the additive diagnostics remain supported; session queries require the new Server endpoint.

Configuration preparation (`skill add` and rule/remove/rollback commands) now handles Ctrl-C during
user authentication, recovery lookup, source selection, interactive confirmation and package upload.
It exits 130 without submitting a new configuration request. Upload staging or already stored package
content may remain on the Server; interruption does not claim to delete it or cancel an older pending
operation. Interactive selection accepts at most 8192 input bytes and confirmation at most 4096.
Updates share the bounded confirmation input, and their authentication step is cancellable too.

One command-scoped signal listener preserves Ctrl-C across phase transitions and local journal work.
If submission may have begun, JSON retains the original key and explicitly reports unknown commitment;
a verified receipt retains its known commitment. Use `skill status --last` or repeat the original
command to recover. Preparation keeps the existing `SOURCE_INTERRUPTED` code; interrupted acceptance
uses `SKILL_INTERRUPTED`. Human-mode cancellation exits 130 without another terminal message, so an
unread prompt/warning pipe cannot block that exit. JSON attempts to emit the corresponding result envelope; interrupted output may be partial.
Source catalogs and configuration dry-run results use output-only workers. Ctrl-C during their
streamed output exits 130 without appending another JSON envelope; output may be partial. Display
workers cannot create a journal, upload content or submit configuration.

Final configuration receipts and single/batch update results also remain interruptible while stdout
or stderr is blocked. Once Ctrl-C is retained, final output has at most 250 ms to finish before exit
130; no second envelope is appended. This includes the interruption result itself. A verified receipt
stays in the local journal and can be queried with `skill status --last`; output interruption does not
change commitment or submit another request.

State reset/restore, migrate and resolve use the same retained interruption and output boundaries.
Ctrl-C during review or confirmation submits no new state change; uploaded resolution content may
remain stored. JSON reports `SKILL_INTERRUPTED` before result output starts, and human mode exits 130
without another message. Large previews, dry-run output and final receipts remain cancellable on
blocked stdout/stderr. Final output has a 250 ms drain allowance and may be partial; no second envelope
is appended. Interruption during receipt persistence keeps a verified Server result and its original
operation ID, recoverable with `skill status --last`. Unknown acceptance retains the original key.

State list/info/diff/conflicts/export retain Ctrl-C through authenticated reads and final success or
error output. Blocked output has the same 250 ms cancellation allowance and exits 130 without a
second envelope. Export cancellation before publication discards staging; once publication starts,
the CLI observes its result and preserves the verified local bundle even if result output is
interrupted. No remote skill state is changed. General skill queries/status retain their separate behavior.

Global options can precede an explicit command, for example `fclaude --home PATH stop SESSION`.
Use `--` to pass a command name as Claude prompt text: `fclaude --home PATH -- stop`.

For managed Skill sessions, `fclaude stop SESSION [--timeout 60]` prints the durable saving operation
ID and waits up to the specified seconds for publication. Process stop is separate from data saving:
`local_durable`, `upload_pending`, and `persisted` remain visible while Node retries independently.
Use `fclaude stop-status OPERATION_ID [--wait] [--timeout 60]` with the existing device login to query
again, including after session deletion. The operation ID is the original snapshot UUID. A saving
wait returns exit 3 when pending at timeout, 130 on Ctrl+C, or 1 for conflicted/detached/superseded
outcomes requiring review; published returns 0. A plain pending status query returns 0. HTTP or
identity errors return 1. Stopping a legacy session still returns immediately after the request.

When a managed Native account first needs its legacy skills captured, `fclaude` prints the takeover
operation ID and waits for up to 60 seconds. Existing sessions keep running; they must finish normally
before the Node can freeze their shared source. Only a Server receipt explicitly stating that no
session was created permits this wait. After the original takeover commits, the launcher sends the
same creation input once more. It never automatically replays an uncertain creation response.
Timeout exits 3, Ctrl+C exits 130, and recovery/protocol errors exit 1. The operation continues remotely.
After a timeout during creation itself, check `fclaude list` before requesting another new session.

Skill operation status preserves each target’s attempt ID, attempt number and retryable flag in JSON
when supplied by the Server. Terminal output shows the attempt number and retryability; historical
missing metadata is shown as unknown. `preparing` uses the existing bounded read-only wait. These
observations do not themselves retry a deployment.

Use `agent-remote skill retry OPERATION_ID --dry-run` to inspect the original ended transient failed
targets, then `agent-remote skill retry OPERATION_ID --yes` to submit them. The command saves the
original generation, account/attempt IDs and plan digests before sending. It does not reacquire Git
or local sources, change library configuration, or retry successful targets. Superseded operations,
permissions, unresolved conflicts, unsupported targets and unknown historical attempts are rejected.
`--no-wait` returns after acceptance; the default wait is 60 seconds (`--timeout SECONDS`). Timeout
exits 3 and Ctrl+C exits 130 without cancelling remote work. A failed overall operation still exits 1.
If acceptance is uncertain, repeat the same command to recover its exact request, or use
`agent-remote skill status --last` for read-only retry-receipt lookup. A missing retry receipt alone
allows the command to resend the retained request; a changed current plan never authorizes replanning.
Ordinary bound targets remain unsupported until actual Node deployment dispatch is connected; these
commands expose durable retry acceptance without claiming a working deployment executor.

### Recover a retained backend migration

Administrators can request a passive check of an exact failed backend migration:

```sh
agent-remote account recover-runtime ACCOUNT_UUID \
  --original-task migrate_tool_account_runtime:ACCOUNT_UUID:ORIGINAL_UUID \
  --request-id RECOVERY_UUID
agent-remote --json account recovery-status ACCOUNT_UUID --request-id RECOVERY_UUID
```

Use full lowercase UUIDs and retain the independently chosen recovery UUID. The original task ID
comes from the administrator migration API's acceptance response. Repeating the same account,
original task and request ID observes the same recovery task. Status never submits work. Both
commands require an administrator user login; they do not use a device token. After a timeout or
lost acceptance response, query the same request ID before repeating it. A different key may
request another check only after the preceding recovery task has ended.

Default recovery checks existing Node evidence for a completed target migration. Add
`--verify-source` to verify an already completed exact source rollback instead. Source verification
requires the original pre-copy baseline, immutable failure attestation and unchanged content,
permissions and parent ACLs. A successful source check keeps the source backend and marks the
original profile `rolled_back`, reopening its admission gate. Both actions preserve the original
failed task/result and account disable. Neither restarts copying, permission changes or rollback.
Completed previous-boot evidence additionally requires absent current units and cgroups;
incomplete migrations remain blocked. No backend capability is enabled.

The selected action is immutable for a request UUID. Source verification uses a version-2 binding
with `action: "verify_source"`. Its JSON output has `schema_version: 2`,
`source_restoration_confirmed`, and `target_completion_confirmed: false`. Submission failures
retain that action and use `source_restoration_confirmed: null`; an unsuccessful status query
cannot infer the saved action. Status queries otherwise render the verified saved binding.

Interrupted backend permission repair uses `account recover-runtime --repair-source` with the
same required `--original-task` and `--request-id` arguments above. The Helper requires the original
completed backup, baseline and proof that all original writers are stopped. It restores source
permissions and records independent repair evidence while preserving the original failed task.
Do not combine `--repair-source` with `--verify-source`. Query `account recovery-status` with the
same request ID after an uncertain reply. JSON uses schema version 3 and
`source_restoration_confirmed`; the account remains disabled if it was disabled before recovery.

Default recovery with `--json` emits one version-1 success document with `request_id`, typed `recovery.binding`,
`recovery.status` and `target_completion_confirmed`. Confirmation refers only to the original
migration, not a newer account state. Submission/query exits 0 when its response is verified,
even if the recovery is pending or failed; inspect the status for the outcome. Input/API/protocol
errors exit 1 (missing required flags exit 2). Human diagnostics use stderr. For default recovery in JSON mode, errors
emit one version-1 envelope on stdout with validated `account_id`, `request_id`, `original_task_id`,
a fixed `error_code`, `message`, `acceptance`, and the exact `next_command` for status lookup.
Unavailable identities and `recovery`/`target_completion_confirmed` are null. Submission preparation
failures are `not_submitted`; explicit HTTP 4xx rejections are `rejected` for that submission only.
Transport errors, 5xx and malformed successful responses leave acceptance `unknown`. Failed status
queries also leave acceptance unknown. Remote error bodies and credential diagnostics are not echoed.

When capture fails after writers stop, `capture_pending` reports `quota_exceeded`,
`insufficient_storage`, `portability_error`, or `capture_failed`. Stop/status waiting returns 1
and prints a snapshot export command using the original operation ID. This does not confirm
local durability. Keep the Node data; after correcting the cause, query the same operation again.
