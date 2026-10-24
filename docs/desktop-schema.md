# Desktop command schema, version 1

`agent-remote --desktop-schema` and `fclaude --desktop-schema` are standalone,
side-effect-free invocations. They describe the built Clap command tree, including
inherited arguments, value types/actions, defaults and choices. Discovery does not
read configuration or credentials, run external tools, contact a server, or create
state. Clap remains authoritative for argument combinations. The schema does not
advertise that a corresponding desktop operation or GUI workflow exists.

The root contains `schema_version`, `executable`, `cli_version`, and `commands`.
Each command has an exact `path` array relative to the executable, `description`,
`arguments`, `has_subcommands`, and optionally `platforms`:

```json
{"path":["device","launch"],"description":"Verify credentials and launch the installed Agent Remote Device app.","arguments":[],"has_subcommands":false,"platforms":["macos"]}
```

The example omits inherited arguments for brevity. `platforms` uses Rust host-OS
names: `linux`, `macos`, and `windows`. It declares the operating systems on which
the client command has explicit implementation support. It never describes a remote
Node, server, Agent runtime, or browser's operating system. This is additive metadata
in schema version 1; readers must accept its absence from older CLI versions.

An absent field means **not declared**, not universal support or known rejection.
The CLI does not emit an empty array. Declarations apply only to the exact command
path and executable; do not inherit a parent declaration or infer one from help
text. Parent command groups currently have no declaration. Platform support alone
does not establish installation, credentials, permissions, server capabilities,
runtime availability, or successful operation. GUI execution must still check
those separate requirements.

The currently audited declarations are deliberately narrow:

| Exact command path after `agent-remote` | Declared host platforms | Implementation evidence |
| --- | --- | --- |
| `device install`, `device uninstall`, `device status`, `device launch`, `device diagnose` | `macos` | Each corresponding `src/device.rs` entry calls `ensure_macos` before platform work. |
| `ego-browser upgrade` | `macos` | `select_bridge_installer("upgrade", ...)` always selects `ManagedBootstrap`; `run_managed_bridge_bootstrap` rejects other operating systems. |
| `wireguard config` | `linux`, `macos`, `windows` | Shared config rendering with Unix owner-only permissions and Windows ACL handling in `src/platform.rs`. |
| `wireguard check`, `wireguard status`, `wireguard up`, `wireguard down` | `linux`, `macos`, `windows` | Packaged helper provides Windows WireGuard/service/elevation handling and Unix `wg-quick`/`wg` handling. |

All other commands currently omit `platforms`. In particular:

- `device revoke` and `device rotate-token` call the control plane and shared
  credential APIs; their parent's macOS description is not a host restriction.
- `node install` probes **the remote SSH target** for Linux. That probe does not
  restrict the desktop/CLI host to Linux.
- `ego-browser setup` and `repair` can select an already installed external script,
  while other local operations can delegate to an independently supplied Device
  Client. The official local Bridge component currently targets macOS, but this
  schema does not turn dependency packaging into an unconditional CLI host gate.
- `ego-browser status`, `list`, `requests`, `cancel-request`, `delete-device` and
  `delete-binding` have control-plane/cache paths; do not disable the whole family
  because the managed local Bridge is a macOS component.
- `fclaude` presently has no per-command host declarations. Its own command tree
  must never inherit the main CLI's path metadata.

Contract tests exercise both real executable discovery paths using an absent
temporary `AGENT_REMOTE_HOME`. They verify exact restricted paths, explicit helper
platforms, non-inheritance, unknown omissions and no state initialization.
