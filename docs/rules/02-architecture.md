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
```

Network calls belong in `api.rs`; persistent metadata belongs in `local_state.rs`; secrets belong behind `secrets.rs`. Keep platform-specific behavior isolated and testable. Entry points orchestrate modules but should not duplicate their domain logic.

The device installer accepts only an explicit local `.app` bundle, verifies its fixed bundle ID,
embedded XPC services, code signature, and Gatekeeper assessment, and installs it atomically into
the current user's Applications directory. It must not execute an endpoint or installer path from
project data or an unverified API response.
