use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::WireGuardConfigData;
use crate::config::AppPaths;

#[allow(dead_code)] // Native execution bridge is platform-specific and fail-closed.
pub(crate) mod broker;
#[allow(dead_code)] // Strict challenge/response contract; transport integration follows.
mod caller_auth;
pub mod configuration;
#[allow(dead_code)] // Shared privileged-execution foundation; bridge integration follows.
mod execution_config;
#[allow(dead_code)]
mod execution_observation;
#[allow(dead_code)] // Internal persistent execution records; no public apply capability yet.
mod execution_request;
#[allow(dead_code)]
mod execution_store;
pub mod inspection;
mod inspection_parser;
#[cfg(target_os = "linux")]
#[allow(dead_code)] // Broker entry point is linked only by the native broker binary.
pub mod linux_broker;
#[allow(dead_code)] // The human binary keeps legacy status; the library uses this machine probe.
mod probe;
mod publication;
#[allow(dead_code)]
pub mod replay;
#[allow(dead_code)]
// Desktop-control uses the library's copy; human status preserves its helper contract.
pub mod status;
#[allow(dead_code)] // Desktop plan is a library API; human up/down keep their existing helper.
pub mod target;
mod tool_snapshot;
pub mod tools;
#[allow(dead_code)]
pub mod tunnel;
mod validation;
#[cfg(windows)]
pub mod windows_broker;

#[cfg(target_os = "macos")]
pub(crate) mod macos_broker;
#[cfg(target_os = "macos")]
pub mod macos_broker_service;

const DEFAULT_MTU: u16 = 1000;

pub fn generate_private_key() -> String {
    STANDARD.encode(StaticSecret::random_from_rng(OsRng).to_bytes())
}

pub fn public_key_from_private(private_key: &str) -> Result<String> {
    let mut decoded = zeroize::Zeroizing::new(Vec::new());
    STANDARD
        .decode_vec(private_key, &mut decoded)
        .context("stored WireGuard private key is not valid base64")?;
    let private_bytes =
        zeroize::Zeroizing::new(<[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| {
            anyhow::anyhow!("stored WireGuard private key must be exactly 32 bytes")
        })?);
    let public_key = PublicKey::from(&StaticSecret::from(*private_bytes));
    Ok(STANDARD.encode(public_key.as_bytes()))
}

pub fn render_config(config: &WireGuardConfigData, private_key: &str) -> Result<String> {
    validation::validate(config, &config.device_id)?;
    public_key_from_private(private_key)?;
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {private_key}"),
        format!("Address = {}", config.interface_address),
        format!("MTU = {DEFAULT_MTU}"),
    ];
    if !config.dns.is_empty() {
        lines.push(format!("DNS = {}", config.dns.join(", ")));
    }
    for peer in &config.peers {
        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!("PublicKey = {}", peer.public_key));
        lines.push(format!("Endpoint = {}", peer.endpoint));
        lines.push(format!("AllowedIPs = {}", peer.allowed_ips.join(", ")));
        lines.push(format!(
            "PersistentKeepalive = {}",
            peer.persistent_keepalive_seconds
        ));
    }
    Ok(format!(
        "{}
",
        lines.join(
            "
"
        )
    ))
}

#[allow(dead_code)] // Public safe file writer also exercised by library unit tests.
pub fn write_config(path: &Path, config: &WireGuardConfigData, private_key: &str) -> Result<()> {
    let rendered = render_config(config, private_key)?;
    let plan = publication::inspect(path)?;
    let canceled = std::sync::atomic::AtomicBool::new(false);
    let mut target = publication::PreparedOutput::prepare(&plan, &canceled)?;
    target.publish(&rendered, &canceled).map_err(Into::into)
}

pub fn default_config_path(paths: &AppPaths) -> PathBuf {
    paths.wireguard_config_path()
}

/// Human presentation for the same read-only service used by desktop-control.
pub fn check_config(paths: &AppPaths, path: &Path, dry_run: bool) -> Result<()> {
    let result = inspection::check(paths, Some(path))?;
    if result.config.state != "ready" {
        bail!(
            "WireGuard configuration check failed ({})",
            result.config.state
        );
    }
    let tunnel = result
        .tools
        .get(1)
        .context("WireGuard tunnel tool inspection is unavailable")?;
    if tunnel.state != "available" {
        bail!("WireGuard tunnel tool is {}", tunnel.state);
    }
    let tool = tunnel
        .path
        .as_ref()
        .context("WireGuard tunnel tool path is unavailable")?;
    crate::terminal::success_line("WireGuard configuration is readable");
    crate::terminal::Details::new()
        .field("Config", result.config.path.display())
        .field("Tunnel tool", tool.display())
        .render();
    if dry_run {
        crate::terminal::note("Read-only check; no tunnel command was executed.");
    }
    Ok(())
}

pub fn helper_path(paths: &AppPaths) -> PathBuf {
    // Development-only hook for contract tests. Release builds always use the
    // managed sibling and never accept a caller-selected helper path.
    if cfg!(debug_assertions) {
        if let Some(override_path) = std::env::var_os("AGENT_REMOTE_WIREGUARD_HELPER") {
            let path = PathBuf::from(override_path);
            if path.is_file() {
                return path;
            }
        }
    }
    let managed = crate::platform::managed_binary(&paths.bin_dir(), "agent-remote-wireguard");
    if managed.exists() {
        return managed;
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = crate::platform::managed_binary(parent, "agent-remote-wireguard");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    managed
}

pub fn run_helper(paths: &AppPaths, action: &str, config_path: &Path, dry_run: bool) -> Result<()> {
    run_helper_inner(paths, action, config_path, dry_run, false)
}

/// Execute the packaged helper from desktop-control. Environment overrides
/// used by the human CLI are removed so a reviewed tool snapshot cannot be
/// silently replaced between planning and submission.
#[allow(dead_code)]
pub fn run_helper_machine(
    paths: &AppPaths,
    action: &str,
    config_path: &Path,
    dry_run: bool,
) -> Result<()> {
    run_helper_inner(paths, action, config_path, dry_run, true)
}

fn run_helper_inner(
    paths: &AppPaths,
    action: &str,
    config_path: &Path,
    dry_run: bool,
    machine: bool,
) -> Result<()> {
    let helper = helper_path(paths);
    if !helper.exists() {
        bail!(
            "WireGuard helper is missing at {}; run agent-remote doctor --fix after installing the packaged CLI",
            helper.display()
        );
    }
    if machine {
        // The desktop-control path is a reviewed machine operation.  Reject
        // common caller-controlled link and permission replacement forms
        // before starting the helper.  This is a boundary check only; it does
        // not grant elevation or prove that a protected broker is installed.
        validate_machine_helper(&helper)?;
    }
    let mut command = Command::new(helper);
    command.arg(action).arg("--config").arg(config_path);
    if dry_run {
        command.arg("--dry-run");
    }
    if machine {
        command
            .env_remove("AGENT_REMOTE_WG")
            .env_remove("AGENT_REMOTE_WG_QUICK")
            .env_remove("AGENT_REMOTE_WIREGUARD")
            .env_remove("AGENT_REMOTE_SUDO");
    }
    // The helper is also called by the JSON desktop-control process. Capture
    // both streams so terminal presentation can never corrupt its stdout
    // envelope; the human CLI reports the stable exit error below.
    let status = command
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to execute WireGuard helper")?;
    ensure_helper_succeeded(status)
}

fn validate_machine_helper(path: &Path) -> Result<()> {
    anyhow::ensure!(
        path.is_absolute(),
        "WireGuard machine helper path is not absolute"
    );
    let metadata = std::fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect WireGuard helper {}", path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file() && !metadata.file_type().is_symlink(),
        "WireGuard machine helper is not a regular file"
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        anyhow::ensure!(
            metadata.nlink() == 1,
            "WireGuard machine helper is hard-linked"
        );
        anyhow::ensure!(
            metadata.mode() & 0o022 == 0,
            "WireGuard machine helper is writable by another principal"
        );
        anyhow::ensure!(
            metadata.mode() & 0o111 != 0,
            "WireGuard machine helper is not executable"
        );
    }
    Ok(())
}

pub fn show_status(paths: &AppPaths) -> Result<()> {
    let helper = helper_path(paths);
    if !helper.exists() {
        bail!(
            "WireGuard helper is missing at {}; run agent-remote doctor --fix after installing the packaged CLI",
            helper.display()
        );
    }
    let status = Command::new(helper)
        .arg("status")
        .status()
        .context("failed to execute WireGuard helper")?;
    ensure_helper_succeeded(status)
}

fn ensure_helper_succeeded(status: ExitStatus) -> Result<()> {
    if !status.success() {
        bail!("WireGuard helper exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/src/wireguard.rs"]
mod tests;
