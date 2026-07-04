use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::api::WireGuardConfigData;
use crate::config::AppPaths;

pub fn render_config(config: &WireGuardConfigData) -> String {
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("# PrivateKey = {}", config.private_key_ref),
        format!("Address = {}", config.interface_address),
    ];
    if !config.dns.is_empty() {
        lines.push(format!("DNS = {}", config.dns.join(", ")));
    }
    for peer in &config.peers {
        lines.push(String::new());
        lines.push("[Peer]".to_string());
        lines.push(format!(
            "# Node = {} ({}, {})",
            peer.name, peer.node_id, peer.region_code
        ));
        lines.push(format!("PublicKey = {}", peer.public_key));
        lines.push(format!("Endpoint = {}", peer.endpoint));
        lines.push(format!("AllowedIPs = {}", peer.allowed_ips.join(", ")));
        lines.push(format!(
            "PersistentKeepalive = {}",
            peer.persistent_keepalive_seconds
        ));
    }
    format!(
        "{}
",
        lines.join(
            "
"
        )
    )
}

pub fn write_config(path: &Path, config: &WireGuardConfigData) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, render_config(config))?;
    Ok(())
}

pub fn default_config_path(paths: &AppPaths) -> PathBuf {
    paths.wireguard_config_path()
}

pub fn helper_path(paths: &AppPaths) -> PathBuf {
    let managed = paths.bin_dir().join("agent-remote-wireguard");
    if managed.exists() {
        return managed;
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("agent-remote-wireguard");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    managed
}

pub fn run_helper(paths: &AppPaths, action: &str, config_path: &Path, dry_run: bool) -> Result<()> {
    let helper = helper_path(paths);
    if !helper.exists() {
        bail!(
            "WireGuard helper is missing at {}; run agent-remote doctor --fix after installing the packaged CLI",
            helper.display()
        );
    }
    let mut command = Command::new(helper);
    command.arg(action).arg("--config").arg(config_path);
    if dry_run {
        command.arg("--dry-run");
    }
    let status = command
        .status()
        .context("failed to execute WireGuard helper")?;
    if !status.success() {
        bail!("WireGuard helper exited with {status}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::api::{WireGuardConfigData, WireGuardNodePeerData};

    use super::render_config;

    #[test]
    fn renders_wireguard_config() {
        let rendered = render_config(&WireGuardConfigData {
            device_id: "device-1".to_string(),
            interface_address: "10.77.0.2".to_string(),
            private_key_ref: "local-secret".to_string(),
            dns: vec![],
            peers: vec![WireGuardNodePeerData {
                node_id: "node-1".to_string(),
                name: "us-west".to_string(),
                region_code: "US".to_string(),
                public_key: "node-public".to_string(),
                endpoint: "203.0.113.10:51820".to_string(),
                allowed_ips: vec!["10.42.0.10/32".to_string()],
                persistent_keepalive_seconds: 25,
            }],
        });
        assert!(rendered.contains("[Interface]"));
        assert!(rendered.contains("PublicKey = node-public"));
        assert!(rendered.contains("AllowedIPs = 10.42.0.10/32"));
    }
}
