use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use rand_core::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::api::WireGuardConfigData;
use crate::config::AppPaths;

pub fn generate_private_key() -> String {
    STANDARD.encode(StaticSecret::random_from_rng(OsRng).to_bytes())
}

pub fn public_key_from_private(private_key: &str) -> Result<String> {
    let decoded = STANDARD
        .decode(private_key)
        .context("stored WireGuard private key is not valid base64")?;
    let private_bytes: [u8; 32] = decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("stored WireGuard private key must be exactly 32 bytes"))?;
    let public_key = PublicKey::from(&StaticSecret::from(private_bytes));
    Ok(STANDARD.encode(public_key.as_bytes()))
}

pub fn render_config(config: &WireGuardConfigData, private_key: &str) -> String {
    let mut lines = vec![
        "[Interface]".to_string(),
        format!("PrivateKey = {private_key}"),
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

pub fn write_config(path: &Path, config: &WireGuardConfigData, private_key: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, render_config(config, private_key))?;
    set_owner_only_permissions(path)?;
    Ok(())
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<()> {
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
    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use tempfile::tempdir;

    use crate::api::{WireGuardConfigData, WireGuardNodePeerData};

    use super::{generate_private_key, public_key_from_private, render_config, write_config};

    #[test]
    fn renders_wireguard_config() {
        let private_key = STANDARD.encode([7_u8; 32]);
        let rendered = render_config(
            &WireGuardConfigData {
                device_id: "device-1".to_string(),
                interface_address: "10.77.0.2".to_string(),
                _private_key_ref: "local-secret".to_string(),
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
            },
            &private_key,
        );
        assert!(rendered.contains("[Interface]"));
        assert!(rendered.contains(&format!("PrivateKey = {private_key}")));
        assert!(!rendered.contains("# PrivateKey"));
        assert!(rendered.contains("PublicKey = node-public"));
        assert!(rendered.contains("AllowedIPs = 10.42.0.10/32"));
    }

    #[test]
    fn generates_and_derives_canonical_wireguard_keys() {
        let private_key = generate_private_key();
        let public_key = public_key_from_private(&private_key).unwrap();
        assert_eq!(STANDARD.decode(&private_key).unwrap().len(), 32);
        assert_eq!(STANDARD.decode(&public_key).unwrap().len(), 32);
        assert_eq!(public_key_from_private(&private_key).unwrap(), public_key);
    }

    #[cfg(unix)]
    #[test]
    fn writes_owner_only_config() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempdir().unwrap();
        let path = dir.path().join("agent-remote.conf");
        let config = WireGuardConfigData {
            device_id: "device-1".to_string(),
            interface_address: "10.77.0.2".to_string(),
            _private_key_ref: "local-secret".to_string(),
            dns: vec![],
            peers: vec![],
        };
        write_config(&path, &config, &STANDARD.encode([9_u8; 32])).unwrap();
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
