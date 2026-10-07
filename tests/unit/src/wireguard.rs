// Tests for src/wireguard.rs.

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
#[cfg(any(unix, windows))]
use tempfile::tempdir;

use crate::api::{WireGuardConfigData, WireGuardNodePeerData};

#[cfg(unix)]
use super::show_status;
#[cfg(any(unix, windows))]
use super::write_config;
use super::{generate_private_key, public_key_from_private, render_config};

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
    assert!(rendered.contains("MTU = 1000"));
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

#[cfg(unix)]
#[test]
fn reports_helper_status_and_errors() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempdir().unwrap();
    let paths = crate::config::AppPaths::from_home(dir.path().to_path_buf());
    let missing = show_status(&paths).unwrap_err().to_string();
    assert!(missing.contains("WireGuard helper is missing"));

    fs::create_dir_all(paths.bin_dir()).unwrap();
    let helper = paths.bin_dir().join("agent-remote-wireguard");
    fs::write(&helper, "#!/bin/sh\n[ \"$1\" = status ]\n").unwrap();
    fs::set_permissions(&helper, fs::Permissions::from_mode(0o700)).unwrap();
    show_status(&paths).unwrap();

    fs::write(&helper, "#!/bin/sh\nexit 7\n").unwrap();
    let failed = show_status(&paths).unwrap_err().to_string();
    assert!(failed.contains("WireGuard helper exited"));
}

#[cfg(windows)]
#[test]
fn writes_config_readable_by_local_system() {
    use std::process::Command;

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

    let output = Command::new("icacls.exe")
        .arg(&path)
        .args(["/findsid", "*S-1-5-18"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("agent-remote.conf"));
}
