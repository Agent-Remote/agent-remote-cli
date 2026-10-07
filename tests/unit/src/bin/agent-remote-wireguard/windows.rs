// Tests for src/bin/agent-remote-wireguard/windows.rs.

use std::ffi::OsString;
use std::path::PathBuf;

use super::{command_line, tunnel_arguments};

#[test]
fn elevation_targets_tunnel_changes() {
    let config = PathBuf::from(r#"C:\Program Files\Agent Remote\tunnel.conf"#);
    assert!(tunnel_arguments("check", &config, false).is_none());
    assert!(tunnel_arguments("status", &config, false).is_none());
    assert!(tunnel_arguments("up", &config, true).is_none());
    assert_eq!(
        tunnel_arguments("down", &config, false),
        Some(vec![
            OsString::from("down"),
            OsString::from("--config"),
            config.into_os_string(),
        ])
    );
}

#[test]
fn elevation_command_line_quotes_paths() {
    let command_line = command_line(&[
        OsString::from("up"),
        OsString::from("--config"),
        OsString::from(r#"C:\Program Files\Agent "Remote"\tunnel.conf"#),
    ])
    .unwrap();
    let rendered = String::from_utf16(&command_line[..command_line.len() - 1]).unwrap();
    assert_eq!(
        rendered,
        r#""up" "--config" "C:\Program Files\Agent \"Remote\"\tunnel.conf""#
    );
}
