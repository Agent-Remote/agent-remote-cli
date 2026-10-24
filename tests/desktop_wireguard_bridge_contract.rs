use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn invoke(home: &Path, params: Value) -> (bool, Value) {
    let request = json!({
        "protocol_version": 1,
        "request_id": "bridge-status",
        "method": "wireguard.bridge.status",
        "params": params,
    });
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(&request).unwrap().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.stderr.is_empty());
    let mut text = String::new();
    std::io::Cursor::new(output.stdout)
        .read_to_string(&mut text)
        .unwrap();
    (
        output.status.success(),
        serde_json::from_str(&text).unwrap(),
    )
}

#[test]
fn bridge_status_is_read_only_and_fail_closed_until_native_broker_exists() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent-home");
    let (ok, response) = invoke(&home, json!({"expected_home": home}));
    assert!(ok, "{response}");
    let result = &response["result"];
    assert_eq!(result.as_object().unwrap().len(), 9);
    assert_eq!(result["version"], 1);
    assert_eq!(result["home"], home.to_string_lossy().as_ref());
    assert!(matches!(
        result["platform"].as_str(),
        Some("linux" | "macos" | "windows")
    ));
    assert!(matches!(
        result["state"].as_str(),
        Some("unsupported" | "unavailable")
    ));
    assert_eq!(result["installation"], "not_installed");
    assert_eq!(result["approval"], "not_requested");
    assert_eq!(result["protocol"], "unsupported");
    assert_eq!(result["authentication"], "unavailable");
    assert_eq!(result["execution"], "unavailable");
    assert!(!home.exists());
}

#[test]
fn bridge_status_rejects_unknown_fields_and_wrong_home_without_initializing_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent-home");
    let (ok, response) = invoke(&home, json!({"expected_home": home, "request_admin": true}));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    let (ok, response) = invoke(
        &home,
        json!({"expected_home": temp.path().join("other-home")}),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "configuration_changed");
    assert!(!home.exists());
}
