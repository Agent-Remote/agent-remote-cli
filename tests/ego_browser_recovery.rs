#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_agent-remote");
const SESSION: &str = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";

fn check_existing_binding(command: &str, status: &str, admission: &str, expected: &str) {
    let confirmation = matches!(command, "pause" | "stop" | "revoke" | "resume");
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("cli");
    let store = temporary.path().join("device");
    fs::create_dir_all(home.join("secrets")).unwrap();
    fs::create_dir_all(home.join("bin")).unwrap();
    fs::create_dir(&store).unwrap();
    fs::set_permissions(&store, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let binding = serde_json::json!({
        "id":"8f8aab48-1c87-4f00-9af3-01ec41234567", "ego_browser_device_id":"device-existing",
        "tool_session_id":SESSION, "node_id":"node-test", "status":status,
        "relay_binding_kind":"ego_browser", "authorization_mode":"ego_browser_script_full_trust",
        "release_profile":"community-local-trust", "bridge_protocol_version":"ego-browser-bridge-v1",
        "allowlist_revision":1, "lease_health":"healthy", "generation":3, "binding_generation":3
    });
    let responses = if command == "status" {
        vec![
            serde_json::json!({"data":{"items":[{"id":"device-existing","generation":1,"device_generation":1,"status":"active","release_profile":"community-local-trust"}]}}),
            serde_json::json!({"data":{"items":[binding]}}),
            serde_json::json!({"data":{"enabled":true,"enrollment_enabled":true,"execution_admission":true,"protocol":"ego-browser-bridge-v1"}}),
        ]
    } else if confirmation {
        vec![serde_json::json!({"data":{"items":[binding]}})]
    } else {
        vec![serde_json::json!({"data":binding})]
    };
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 16384];
            let n = stream.read(&mut buffer).unwrap();
            requests.push(
                String::from_utf8_lossy(&buffer[..n])
                    .lines()
                    .next()
                    .unwrap()
                    .to_owned(),
            );
            let body = response.to_string();
            write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
        }
        requests
    });
    let write = |path: &std::path::Path, value: String| {
        fs::write(path, value).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    };
    write(
        &home.join("config.toml"),
        format!("server_url = \"{origin}\"\n"),
    );
    let key: String = format!("user-token:{origin}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || "-_.".contains(c) {
                c
            } else {
                '_'
            }
        })
        .collect();
    write(&home.join("secrets").join(format!("{key}.secret")),serde_json::json!({
        "version":1,"token":{"access_token":"test-access","expires_in":3600,"refresh_token":"test-refresh","refresh_expires_in":2592000},
        "refresh_at":4102444800_u64,"expires_at":4102444800_u64,"session_expires_at":4102444800_u64
    }).to_string());
    write(&store.join("ego-browser-credential.json"),serde_json::json!({
        "version":1,"device_id":"device-existing","server_url":origin,"revision":1,"expires_at_unix":4102444800_u64,
        "release_profile":"community-local-trust","credential_profile":"community_file","device_generation":1
    }).to_string());
    let handoff_path = store.join("ego-browser-active-binding.json");
    write(&handoff_path,serde_json::json!({
        "version":1,"binding_id":"8f8aab48-1c87-4f00-9af3-01ec41234567","generation":3,"device_id":"device-existing",
        "task_space_label":format!("agent-remote:{SESSION}"),"authorization_mode":"ego_browser_script_full_trust","user_confirmation":true
    }).to_string());
    let admission_path = store.join("ego-browser-local-admission.json");
    write(
        &admission_path,
        serde_json::json!({
            "version":1,"state":admission,"device_id":"device-existing","device_generation":1,
            "binding_id":if admission=="open" {Some("8f8aab48-1c87-4f00-9af3-01ec41234567")} else {None},
            "binding_generation":if admission=="open" {Some(3)} else {None},"updated_at_unix":1
        })
        .to_string(),
    );
    let original = fs::read(&admission_path).unwrap();
    let handoff = fs::read(&handoff_path).unwrap();
    let marker = temporary.path().join("device-called");
    let executable = home.join("bin/ego-browser-device");
    fs::write(
        &executable,
        "#!/bin/sh\ntouch \"$TEST_DEVICE_CALLED\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut process = Command::new(CLI);
    process.args(["--json", "ego-browser", command]);
    if confirmation {
        process.arg("8f8aab48-1c87-4f00-9af3-01ec41234567");
    } else if command != "status" {
        process.args([SESSION, "--yes"]);
    }
    let output = process
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &store)
        .env("EGO_BROWSER_DEVICE_HOME", &store)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &executable)
        .env("TEST_DEVICE_CALLED", &marker)
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.success(), command == "status", "{result}");
    assert_eq!(result["next_action"], expected, "{result}");
    if confirmation {
        assert_eq!(result["error_code"], "confirmation_required");
        assert_eq!(result["admission"]["local"], admission);
        if admission != "closed" {
            assert!(result["state"]["connected"].is_null(), "{result}");
            assert!(result["state"]["available"].is_null(), "{result}");
        }
    } else if command != "status" {
        assert_eq!(result["error_code"], "binding_conflict");
    }
    if expected == "pause" && command == "status" {
        assert_eq!(result["error_code"], "admission_disabled");
    }
    assert!(!marker.exists());
    assert_eq!(fs::read(&admission_path).unwrap(), original);
    assert_eq!(fs::read(&handoff_path).unwrap(), handoff);
    assert!(server
        .join()
        .unwrap()
        .iter()
        .all(|request| request.starts_with("GET /api/v1/ego-browser/")));
}

#[test]
fn repeated_claim_and_connect_preserve_active_admission() {
    for command in ["claim", "connect"] {
        check_existing_binding(command, "active", "open", "status");
    }
}

#[test]
fn repeated_claim_preserves_binding_during_connection_handshake() {
    for status in ["pending_device", "connecting", "probing_local_browser"] {
        for command in ["claim", "connect"] {
            check_existing_binding(command, status, "open", "status");
        }
    }
}

#[test]
fn paused_binding_offers_resume_without_claiming_again() {
    for command in ["claim", "connect", "status"] {
        check_existing_binding(command, "paused", "ready", "resume");
    }
}

#[test]
fn closed_active_binding_offers_pause_before_resume() {
    for command in ["claim", "connect", "status"] {
        check_existing_binding(command, "active", "closed", "pause");
    }
}

#[test]
fn connected_status_does_not_request_recovery() {
    check_existing_binding("status", "active", "open", "none");
}

#[test]
fn unconfirmed_lifecycle_reports_observed_admission_without_changing_it() {
    for command in ["pause", "stop", "revoke"] {
        for admission in ["open", "ready", "closed"] {
            check_existing_binding(command, "active", admission, "confirm_lifecycle");
        }
    }
    check_existing_binding("resume", "paused", "ready", "confirm_full_trust");
}
