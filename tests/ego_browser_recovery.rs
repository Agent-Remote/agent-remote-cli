#![cfg(unix)]

use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

const CLI: &str = env!("CARGO_BIN_EXE_agent-remote");
const SESSION: &str = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";
const BINDING: &str = "8f8aab48-1c87-4f00-9af3-01ec41234567";
const DEVICE: &str = "149aef7a-ba99-4bd5-a0e9-baf1a2635c10";

fn check_existing_binding(command: &str, status: &str, admission: &str, expected: &str) {
    check_binding_command(command, status, admission, expected, &[], vec![]);
}

fn check_binding_command(
    command: &str,
    status: &str,
    admission: &str,
    expected: &str,
    arguments: &[&str],
    request_responses: Vec<(u16, serde_json::Value)>,
) -> serde_json::Value {
    let confirmation = matches!(command, "pause" | "stop" | "revoke" | "resume");
    let identity = matches!(
        command,
        "forget-this-mac" | "re-enroll" | "device-rotate" | "switch-server"
    );
    let deletion = matches!(command, "delete-device" | "delete-binding");
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
        "id":BINDING, "ego_browser_device_id":DEVICE,
        "tool_session_id":SESSION, "node_id":"node-test", "status":status,
        "relay_binding_kind":"ego_browser", "authorization_mode":"ego_browser_script_full_trust",
        "release_profile":"community-local-trust", "bridge_protocol_version":"ego-browser-bridge-v1",
        "allowlist_revision":1, "lease_health":"healthy", "generation":3, "binding_generation":3
    });
    let responses = if command == "status" {
        vec![
            serde_json::json!({"data":{"items":[{"id":DEVICE,"generation":1,"device_generation":1,"status":"active","release_profile":"community-local-trust"}]}}),
            serde_json::json!({"data":{"items":[binding]}}),
            serde_json::json!({"data":{"enabled":true,"enrollment_enabled":true,"execution_admission":true,"protocol":"ego-browser-bridge-v1"}}),
        ]
    } else if command == "delete-device" {
        vec![
            serde_json::json!({"data":{"items":[{"id":DEVICE,"generation":1,"device_generation":1,"status":status,"release_profile":"community-local-trust"}]}}),
        ]
    } else if confirmation
        || matches!(
            command,
            "cancel-request" | "device-rotate" | "delete-binding"
        )
    {
        vec![serde_json::json!({"data":{"items":[binding]}})]
    } else if identity {
        vec![]
    } else {
        vec![serde_json::json!({"data":binding})]
    };
    let responses: Vec<_> = responses
        .into_iter()
        .map(|body| (200, body))
        .chain(request_responses)
        .collect();
    let server = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for (status, response) in responses {
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
            write!(stream,"HTTP/1.1 {status} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
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
        "version":1,"device_id":DEVICE,"server_url":origin,"revision":1,"expires_at_unix":4102444800_u64,
        "release_profile":"community-local-trust","credential_profile":"community_file","device_generation":1
    }).to_string());
    let handoff_path = store.join("ego-browser-active-binding.json");
    write(&handoff_path,serde_json::json!({
        "version":1,"binding_id":BINDING,"generation":3,"device_id":DEVICE,
        "task_space_label":format!("agent-remote:{SESSION}"),"authorization_mode":"ego_browser_script_full_trust","user_confirmation":true
    }).to_string());
    let admission_path = store.join("ego-browser-local-admission.json");
    write(
        &admission_path,
        serde_json::json!({
            "version":1,"state":admission,"device_id":DEVICE,"device_generation":1,
            "binding_id":if admission=="open" {Some("8f8aab48-1c87-4f00-9af3-01ec41234567")} else {None},
            "binding_generation":if admission=="open" {Some(3)} else {None},"updated_at_unix":1
        })
        .to_string(),
    );
    let original = fs::read(&admission_path).unwrap();
    let handoff = fs::read(&handoff_path).unwrap();
    let credential = fs::read(store.join("ego-browser-credential.json")).unwrap();
    let config = fs::read(home.join("config.toml")).unwrap();
    let metadata_path = temporary.path().join("metadata.json");
    write(
        &metadata_path,
        serde_json::json!({
            "device_id":DEVICE,"device_generation":1,"server_url":origin,
            "release_profile":"community-local-trust","credential_profile":"community_file",
            "credential_revision":1,"credential_expires_at_unix":4102444800_u64
        })
        .to_string(),
    );
    let marker = temporary.path().join("device-called");
    let executable = home.join("bin/ego-browser-device");
    fs::write(
        &executable,
        "#!/bin/sh\nif [ \"$1\" = metadata ]; then\ncat \"$TEST_DEVICE_METADATA\"\nexit 0\nfi\ntouch \"$TEST_DEVICE_CALLED\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let mut process = Command::new(CLI);
    process.args(["--json", "ego-browser", command]);
    if confirmation || matches!(command, "cancel-request" | "delete-binding") {
        process.arg(BINDING);
    } else if command == "delete-device" {
        process.arg(DEVICE);
    } else if command != "status" && !identity {
        process.args([SESSION, "--yes"]);
    }
    process.args(arguments);
    let output = process
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &store)
        .env("EGO_BROWSER_DEVICE_HOME", &store)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &executable)
        .env("TEST_DEVICE_CALLED", &marker)
        .env("TEST_DEVICE_METADATA", &metadata_path)
        .output()
        .unwrap();
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.success(), command == "status", "{result}");
    assert_eq!(result["next_action"], expected, "{result}");
    if confirmation || command == "cancel-request" || identity || deletion {
        if (confirmation || command == "cancel-request") && arguments.is_empty() {
            assert_eq!(result["error_code"], "confirmation_required");
        }
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
    assert_eq!(
        fs::read(store.join("ego-browser-credential.json")).unwrap(),
        credential
    );
    assert_eq!(fs::read(home.join("config.toml")).unwrap(), config);
    assert!(!home.join("ego-browser-pending-revocation.json").exists());
    let requests = server.join().unwrap();
    assert!(requests
        .iter()
        .all(|request| request.starts_with("GET /api/v1/ego-browser/")
            || (command == "cancel-request"
                && request.starts_with("POST /api/v1/ego-browser/")
                && request.contains("/cancel"))));
    result
}

#[test]
fn identity_guards_preserve_admission_without_reporting_corrupt_identity() {
    for admission in ["open", "ready", "closed"] {
        for (command, status, arguments, code, action) in [
            (
                "forget-this-mac",
                "active",
                vec![],
                "confirmation_required",
                "confirm_forget",
            ),
            (
                "forget-this-mac",
                "active",
                vec!["--device-id", "ffff"],
                "device_conflict",
                "select_device",
            ),
            (
                "re-enroll",
                "active",
                vec![],
                "confirmation_required",
                "confirm_re_enroll",
            ),
            (
                "device-rotate",
                "active",
                vec![],
                "binding_conflict",
                "stop_existing_binding",
            ),
            (
                "device-rotate",
                "stopped",
                vec![],
                "confirmation_required",
                "confirm_device_rotate",
            ),
            (
                "switch-server",
                "active",
                vec!["--server-url", "https://example.invalid"],
                "server_profile_required",
                "login",
            ),
            (
                "switch-server",
                "active",
                vec!["--server-url", "file:///invalid"],
                "configuration_invalid",
                "login",
            ),
        ] {
            let result =
                check_binding_command(command, status, admission, action, &arguments, vec![]);
            assert_eq!(result["error_code"], code, "{result}");
            assert_ne!(result["state"]["phase"], "identity_corrupt", "{result}");
        }
    }
}

#[test]
fn deletion_preconditions_report_recovery_without_changing_local_admission() {
    for admission in ["open", "ready", "closed"] {
        for arguments in [vec![], vec!["--yes"]] {
            let result = check_binding_command(
                "delete-device",
                "active",
                admission,
                "revoke_device",
                &arguments,
                vec![],
            );
            assert_eq!(result["error_code"], "device_not_revoked");
            for status in [
                "pending_device",
                "connecting",
                "active",
                "paused",
                "stopping",
            ] {
                let result = check_binding_command(
                    "delete-binding",
                    status,
                    admission,
                    "stop_existing_binding",
                    &arguments,
                    vec![],
                );
                assert_eq!(result["error_code"], "binding_not_terminal");
                assert_eq!(
                    result["next_command"],
                    format!("agent-remote ego-browser stop {BINDING}")
                );
            }
        }
        for (command, status, action) in [
            ("delete-device", "revoked", "confirm_device_deletion"),
            ("delete-binding", "stopped", "confirm_binding_deletion"),
            ("delete-binding", "revoked", "confirm_binding_deletion"),
        ] {
            let result = check_binding_command(command, status, admission, action, &[], vec![]);
            assert_eq!(result["error_code"], "confirmation_required");
        }
    }
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

#[test]
fn stale_generation_preserves_observed_admission_and_binding() {
    for command in ["pause", "stop", "revoke", "resume"] {
        for admission in ["open", "ready", "closed"] {
            let result = check_binding_command(
                command,
                if command == "resume" {
                    "paused"
                } else {
                    "active"
                },
                admission,
                "refresh_status",
                &["--binding-generation", "1", "--yes"],
                vec![],
            );
            assert_eq!(result["error_code"], "binding_generation_stale");
            assert_eq!(result["stale"], true);
        }
    }
}

#[test]
fn cancel_request_selection_errors_offer_request_refresh_without_mutation() {
    let request = |id: &str| {
        serde_json::json!({
            "id":id,"request_id":"opaque-request","binding_id":BINDING,
            "generation":3,"binding_generation":3,"sequence":143,
            "message_type":"execute","payload_bytes":10,"status":"accepted","created_at":"2026-09-20T00:00:00Z"
        })
    };
    let first = "aabbccdd-0000-4000-8000-000000000001";
    let second = "aabbccdd-0000-4000-8000-000000000002";
    for (reference, items, code) in [
        (first, vec![], "request_not_active"),
        (
            "aabbccdd0000",
            vec![request(first), request(second)],
            "request_ambiguous",
        ),
        ("invalid", vec![], "invalid_request_reference"),
    ] {
        let result = check_binding_command(
            "cancel-request",
            "active",
            "open",
            "refresh_requests",
            &[reference, "--yes"],
            vec![(200, serde_json::json!({"data":{"items":items}}))],
        );
        assert_eq!(result["error_code"], code);
        assert_eq!(
            result["next_command"],
            format!("agent-remote ego-browser requests {BINDING}")
        );
    }
    for code in [
        "EGO_BROWSER_REQUEST_NOT_FOUND",
        "EGO_BROWSER_REQUEST_NOT_ACTIVE",
    ] {
        let result = check_binding_command(
            "cancel-request",
            "active",
            "open",
            "refresh_requests",
            &["aabbccdd0000", "--yes"],
            vec![
                (200, serde_json::json!({"data":{"items":[request(first)]}})),
                (
                    409,
                    serde_json::json!({"error":{"code":code,"message":"request ended"}}),
                ),
            ],
        );
        assert_eq!(result["error_code"], "request_not_active");
    }
}
