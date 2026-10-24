use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

fn invoke(home: &Path, method: &str, params: Value) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({
        "protocol_version":1,
        "request_id":"command-diagnostics-test",
        "method":method,
        "params":params
    });
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

#[test]
fn capabilities_advertise_the_versioned_command_projections() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, response) = invoke(
        temp.path().join("home").as_path(),
        "capabilities",
        json!({}),
    );
    assert!(ok, "{response}");
    let operations = response["result"]["operations"].as_array().unwrap();
    for (method, effect, confirmation) in [
        ("status.inspect", "read", None),
        ("doctor.inspect", "read", None),
        ("doctor.repair", "write", Some("exact_request")),
        ("deps.inspect", "read", None),
        ("deps.repair", "write", Some("exact_request")),
        ("ssh.inspect", "read", None),
    ] {
        let operation = operations
            .iter()
            .find(|operation| operation["method"] == method)
            .unwrap_or_else(|| panic!("missing capability {method}"));
        assert_eq!(operation["effect"], effect);
        match confirmation {
            Some(value) => assert_eq!(operation["confirmation"], value),
            None => assert!(operation.get("confirmation").is_none()),
        }
    }
}

#[test]
fn status_and_doctor_observation_are_versioned_and_do_not_initialize_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, status) = invoke(&home, "status.inspect", json!({}));
    assert!(ok, "{status}");
    assert_eq!(status["result"]["schema_version"], 1);
    assert_eq!(status["result"]["operation"], "status.inspect");
    assert_eq!(status["result"]["online"], false);
    assert_eq!(status["result"]["remote"]["server"], "not_checked");
    assert!(!home.exists());

    let (ok, doctor) = invoke(&home, "doctor.inspect", json!({}));
    assert!(ok, "{doctor}");
    assert_eq!(doctor["result"]["schema_version"], 1);
    assert_eq!(doctor["result"]["operation"], "doctor.inspect");
    assert_eq!(doctor["result"]["online"], true);
    assert!(!home.exists());
}

#[test]
fn repair_requires_exact_confirmation_and_home_then_returns_typed_receipts() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("repair-home");
    let expected = std::path::absolute(&home).unwrap();
    let (ok, response) = invoke(&home, "doctor.repair", json!({"expected_home": expected}));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "confirmation_required");
    assert!(!home.exists());

    let (ok, response) = invoke(
        &home,
        "doctor.repair",
        json!({"confirmed":true,"expected_home":expected,"online":false,"deep_check":false,"verify_versions":false}),
    );
    assert!(ok, "{response}");
    assert_eq!(response["result"]["operation"], "doctor.repair");
    assert_eq!(response["result"]["setup"]["complete"], true);
    assert!(home.join("state.sqlite3").exists());

    let deps_home = temp.path().join("deps-home");
    let expected_deps = std::path::absolute(&deps_home).unwrap();
    let (ok, response) = invoke(
        &deps_home,
        "deps.repair",
        json!({"confirmed":true,"expected_home":expected_deps,"verify_versions":false}),
    );
    assert!(ok, "{response}");
    assert_eq!(response["result"]["operation"], "deps.repair");
    assert_eq!(response["result"]["repair"]["complete"], true);
    assert!(deps_home.join("dependencies/manifest.json").exists());
}

#[test]
fn deps_observation_and_ssh_observation_reject_unknown_or_unbound_input() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, response) = invoke(&home, "deps.inspect", json!({"unexpected":true}));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());

    let (ok, response) = invoke(&home, "ssh.inspect", json!({"session_id":"not-a-uuid"}));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!response.to_string().contains("not-a-uuid"));
    assert!(!home.exists());
}
