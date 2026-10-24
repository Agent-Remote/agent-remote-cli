use agent_remote_cli::{
    config::{AppPaths, Config},
    local_state::LocalState,
    secrets::{device_token_key, SecretStore},
};
use serde_json::{json, Value};
use std::{io::Write, sync::mpsc, time::Duration};
#[cfg(unix)]
#[path = "desktop_accounts/binding.rs"]
mod binding;
#[path = "desktop_accounts/fixture.rs"]
mod fixture;
#[path = "desktop_accounts/import.rs"]
mod import;
#[path = "desktop_accounts/runtime_recovery.rs"]
mod runtime_recovery;
#[cfg(unix)]
#[path = "desktop_accounts/session_attach.rs"]
mod session_attach;
#[path = "desktop_accounts/sync.rs"]
mod sync;
#[path = "desktop_accounts/sync_recovery.rs"]
mod sync_recovery;
use fixture::*;

#[test]
fn seed_account_device() {
    let Ok(server) = std::env::var("ACCOUNT_TEST_SERVER") else {
        return;
    };
    let paths = AppPaths::new(None).unwrap();
    let device = std::env::var("ACCOUNT_TEST_DEVICE").unwrap_or_else(|_| "device-test".into());
    Config {
        server_url: Some(server.clone()),
        active_device_id: Some(device.clone()),
    }
    .save(&paths)
    .unwrap();
    SecretStore::new(paths.clone())
        .set_secret(&device_token_key(&server, &device), "account-test-token")
        .unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .set_kv(
            &format!("device-token-refresh-at:{server}:{device}"),
            "4102444800",
        )
        .unwrap();
}

#[test]
fn create_sends_all_exact_cli_fields_and_projects_only_public_metadata() {
    let fixture = Fixture::new(vec![envelope(account("binding_requested"))]);
    let (ok, response) = fixture.invoke("accounts.create", fixture.create());
    assert!(ok, "{response}");
    redact(&response);
    let result = &response["result"];
    assert_eq!(result["operation_id"], "account-operation");
    assert_eq!(result["accepted"], true);
    assert_eq!(result["context"], fixture.context);
    assert!(result["binding"].is_null());
    assert_eq!(result["account"]["status"], "binding_requested");
    let wires = fixture.wires();
    assert_eq!(wires.len(), 1);
    assert!(wires[0].starts_with("POST /api/v1/tool-accounts HTTP/1.1"));
    assert!(wires[0]
        .to_ascii_lowercase()
        .contains("authorization: bearer account-test-token"));
    let body: Value = serde_json::from_str(wires[0].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(
        body,
        json!({"tool_type":"claude","display_name":"测试 account","region_code":"SG","timezone":"Asia/Singapore","locale":"zh_CN.UTF-8","preferred_node_tags":["gpu","preferred:asia"]})
    );
}

#[test]
fn bind_verify_are_task_acceptances_and_disable_is_not_a_session_operation() {
    for (method, path, body) in [
        (
            "accounts.bind",
            "bind/start",
            binding("binding_session_starting"),
        ),
        (
            "accounts.verify",
            "bind/verify",
            binding("binding_verifying"),
        ),
        ("accounts.disable", "disable", account("disabled")),
    ] {
        let fixture = Fixture::new(vec![envelope(body)]);
        let (ok, response) = fixture.invoke(method, fixture.action());
        assert!(ok, "{response}");
        redact(&response);
        let result = &response["result"];
        assert_eq!(result["accepted"], true);
        assert_eq!(result["context"], fixture.context);
        if method == "accounts.disable" {
            assert!(result["binding"].is_null());
            assert_eq!(result["account"]["status"], "disabled");
        } else {
            assert!(result["account"].is_null());
            assert_eq!(
                result["binding"]["task_id"],
                "create_binding_session:account:attempt"
            );
            assert_eq!(result["binding"]["error_code"], "binding_failed");
        }
        let wires = fixture.wires();
        assert_eq!(wires.len(), 1);
        assert!(wires[0].starts_with(&format!(
            "POST /api/v1/tool-accounts/{ACCOUNT_ID}/{path} HTTP/1.1"
        )));
    }
}

#[test]
fn status_returns_two_distinct_observations_without_implying_atomic_consistency() {
    let mut second = binding("binding_verifying");
    second["error"] = Value::Null;
    second["task_id"] = Value::Null;
    let fixture = Fixture::new(vec![
        envelope(account("binding_waiting_user_login")),
        envelope(second),
    ]);
    let (ok, response) = fixture.invoke(
        "accounts.status",
        json!({"expected_context":fixture.context,"account_id":ACCOUNT_ID}),
    );
    assert!(ok, "{response}");
    redact(&response);
    assert_eq!(
        response["result"]["account"]["status"],
        "binding_waiting_user_login"
    );
    assert_eq!(response["result"]["binding"]["status"], "binding_verifying");
    assert!(response["result"]["binding"]["task_id"].is_null());
    let wires = fixture.wires();
    assert_eq!(wires.len(), 2);
    assert!(wires[0].starts_with(&format!("GET /api/v1/tool-accounts/{ACCOUNT_ID} HTTP/1.1")));
    assert!(wires[1].starts_with(&format!(
        "GET /api/v1/tool-accounts/{ACCOUNT_ID}/bind/status HTTP/1.1"
    )));
}

#[test]
fn confirmation_context_and_typed_fields_are_checked_before_any_api_call() {
    let fixture = Fixture::new(vec![]);
    for method in [
        "accounts.create",
        "accounts.bind",
        "accounts.verify",
        "accounts.disable",
    ] {
        let mut input = if method == "accounts.create" {
            fixture.create()
        } else {
            fixture.action()
        };
        input["confirmed"] = json!(false);
        let (ok, response) = fixture.invoke(method, input);
        assert!(!ok);
        assert_eq!(response["error"]["code"], "confirmation_required");
    }
    let mut wrong = fixture.action();
    wrong["expected_context"]["active_device_id"] = json!("wrong-device");
    let (_, response) = fixture.invoke("accounts.bind", wrong);
    assert_eq!(response["error"]["code"], "configuration_changed");
    for field in ["home", "server_url", "active_device_id"] {
        let mut input = fixture.action();
        input["expected_context"]
            .as_object_mut()
            .unwrap()
            .remove(field);
        let (_, response) = fixture.invoke("accounts.verify", input);
        assert_eq!(response["error"]["code"], "invalid_params");
    }
    for field in ["tool", "name", "region", "timezone", "locale", "tags"] {
        let mut input = fixture.create();
        input.as_object_mut().unwrap().remove(field);
        let (_, response) = fixture.invoke("accounts.create", input);
        assert_eq!(response["error"]["code"], "invalid_params");
    }
    for bad in [
        json!("../account"),
        json!("bad\nsecret"),
        json!("x".repeat(129)),
        Value::Null,
    ] {
        let mut input = fixture.action();
        input["account_id"] = bad;
        let (_, response) = fixture.invoke("accounts.disable", input);
        assert_eq!(response["error"]["code"], "invalid_params");
    }
    let mut input = fixture.create();
    input["tags"] = json!(["bad\nsecret"]);
    let (_, response) = fixture.invoke("accounts.create", input);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(fixture.wires().is_empty());
}

#[test]
fn rejection_is_distinct_from_unknown_acceptance_and_neither_is_retried() {
    for (reply, code, http_status) in [
        (
            Reply::json(
                403,
                json!({"error":{"code":"SECRET_SERVER_CODE","message":"secret-binding-error"}}),
            ),
            "account_rejected",
            Some(403),
        ),
        (
            Reply::json(429, json!({"error":"secret-binding-error"})),
            "account_rejected",
            Some(429),
        ),
        (
            Reply::json(500, json!({"error":"secret-binding-error"})),
            "account_outcome_unknown",
            Some(500),
        ),
        (
            Reply {
                status: 200,
                advertised_length: None,
                body: Some(b"{not-json secret-binding-error".to_vec()),
            },
            "account_outcome_unknown",
            Some(200),
        ),
        (
            Reply {
                status: 200,
                advertised_length: None,
                body: None,
            },
            "account_outcome_unknown",
            None,
        ),
    ] {
        let fixture = Fixture::new(vec![reply]);
        let (ok, response) = fixture.invoke("accounts.bind", fixture.action());
        assert!(!ok);
        redact(&response);
        assert_eq!(response["error"]["code"], code);
        assert_eq!(response["error"]["retryable"], false);
        if let Some(status) = http_status {
            assert_eq!(response["error"]["http_status"], status);
        }
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn contradictory_and_future_success_responses_remain_unknown() {
    let mut wrong_id = binding("binding_verifying");
    wrong_id["tool_account_id"] = json!("different-account");
    let mut missing_task = binding("binding_verifying");
    missing_task["task_id"] = Value::Null;
    let mut wrong_fields = account("binding_requested");
    wrong_fields["display_name"] = json!("another name");
    let mut future_backend = account("disabled");
    future_backend["runtime_backend"] = json!("future-backend");
    for (method, body) in [
        ("accounts.verify", binding("future-status")),
        ("accounts.verify", wrong_id),
        ("accounts.verify", missing_task),
        ("accounts.create", wrong_fields),
        ("accounts.disable", account("active")),
        ("accounts.disable", future_backend),
    ] {
        let fixture = Fixture::new(vec![envelope(body)]);
        let input = if method == "accounts.create" {
            fixture.create()
        } else {
            fixture.action()
        };
        let (ok, response) = fixture.invoke(method, input);
        assert!(!ok);
        assert_eq!(response["error"]["code"], "account_outcome_unknown");
        redact(&response);
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn context_changed_while_login_lock_is_held_prevents_submission() {
    let fixture = Fixture::new(vec![]);
    let paths = AppPaths::new(Some(fixture.home.clone())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let guard = runtime
        .block_on(agent_remote_cli::auth::login::lock(&paths))
        .unwrap();
    let mut child = command(&fixture.home).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request("accounts.bind", fixture.action()))
        .unwrap();
    Config {
        server_url: Some("http://127.0.0.1:9".into()),
        active_device_id: Some("changed-device".into()),
    }
    .save(&paths)
    .unwrap();
    drop(guard);
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "configuration_changed");
    assert!(fixture.wires().is_empty());
}

#[test]
fn selected_context_cannot_change_during_remote_post_and_guards_release_afterward() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fixture = Fixture::with_hook(
        vec![envelope(binding("binding_session_starting"))],
        Some(Box::new(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })),
    );
    let paths = AppPaths::new(Some(fixture.home.clone())).unwrap();
    let mut child = command(&fixture.home).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request("accounts.bind", fixture.action()))
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    let changed = Config {
        server_url: Some("http://127.0.0.1:9".into()),
        active_device_id: Some("changed-device".into()),
    };
    assert!(changed.save(&paths).is_err());
    release_tx.send(()).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    changed.save(&paths).unwrap();
    assert_eq!(fixture.wires().len(), 1);
}

#[cfg(unix)]
#[test]
fn sigterm_during_submitted_post_is_unknown_and_never_replayed() {
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let fixture = Fixture::with_hook(
        vec![Reply {
            status: 200,
            advertised_length: None,
            body: None,
        }],
        Some(Box::new(move || {
            started_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        })),
    );
    let mut child = command(&fixture.home).spawn().unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&request("accounts.verify", fixture.action()))
        .unwrap();
    started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGTERM) }, 0);
    let output = child.wait_with_output().unwrap();
    release_tx.send(()).unwrap();
    assert!(!output.status.success());
    assert!(output.stderr.is_empty());
    let response: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(response["error"]["code"], "account_outcome_unknown");
    assert_eq!(response["error"]["retryable"], false);
    assert_eq!(fixture.wires().len(), 1);
    let paths = AppPaths::new(Some(fixture.home.clone())).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _guard = runtime
        .block_on(agent_remote_cli::auth::login::lock(&paths))
        .unwrap();
    Config::load(&paths).unwrap().save(&paths).unwrap();
}

#[test]
fn invalid_read_identity_or_unknown_status_is_not_a_mutation_outcome() {
    for mut body in [account("future-status"), account("active")] {
        if body["status"] == "active" {
            body["id"] = json!("different-account");
        }
        let fixture = Fixture::new(vec![envelope(body)]);
        let (ok, response) = fixture.invoke(
            "accounts.status",
            json!({"expected_context":fixture.context,"account_id":ACCOUNT_ID}),
        );
        assert!(!ok);
        assert_eq!(response["error"]["code"], "account_response_invalid");
        assert_eq!(fixture.wires().len(), 1);
    }
}

#[test]
fn truncated_error_body_preserves_known_rejection_while_success_remains_unknown() {
    for (status, code) in [(403, "account_rejected"), (200, "account_outcome_unknown")] {
        let fixture = Fixture::new(vec![Reply {
            status,
            body: Some(b"truncated".to_vec()),
            advertised_length: Some(1000),
        }]);
        let (ok, response) = fixture.invoke("accounts.verify", fixture.action());
        assert!(!ok);
        assert_eq!(response["error"]["code"], code);
        assert_eq!(response["error"]["http_status"], status);
        assert_eq!(fixture.wires().len(), 1);
    }
}
