#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use serde_json::{json, Value};
use std::time::{Duration, Instant};
use support::*;

#[test]
fn skill_list_uses_user_token_and_exact_scope_with_lossless_json() {
    let expected = envelope(
        json!({"generation":9007199254740993_i64,"items":[installation()],"local_items":[]}),
    );
    let (url, server) = serve(vec![(200, expected.clone())]);
    let home = home(&url);
    let output = run(
        home.path(),
        &[
            "--json",
            "skill",
            "list",
            "--account-id",
            ACCOUNT,
            "--effective",
        ],
    );
    assert_eq!(json_output(&output, 0), expected);
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/skills?effective=true&account_id={ACCOUNT} HTTP/1.1"
    )));
    assert!(requests[0]
        .to_lowercase()
        .contains("authorization: bearer skill-user-token\r\n"));
}

#[test]
fn skill_info_shows_overrides_provenance_and_scope() {
    let (url, server) = serve(vec![(200, envelope(installation()))]);
    let home = home(&url);
    let output = run(
        home.path(),
        &["skill", "info", "sample", "--tool", "claude"],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    for expected in [
        "Enabled source",
        "Revision source",
        "Retained",
        "tool:claude",
        "inherit",
        REVISION,
    ] {
        assert!(text.contains(expected), "{text}");
    }
    assert!(server.join().unwrap()[0]
        .starts_with("GET /api/v1/skills/installations/sample?tool=claude HTTP/1.1"));
}

#[test]
fn skill_status_wait_returns_original_complete_receipt_once() {
    let pending = operation("pending", "pending");
    let completed = operation("stored", "stored");
    let (url, server) = serve(vec![(200, pending), (200, completed.clone())]);
    let home = home(&url);
    let output = run(
        home.path(),
        &["--json", "skill", "status", OP, "--wait", "--timeout", "5"],
    );
    assert_eq!(json_output(&output, 0), completed);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|r| r.starts_with(&format!("GET /api/v1/skills/operations/{OP} HTTP/1.1"))));
}

#[test]
fn skill_status_preserves_original_target_plan_digest() {
    let mut expected = operation("stored", "stored");
    expected["data"]["targets"][0]["plan_digest"] = json!("a".repeat(64));
    let (url, server) = serve(vec![(200, expected.clone())]);
    let home = home(&url);
    let output = run(home.path(), &["--json", "skill", "status", OP]);
    assert_eq!(json_output(&output, 0), expected);
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn skill_status_timeout_preserves_pending_and_does_not_cancel() {
    let pending = operation("pending", "pending");
    let (url, server) = serve(vec![(200, pending.clone())]);
    let home = home(&url);
    let started = Instant::now();
    let output = run(
        home.path(),
        &["--json", "skill", "status", OP, "--wait", "--timeout", "1"],
    );
    assert_eq!(json_output(&output, 3), pending);
    assert!(started.elapsed() < Duration::from_secs(4));
    assert!(String::from_utf8_lossy(&output.stderr).contains("remote operation continues"));
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn skill_status_partial_failure_and_supersession_remain_failure() {
    for (status, readiness) in [
        ("failed", "unsupported"),
        ("needs_resolution", "needs_resolution"),
        ("superseded", "ready"),
        ("stored", "pending"),
        ("invented", "ready"),
    ] {
        let mut expected = operation(status, readiness);
        if status == "superseded" {
            expected["data"]["replacement_id"] = json!(ACCOUNT);
        }
        let (url, server) = serve(vec![(200, expected.clone())]);
        let home = home(&url);
        // A read-only status query may report pending successfully; --wait owns the timeout code.
        let code = if readiness == "pending" { 0 } else { 1 };
        assert_eq!(
            json_output(&run(home.path(), &["--json", "skill", "status", OP]), code),
            expected
        );
        server.join().unwrap();
    }
}

#[test]
fn skill_server_errors_keep_the_skill_envelope() {
    let expected = json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":"SKILL_MANAGER_DISABLED","message":"skill management API is not enabled","object_id":null,"details":{}}]});
    let (url, server) = serve(vec![(503, expected.clone())]);
    let home = home(&url);
    assert_eq!(
        json_output(&run(home.path(), &["--json", "skill", "list"]), 1),
        expected
    );
    server.join().unwrap();
}

#[test]
fn skill_queries_reject_wrong_schema_and_wrong_operation_receipts() {
    for wrong_operation in [false, true] {
        let mut response = operation("stored", "stored");
        if wrong_operation {
            response["operation_id"] = json!(ACCOUNT);
        } else {
            response["schema_version"] = json!(2);
        }
        let (url, server) = serve(vec![(200, response)]);
        let home = home(&url);
        let result = json_output(&run(home.path(), &["--json", "skill", "status", OP]), 1);
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        server.join().unwrap();
    }
}

#[test]
fn skill_auth_errors_never_print_private_server_messages() {
    let (url, server) = serve(vec![(
        401,
        json!({"error":{"code":"COMMON_UNAUTHORIZED","message":"private-refresh private server detail"}}),
    )]);
    let home = home(&url);
    let output = run(home.path(), &["--json", "skill", "list"]);
    let result = json_output(&output, 1);
    assert_eq!(result["errors"][0]["code"], "COMMON_UNAUTHORIZED");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private server detail"));
    server.join().unwrap();
}

#[test]
fn skill_missing_login_has_stable_json_and_does_not_use_device_auth() {
    let home = tempfile::tempdir().unwrap();
    private(
        &home.path().join("config.toml"),
        "server_url = \"http://127.0.0.1:1\"\nactive_device_id = \"device-only\"\n".to_owned(),
    );
    let result = json_output(&run(home.path(), &["--json", "skill", "list"]), 1);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(result["committed"], false);
}

#[test]
fn skill_invalid_arguments_exit_two_without_credentials() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["skill", "info", "../../private"],
        vec!["skill", "list", "--account-id", ACCOUNT],
        vec![
            "skill",
            "list",
            "--tool",
            "claude",
            "--account-id",
            ACCOUNT,
            "--effective",
        ],
        vec!["skill", "status", "not-uuid"],
        vec!["skill", "status", OP, "--timeout", "2"],
        vec!["skill", "status", OP, "--wait", "--timeout", "0"],
    ] {
        assert_eq!(run(home.path(), &args).status.code(), Some(2), "{args:?}");
    }
}

#[test]
fn skill_terminal_output_escapes_control_characters() {
    let mut item = installation();
    item["name"] = json!("sample\u{1b}[2J\nforged");
    let (url, server) = serve(vec![(
        200,
        envelope(json!({"generation":1,"items":[item]})),
    )]);
    let home = home(&url);
    let output = run(home.path(), &["skill", "list"]);
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("\nforged"));
    server.join().unwrap();
}

#[test]
fn skill_wait_retries_transient_read_failure_within_its_original_deadline() {
    let completed = operation("stored", "stored");
    let (url, server) = serve(vec![
        (200, operation("pending", "pending")),
        (0, Value::Null),
        (200, completed.clone()),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "status", OP, "--wait", "--timeout", "5"]
            ),
            0
        ),
        completed
    );
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn skill_wait_retains_committed_configuration_when_authorization_is_lost() {
    let previous = operation("pending", "pending");
    let (url, server) = serve(vec![
        (200, previous.clone()),
        (
            401,
            json!({"error":{"code":"COMMON_UNAUTHORIZED","message":"private-refresh"}}),
        ),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "status", OP, "--wait", "--timeout", "5"],
        ),
        1,
    );
    assert_eq!(result["operation_id"], OP);
    assert_eq!(result["committed"], true);
    assert_eq!(result["data"], previous["data"]);
    assert_eq!(result["errors"][0]["code"], "COMMON_UNAUTHORIZED");
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn skill_wait_stops_on_malformed_refresh_without_replacing_known_state() {
    let previous = operation("pending", "pending");
    let (url, server) = serve(vec![
        (200, previous.clone()),
        (200, json!({"private":"private-refresh"})),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "status", OP, "--wait", "--timeout", "5"],
        ),
        1,
    );
    assert_eq!(result["data"], previous["data"]);
    assert_eq!(result["committed"], true);
    assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn skill_status_preserves_attempt_metadata_and_shows_retryability() {
    let mut expected = operation("failed", "failed");
    expected["retryable"] = json!(true);
    let target = &mut expected["data"]["targets"][0];
    target["plan_digest"] = json!("a".repeat(64));
    target["attempt_id"] = json!(REVISION);
    target["attempt_number"] = json!(2);
    target["retryable"] = json!(true);
    target["error_code"] = json!("TRANSFER_FAILED");
    for json_mode in [true, false] {
        let (url, server) = serve(vec![(200, expected.clone())]);
        let home = home(&url);
        let args = if json_mode {
            vec!["--json", "skill", "status", OP]
        } else {
            vec!["skill", "status", OP]
        };
        let output = run(home.path(), &args);
        if json_mode {
            assert_eq!(json_output(&output, 1), expected);
        } else {
            assert_eq!(output.status.code(), Some(1));
            let text = String::from_utf8_lossy(&output.stdout);
            assert!(
                text.contains("Attempt")
                    && text.contains("Retryable")
                    && text.contains("TRANSFER_FAILED"),
                "{text}"
            );
        }
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET "));
    }
}

#[test]
fn skill_status_preparing_waits_for_original_attempt_without_resubmitting() {
    let mut pending = operation("preparing", "pending");
    let target = &mut pending["data"]["targets"][0];
    target["plan_digest"] = json!("a".repeat(64));
    target["attempt_id"] = json!(REVISION);
    target["attempt_number"] = json!(2);
    target["retryable"] = json!(false);
    let mut completed = pending.clone();
    completed["status"] = json!("ready");
    completed["data"]["targets"][0]["readiness"] = json!("ready");
    let (url, server) = serve(vec![(200, pending), (200, completed.clone())]);
    let home = home(&url);
    let output = run(
        home.path(),
        &["--json", "skill", "status", OP, "--wait", "--timeout", "5"],
    );
    assert_eq!(json_output(&output, 0), completed);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests.iter().all(|request| request.starts_with("GET ")));
}

#[test]
fn skill_status_rejects_incomplete_or_unsafe_attempt_metadata() {
    for broken in [
        "missing_id",
        "missing_number",
        "zero",
        "digest",
        "unsafe_retry",
        "account",
        "node",
    ] {
        let mut response = operation("failed", "failed");
        let target = &mut response["data"]["targets"][0];
        target["plan_digest"] = json!("a".repeat(64));
        target["attempt_id"] = json!(REVISION);
        target["attempt_number"] = json!(1);
        target["retryable"] = json!(true);
        target["error_code"] = json!("TRANSFER_FAILED");
        match broken {
            "missing_id" => target["attempt_id"] = Value::Null,
            "missing_number" => target["attempt_number"] = Value::Null,
            "zero" => target["attempt_number"] = json!(0),
            "digest" => target["plan_digest"] = json!("not a digest"),
            "account" => target["account_id"] = json!("not an account"),
            "node" => target["node_id"] = json!("not a node"),
            _ => target["error_code"] = json!("AUTHORIZATION_DENIED"),
        }
        let (url, server) = serve(vec![(200, response)]);
        let home = home(&url);
        let result = json_output(&run(home.path(), &["--json", "skill", "status", OP]), 1);
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        assert_eq!(server.join().unwrap().len(), 1);
    }
}
