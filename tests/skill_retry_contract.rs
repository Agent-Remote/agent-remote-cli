#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use rusqlite::Connection;
use serde_json::{json, Value};
use support::*;

const USER: &str = "55555555-5555-4555-8555-555555555555";
const ATTEMPT: &str = "66666666-6666-4666-8666-666666666666";
const NEXT: &str = "77777777-7777-4777-8777-777777777777";
const OTHER: &str = "88888888-8888-4888-8888-888888888888";
const NODE: &str = "99999999-9999-4999-8999-999999999999";

fn user() -> (u16, Value) {
    (200, json!({"data":{"id":USER}}))
}
fn initial() -> Value {
    let mut value = operation("failed", "failed");
    value["retryable"] = json!(true);
    value["data"]["targets"] = json!([
        {"account_id":ACCOUNT,"node_id":NODE,"readiness":"failed","deploy_on_first_use":false,
        "error_code":"TRANSFER_FAILED","plan_digest":"a".repeat(64),"attempt_id":ATTEMPT,
        "attempt_number":1,"retryable":true},
        {"account_id":OTHER,"node_id":NODE,"readiness":"ready","deploy_on_first_use":false,
        "error_code":null,"plan_digest":"b".repeat(64),"attempt_id":OTHER,"attempt_number":1,"retryable":false}
    ]);
    value
}
fn accepted() -> Value {
    let mut value = initial();
    value["status"] = json!("preparing");
    value["retryable"] = json!(false);
    let target = &mut value["data"]["targets"][0];
    target["readiness"] = json!("pending");
    target["retryable"] = json!(false);
    target["error_code"] = Value::Null;
    target["attempt_id"] = json!(NEXT);
    target["attempt_number"] = json!(2);
    value
}
fn ready() -> Value {
    let mut value = accepted();
    value["status"] = json!("ready");
    value["data"]["targets"][0]["readiness"] = json!("ready");
    value
}
fn missing() -> (u16, Value) {
    (
        404,
        json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,
        "errors":[{"code":"OPERATION_NOT_FOUND","message":"retry receipt not found","object_id":null,"details":{}}]}),
    )
}
fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn journal(home: &std::path::Path) -> (String, Option<String>, Value) {
    let db = Connection::open(home.join("state.sqlite3")).unwrap();
    let (state, id, raw): (String, Option<String>, String) = db
        .query_row(
            "SELECT state, operation_id, request_json FROM skill_commands",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    (state, id, serde_json::from_str(&raw).unwrap())
}
fn command() -> Vec<&'static str> {
    vec!["--json", "skill", "retry", OP, "--yes", "--no-wait"]
}

#[test]
fn retry_journals_exact_failed_selection_before_post_and_preserves_generation() {
    let (url, server) = serve(vec![user(), (200, initial()), (200, accepted())]);
    let home = home(&url);
    assert_eq!(json_output(&run(home.path(), &command()), 0), accepted());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[1].starts_with(&format!("GET /api/v1/skills/operations/{OP} HTTP")));
    assert!(requests[2].starts_with(&format!("POST /api/v1/skills/operations/{OP}/retries HTTP")));
    let request = body(&requests[2]);
    assert_eq!(request["expected_generation"], 3);
    assert_eq!(
        request["targets"],
        json!([{"account_id":ACCOUNT,"attempt_id":ATTEMPT}])
    );
    assert_eq!(request.as_object().unwrap().len(), 3);
    let (state, id, saved) = journal(home.path());
    assert_eq!(state, "received");
    assert_eq!(id.as_deref(), Some(OP));
    assert_eq!(saved["command"], "deployment_retry");
    assert_eq!(saved["operation_id"], OP);
    assert_eq!(saved["request"], request);
    assert_eq!(saved["attempts"][0]["plan_digest"], "a".repeat(64));
}

#[test]
fn retry_dry_run_has_no_post_or_pending_journal() {
    let (url, server) = serve(vec![user(), (200, initial())]);
    let home = home(&url);
    let output = json_output(
        &run(home.path(), &["--json", "skill", "retry", OP, "--dry-run"]),
        0,
    );
    assert_eq!(output["status"], "planned");
    assert_eq!(
        output["data"]["request"]["targets"][0]["attempt_id"],
        ATTEMPT
    );
    assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM skill_commands", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn retry_requires_noninteractive_confirmation_and_valid_operation_id() {
    let home = home("http://127.0.0.1:1");
    let result = json_output(&run(home.path(), &["--json", "skill", "retry", OP]), 2);
    assert_eq!(result["errors"][0]["code"], "CONFIRMATION_REQUIRED");
    assert_eq!(
        run(home.path(), &["skill", "retry", "invalid", "--yes"])
            .status
            .code(),
        Some(2)
    );
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn retry_recovers_lost_acceptance_by_retry_key_without_reposting() {
    let (url, server) = serve(vec![
        user(),
        (200, initial()),
        (0, Value::Null),
        (200, accepted()),
    ]);
    let home = home(&url);
    assert_eq!(json_output(&run(home.path(), &command()), 0), accepted());
    let requests = server.join().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    let key = body(&requests[2])["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(requests[3].starts_with(&format!(
        "GET /api/v1/skills/operations/{OP}/retries?key={key} HTTP"
    )));
    assert_eq!(journal(home.path()).0, "received");
}

#[test]
fn missing_retry_receipt_resends_identical_request_without_reselecting_targets() {
    let (url, server) = serve(vec![
        user(),
        (200, initial()),
        (0, Value::Null),
        missing(),
        (200, accepted()),
    ]);
    let home = home(&url);
    assert_eq!(json_output(&run(home.path(), &command()), 0), accepted());
    let requests = server.join().unwrap();
    assert_eq!(body(&requests[2]), body(&requests[4]));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with(&format!("GET /api/v1/skills/operations/{OP} HTTP")))
            .count(),
        1
    );
}

#[test]
fn restarted_retry_and_status_last_recover_original_receipt_before_observing_new_failures() {
    let (url, server) = serve(vec![
        user(),
        (200, initial()),
        (0, Value::Null),
        (0, Value::Null),
        (0, Value::Null),
        user(),
        (200, accepted()),
        user(),
        (200, ready()),
    ]);
    let home = home(&url);
    let first = json_output(&run(home.path(), &command()), 1);
    assert_eq!(first["status"], "unknown");
    let original = journal(home.path());
    assert_eq!(original.0, "pending");
    assert_eq!(
        json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            0
        ),
        accepted()
    );
    assert_eq!(journal(home.path()), original); // Status is read-only even after receipt recovery.
    assert_eq!(json_output(&run(home.path(), &command()), 0), ready());
    let saved = journal(home.path());
    assert_eq!(saved.0, "received");
    assert_eq!(saved.2, original.2);
    let requests = server.join().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    assert!(requests[6].starts_with(&format!("GET /api/v1/skills/operations/{OP}/retries?key=")));
    assert!(requests[8].starts_with(&format!("GET /api/v1/skills/operations/{OP}/retries?key=")));
}

#[test]
fn retry_wait_uses_only_original_operation_gets_and_keeps_successful_targets() {
    let (url, server) = serve(vec![
        user(),
        (200, initial()),
        (200, accepted()),
        (200, ready()),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "retry", OP, "--yes", "--timeout", "3"]
            ),
            0
        ),
        ready()
    );
    let requests = server.join().unwrap();
    assert!(requests[3].starts_with(&format!("GET /api/v1/skills/operations/{OP} HTTP")));
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
}

#[test]
fn retry_refuses_nonretryable_or_unknown_history_without_mutation() {
    for case in [
        "superseded",
        "permission",
        "active",
        "conflict",
        "legacy",
        "duplicate",
        "no_node",
    ] {
        let mut value = initial();
        match case {
            "superseded" => value["data"]["replacement_id"] = json!(NEXT),
            "permission" => {
                value["data"]["targets"][0]["error_code"] = json!("AUTHORIZATION_DENIED")
            }
            "active" => value["data"]["targets"][1]["readiness"] = json!("pending"),
            "conflict" => value["data"]["targets"][1]["readiness"] = json!("needs_resolution"),
            "legacy" => {
                value["data"]["targets"][0]["retryable"] = json!(false);
                value["data"]["targets"][0]["attempt_id"] = Value::Null;
                value["data"]["targets"][0]["attempt_number"] = Value::Null;
            }
            "duplicate" => value["data"]["targets"][1] = value["data"]["targets"][0].clone(),
            "no_node" => value["data"]["targets"][0]["node_id"] = Value::Null,
            _ => unreachable!(),
        }
        let (url, server) = serve(vec![user(), (200, value)]);
        let home = home(&url);
        json_output(&run(home.path(), &command()), 1);
        assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
        let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
        assert_eq!(
            db.query_row("SELECT count(*) FROM skill_commands", [], |r| r
                .get::<_, i64>(0))
                .unwrap(),
            0
        );
    }
}

#[test]
fn malformed_retry_receipts_preserve_uncertain_request_without_automatic_replacement() {
    for case in [
        "identity",
        "generation",
        "predecessor",
        "digest",
        "omission",
        "duplicate",
    ] {
        let mut value = accepted();
        match case {
            "identity" => value["operation_id"] = json!(OTHER),
            "generation" => value["data"]["generation"] = json!(4),
            "predecessor" => value["data"]["targets"][0]["attempt_id"] = json!(ATTEMPT),
            "digest" => value["data"]["targets"][0]["plan_digest"] = json!("c".repeat(64)),
            "omission" => {
                value["data"]["targets"].as_array_mut().unwrap().remove(0);
            }
            "duplicate" => value["data"]["targets"][1] = value["data"]["targets"][0].clone(),
            _ => unreachable!(),
        }
        let (url, server) = serve(vec![user(), (200, initial()), (200, value)]);
        let home = home(&url);
        assert_eq!(
            json_output(&run(home.path(), &command()), 1)["status"],
            "unknown"
        );
        assert_eq!(journal(home.path()).0, "pending");
        assert_eq!(server.join().unwrap().len(), 3);
    }
}

#[test]
fn retry_preserves_full_integer_generation_without_incrementing_configuration() {
    for generation in [9_007_199_254_740_993_i64, i64::MAX] {
        let mut failed = initial();
        let mut receipt = accepted();
        failed["data"]["generation"] = json!(generation);
        receipt["data"]["generation"] = json!(generation);
        let (url, server) = serve(vec![user(), (200, failed), (200, receipt.clone())]);
        let home = home(&url);
        assert_eq!(json_output(&run(home.path(), &command()), 0), receipt);
        let requests = server.join().unwrap();
        assert_eq!(body(&requests[2])["expected_generation"], generation);
    }
}

#[test]
fn retry_timeout_keeps_accepted_identity_and_never_cancels_remote_work() {
    let (url, server) = serve(vec![user(), (200, initial()), (200, accepted())]);
    let home = home(&url);
    let args = ["--json", "skill", "retry", OP, "--yes", "--timeout", "1"];
    assert_eq!(json_output(&run(home.path(), &args), 3), accepted());
    assert_eq!(journal(home.path()).1.as_deref(), Some(OP));
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn interrupted_retry_post_has_durable_request_and_restart_only_recovers_its_receipt() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_with_hook(
        vec![
            user(),
            (200, initial()),
            (0, Value::Null),
            user(),
            (200, accepted()),
        ],
        move |index, request| {
            if index == 2 {
                assert!(request.starts_with("POST "));
                ready_tx.send(body(request)).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&url);
    let mut child = Command::new(BIN)
        .arg("--home")
        .arg(home.path())
        .args(command())
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let posted = ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    let retained = journal(home.path());
    assert_eq!(retained.0, "pending");
    assert_eq!(retained.2["request"], posted);
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("retry did not respect interruption");
    }
    let interrupted = json_output(&child.wait_with_output().unwrap(), 130);
    assert_eq!(interrupted["status"], "unknown");
    assert_eq!(journal(home.path()), retained);
    release_tx.send(()).unwrap();
    assert_eq!(json_output(&run(home.path(), &command()), 0), accepted());
    let requests = server.join().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
    assert_eq!(journal(home.path()).2, retained.2);
}
