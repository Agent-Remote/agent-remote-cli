#![cfg(unix)]
#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use serde_json::{json, Value};
use support::*;

fn storage() -> Value {
    json!({"scope":"user","observed_at":"2026-09-23T00:00:00Z","package_bytes":300,"state_bytes":500,
        "package_reserved_bytes":20,"state_reserved_bytes":40,"node_storage":"not_observed",
        "policy":{"package_file_bytes":10,"package_bytes":50,"package_entries":5000,"checkpoint_bytes":100,"directory_bytes":1000,"state_entries":100000,
            "user_package_bytes":200,"user_state_bytes":2000,"user_staging_bytes":200,"history_days":7,"archive_days":19,"staging_hours":24},
        "deletion":{"pending_tasks":2,"retrying_tasks":1,"completed_tasks":3,"pending_file_bytes":60,"cumulative_deleted_bytes":900}})
}

fn retention(kind: &str, id: &str) -> Value {
    json!({"kind":kind,"id":id,"observed_at":"2026-09-23T00:00:00Z","retained":true,"state":"due","protected_by":[],"archived":false,
        "retention_days":7,"released_at":"2026-09-01T00:00:00Z","expires_at":"2026-09-08T00:00:00Z"})
}

#[test]
fn storage_status_is_an_independent_read_only_query_with_explicit_user_scope() {
    let (url, server) = serve(vec![(200, envelope(storage())), (200, envelope(storage()))]);
    let home = home(&url);
    let value = json_output(
        &run(home.path(), &["--json", "skill", "status", "--storage"]),
        0,
    );
    assert_eq!(value["data"], storage());
    let text = run(home.path(), &["skill", "status", "--storage"]);
    assert!(text.status.success());
    let display = format!(
        "{}{}",
        String::from_utf8_lossy(&text.stdout),
        String::from_utf8_lossy(&text.stderr)
    );
    assert!(display.contains("Server only") && display.contains("Cumulative deleted bytes"));
    assert!(display.contains("not free disk space") && display.contains("Node disk"));
    assert!(!home.path().join("state.sqlite3").exists());
    assert!(server
        .join()
        .unwrap()
        .iter()
        .all(|r| r.starts_with("GET /api/v1/skills/storage ")));
}

#[test]
fn storage_selection_conflicts_fail_before_network() {
    let home = tempfile::tempdir().unwrap();
    for extra in [
        vec![OP],
        vec!["--last"],
        vec!["--wait"],
        vec!["--timeout", "2"],
    ] {
        let mut args = vec!["skill", "status", "--storage"];
        args.extend(extra);
        assert_eq!(run(home.path(), &args).status.code(), Some(2));
    }
}

#[test]
fn skill_and_checkpoint_info_validate_and_preserve_exact_retention_diagnostics() {
    for local in [false, true] {
        let mut detail = if local { local_skill() } else { installation() };
        detail["storage"] = storage();
        detail["revisions"][0]["retention"] =
            retention(if local { "local_revision" } else { "revision" }, REVISION);
        let (url, server) = serve(vec![(200, envelope(detail.clone()))]);
        let home = home(&url);
        let result = json_output(
            &run(
                home.path(),
                &["--json", "skill", "info", SKILL, "--account-id", ACCOUNT],
            ),
            0,
        );
        assert_eq!(result["data"], detail);
        assert_eq!(server.join().unwrap().len(), 1);
    }
    let mut checkpoint = state::checkpoint(false);
    checkpoint["storage"] = storage();
    checkpoint["retention"] = retention("checkpoint", OP);
    let (url, server) = serve(vec![
        (200, envelope(checkpoint.clone())),
        (200, envelope(checkpoint.clone())),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(home.path(), &["--json", "skill", "state", "info", OP]),
        0,
    );
    assert_eq!(result["data"]["checkpoint"], checkpoint);
    let output = run(home.path(), &["skill", "state", "info", OP]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Complete dependency review"));
    server.join().unwrap();
}

#[test]
fn malformed_storage_or_retention_is_rejected_instead_of_presented_as_authority() {
    for field in [
        "scope",
        "quota",
        "tasks",
        "kind",
        "identity",
        "deadline",
        "days",
        "protection",
    ] {
        let mut detail = installation();
        detail["storage"] = storage();
        detail["revisions"][0]["retention"] = retention("revision", REVISION);
        match field {
            "scope" => detail["storage"]["scope"] = json!("account"),
            "quota" => detail["storage"]["policy"]["user_package_bytes"] = json!(0),
            "tasks" => detail["storage"]["deletion"]["retrying_tasks"] = json!(3),
            "kind" => detail["revisions"][0]["retention"]["kind"] = json!("checkpoint"),
            "identity" => detail["revisions"][0]["retention"]["id"] = json!(OP),
            "deadline" => detail["revisions"][0]["retention"]["expires_at"] = Value::Null,
            "days" => detail["revisions"][0]["retention"]["retention_days"] = json!(30),
            "protection" => {
                detail["revisions"][0]["retention"]["protected_by"] = json!(["active_session"])
            }
            _ => unreachable!(),
        }
        let (url, server) = serve(vec![(200, envelope(detail))]);
        let home = home(&url);
        json_output(&run(home.path(), &["--json", "skill", "info", SKILL]), 1);
        assert_eq!(server.join().unwrap().len(), 1);
    }
}

#[test]
fn older_server_details_do_not_invent_zero_usage_or_retention_deadlines() {
    let detail = installation();
    let (url, server) = serve(vec![(200, envelope(detail.clone()))]);
    let home = home(&url);
    let result = json_output(&run(home.path(), &["--json", "skill", "info", SKILL]), 0);
    assert_eq!(result["data"], detail);
    assert!(result["data"].get("storage").is_none());
    assert!(result["data"]["revisions"][0].get("retention").is_none());
    server.join().unwrap();
}

#[test]
fn storage_query_interrupts_without_mutation_or_journal() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_with_hook(vec![(0, json!({}))], move |_, request| {
        assert!(request.starts_with("GET /api/v1/skills/storage "));
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let home = home(&url);
    let mut child = Command::new(BIN)
        .arg("--home")
        .arg(home.path())
        .args(["--json", "skill", "status", "--storage"])
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("storage query did not interrupt");
    }
    let output = json_output(&child.wait_with_output().unwrap(), 130);
    assert_eq!(output["errors"][0]["code"], "SKILL_INTERRUPTED");
    assert!(!home.path().join("state.sqlite3").exists());
    release_tx.send(()).unwrap();
    assert_eq!(server.join().unwrap().len(), 1);
}
