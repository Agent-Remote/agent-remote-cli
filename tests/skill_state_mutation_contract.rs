#![cfg(unix)]

#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use rusqlite::Connection;
use serde_json::{json, Value};
use state::*;
use std::path::Path;
use support::*;

fn user() -> (u16, Value) {
    (200, json!({"data":{"id":SECOND}}))
}
fn current(directory_scope: bool) -> Value {
    json!({"selector":{"account_id":ACCOUNT,"scope":if directory_scope {"account-directory"} else {"item"},"skill":if directory_scope {None} else {Some("sample")}},
        "precondition":{"library_generation":7,"directory_mode":"managed_v1","directory_epoch":4,"directory_head_id":OP,
            "targets":[{"name":"sample","skill_id":SKILL,"origin":"user_library","revision_id":REVISION,"installation_epoch":3,
                "state_id":SECOND,"state_epoch":8,"head_checkpoint_id":OP,"expired":false,"rule":installation()["effective"]}]}})
}
fn receipt(directory_scope: bool, action: &str, preview: bool) -> Value {
    let mut before = current(directory_scope);
    if !directory_scope {
        before["selector"]["skill"] = json!(SKILL);
    }
    let changes =
        json!([{"path":"sample/memory","base":file("sample/memory",b"private"),"current":null}]);
    let mut result = envelope(
        json!({"operation_id":if preview {None} else {Some(OP)},"status":if preview {"preview"} else {"published"},"action":action,
        "before":before,"result_tree_digest":"a".repeat(64),"result_checkpoint_id":if preview {None} else {Some(SECOND)},"changes":changes,
        "branch_changes":[{"skill_id":SKILL,"state_id":SECOND,"checkpoint_id":OP,"baseline_available":true,"changes":changes}],
        "affected":before["precondition"]["targets"],"directory_epoch_advances":directory_scope,"superseded_conflicts":if preview {0} else {2}}),
    );
    result["status"] = json!(if preview { "preview" } else { "published" });
    result["committed"] = json!(!preview);
    result["operation_id"] = json!(if preview { None } else { Some(OP) });
    result
}
fn error(code: &str) -> Value {
    json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":code,"message":"rejected","object_id":null,"details":{}}]})
}
fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn journal(home: &Path) -> (String, String, Option<String>) {
    Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row(
            "SELECT request_json,state,operation_id FROM skill_commands",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}
fn run_state(home: &Path, extra: &[&str], code: i32) -> Value {
    let mut args = vec!["--json", "skill", "state"];
    args.extend(extra);
    json_output(&run(home, &args), code)
}

#[test]
fn reset_restore_require_explicit_scopes_and_noninteractive_confirmation() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["reset"],
        vec!["restore", "sample", "--account-id", ACCOUNT, "--yes"],
        vec![
            "reset",
            "sample",
            "--account-id",
            ACCOUNT,
            "--checkpoint",
            OP,
            "--yes",
        ],
        vec![
            "reset",
            "sample",
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
            "--yes",
        ],
    ] {
        let mut cmd = vec!["--json", "skill", "state"];
        cmd.extend(args);
        assert_eq!(run(home.path(), &cmd).status.code(), Some(2));
    }
    let result = run_state(
        home.path(),
        &["reset", "sample", "--account-id", ACCOUNT],
        2,
    );
    assert_eq!(result["errors"][0]["code"], "CONFIRMATION_REQUIRED");
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn dry_run_uses_server_preview_including_branch_data_loss_without_journaling() {
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
    ]);
    let home = home(&url);
    let result = run_state(
        home.path(),
        &["reset", "sample", "--account-id", ACCOUNT, "--dry-run"],
        0,
    );
    assert_eq!(result["status"], "preview");
    assert_eq!(result["committed"], false);
    assert_eq!(result["data"]["request"]["selector"]["skill"], SKILL);
    assert_eq!(result["data"]["request"]["dry_run"], true);
    assert_eq!(
        result["data"]["preview"]["branch_changes"][0]["changes"][0]["path"],
        "sample/memory"
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        body(&requests[2])["expected"],
        current(false)["precondition"]
    );
    assert_eq!(body(&requests[2])["dry_run"], true);
    assert_eq!(
        Connection::open(home.path().join("state.sqlite3"))
            .unwrap()
            .query_row("SELECT COUNT(*) FROM skill_commands", [], |r| r
                .get::<_, i64>(0))
            .unwrap(),
        0
    );
}

#[test]
fn reset_and_directory_restore_submit_only_confirmed_exact_plan_and_store_state_receipt() {
    for directory_scope in [false, true] {
        let action = if directory_scope { "restore" } else { "reset" };
        let expected = receipt(directory_scope, action, false);
        let (url, server) = serve(vec![
            user(),
            (200, envelope(current(directory_scope))),
            (200, receipt(directory_scope, action, true)),
            (200, expected.clone()),
        ]);
        let home = home(&url);
        let args = if directory_scope {
            vec![
                "restore",
                "--scope",
                "account-directory",
                "--account-id",
                ACCOUNT,
                "--checkpoint",
                OP,
                "--yes",
                "--no-wait",
            ]
        } else {
            vec![
                "reset",
                "sample",
                "--account-id",
                ACCOUNT,
                "--yes",
                "--timeout",
                "1",
            ]
        };
        assert_eq!(run_state(home.path(), &args, 0), expected);
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        let mut preview = body(&requests[2]);
        let actual = body(&requests[3]);
        assert_eq!(actual["dry_run"], false);
        preview["dry_run"] = json!(false);
        assert_eq!(actual, preview);
        assert_eq!(
            actual["checkpoint_id"],
            if directory_scope {
                json!(OP)
            } else {
                Value::Null
            }
        );
        let (retained, state, operation) = journal(home.path());
        let retained: Value = serde_json::from_str(&retained).unwrap();
        assert_eq!(retained["command"], "state");
        assert_eq!(retained["request"], actual);
        assert_eq!(retained["preview_tree_digest"], "a".repeat(64));
        assert_eq!(state, "received");
        assert_eq!(operation.as_deref(), Some(OP));
    }
}

#[test]
fn lost_state_response_recovers_by_original_key_without_reselecting_or_resubmitting() {
    let expected = receipt(false, "reset", false);
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
        (0, Value::Null),
        (200, expected.clone()),
    ]);
    let home = home(&url);
    assert_eq!(
        run_state(
            home.path(),
            &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
            0
        ),
        expected
    );
    let requests = server.join().unwrap();
    let key = body(&requests[3])["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(requests[4].starts_with(&format!("GET /api/v1/skills/state/operations?key={key} ")));
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        2
    );
    assert_eq!(journal(home.path()).1, "received");
}

#[test]
fn state_precondition_conflict_is_definite_and_never_automatically_replanned() {
    let rejected = error("STATE_PRECONDITION_CHANGED");
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
        (409, rejected.clone()),
    ]);
    let home = home(&url);
    assert_eq!(
        run_state(
            home.path(),
            &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
            1
        ),
        rejected
    );
    assert_eq!(server.join().unwrap().len(), 4);
    let (_, state, op) = journal(home.path());
    assert_eq!(state, "received");
    assert!(op.is_none());
}

#[test]
fn forged_published_tree_or_identity_preserves_unknown_acceptance() {
    for replacement in ["tree", "source", "epoch"] {
        let mut forged = receipt(false, "reset", false);
        match replacement {
            "tree" => forged["data"]["result_tree_digest"] = json!("b".repeat(64)),
            "source" => forged["data"]["before"]["selector"]["skill"] = json!(SECOND),
            _ => forged["data"]["before"]["precondition"]["directory_epoch"] = json!(99),
        }
        let (url, server) = serve(vec![
            user(),
            (200, envelope(current(false))),
            (200, receipt(false, "reset", true)),
            (200, forged),
        ]);
        let home = home(&url);
        let result = run_state(
            home.path(),
            &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
            1,
        );
        assert_eq!(result["status"], "unknown");
        assert_eq!(result["errors"][0]["details"]["commit_state"], "unknown");
        assert_eq!(journal(home.path()).1, "pending");
        server.join().unwrap();
    }
}

#[test]
fn restart_recovers_original_state_request_before_fresh_selection_and_supports_status_last() {
    let mut bad = receipt(false, "reset", false);
    bad["data"]["result_tree_digest"] = json!("b".repeat(64));
    let expected = receipt(false, "reset", false);
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
        (200, bad),
        user(),
        (200, expected.clone()),
        user(),
        (200, expected.clone()),
    ]);
    let home = home(&url);
    run_state(
        home.path(),
        &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
        1,
    );
    let original = journal(home.path()).0;
    assert_eq!(
        run_state(
            home.path(),
            &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
            0
        ),
        expected
    );
    assert_eq!(journal(home.path()).0, original);
    assert_eq!(
        json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            0
        ),
        expected
    );
    let requests = server.join().unwrap();
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        2
    );
    assert!(requests[5].starts_with("GET /api/v1/skills/state/operations?key="));
    assert!(requests[7].starts_with("GET /api/v1/skills/state/operations?key="));
}

#[test]
fn missing_original_receipt_allows_only_identical_replay_and_dry_run_never_replays() {
    for dry_run in [false, true] {
        let mut bad = receipt(false, "restore", false);
        bad["data"]["result_tree_digest"] = json!("b".repeat(64));
        let final_response = receipt(false, "restore", dry_run);
        let (url, server) = serve(vec![
            user(),
            (200, envelope(current(false))),
            (200, receipt(false, "restore", true)),
            (200, bad),
            user(),
            (404, error("OPERATION_NOT_FOUND")),
            (200, final_response),
        ]);
        let home = home(&url);
        run_state(
            home.path(),
            &[
                "restore",
                "sample",
                "--account-id",
                ACCOUNT,
                "--checkpoint",
                OP,
                "--yes",
            ],
            1,
        );
        run_state(
            home.path(),
            &[
                "restore",
                "sample",
                "--account-id",
                ACCOUNT,
                "--checkpoint",
                OP,
                if dry_run { "--dry-run" } else { "--yes" },
            ],
            0,
        );
        let requests = server.join().unwrap();
        let mut old = body(&requests[3]);
        if dry_run {
            old["dry_run"] = json!(true);
        }
        assert_eq!(body(&requests[6]), old);
        assert_eq!(
            journal(home.path()).1,
            if dry_run { "pending" } else { "received" }
        );
    }
}

#[test]
fn status_by_id_uses_state_route_only_after_library_operation_not_found() {
    let expected = receipt(false, "reset", false);
    let (url, server) = serve(vec![
        (404, error("OPERATION_NOT_FOUND")),
        (200, expected.clone()),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(home.path(), &["--json", "skill", "status", OP, "--wait"]),
            0
        ),
        expected
    );
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(&format!("GET /api/v1/skills/operations/{OP} ")));
    assert!(requests[1].starts_with(&format!("GET /api/v1/skills/state/operations/{OP} ")));
}

#[test]
fn pending_state_records_do_not_break_automatic_package_updates() {
    let mut bad = receipt(false, "reset", false);
    bad["data"]["result_tree_digest"] = json!("b".repeat(64));
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
        (200, bad),
        user(),
        (200, envelope(json!({"generation":7,"items":[]}))),
    ]);
    let home = home(&url);
    run_state(
        home.path(),
        &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
        1,
    );
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "update", "--all", "--yes"],
        ),
        0,
    );
    assert_eq!(result["data"]["items"], json!([]));
    assert_eq!(journal(home.path()).1, "pending");
    server.join().unwrap();
}

#[test]
fn state_status_fallback_keeps_the_original_wait_deadline() {
    use std::time::Duration;
    let (url, server) = serve_with_hook(
        vec![(404, error("OPERATION_NOT_FOUND")), (0, Value::Null)],
        |index, _| {
            if index == 1 {
                std::thread::sleep(Duration::from_millis(1500));
            }
        },
    );
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "status", OP, "--wait", "--timeout", "1"],
        ),
        1,
    );
    assert_eq!(result["errors"][0]["code"], "SKILL_STATUS_UNAVAILABLE");
    server.join().unwrap();
}

#[test]
fn interruption_distinguishes_unsubmitted_preview_from_unknown_state_acceptance() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    for submitting in [false, true] {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut responses = vec![user(), (200, envelope(current(false)))];
        if submitting {
            responses.push((200, receipt(false, "reset", true)));
        }
        let held = responses.len();
        responses.push((0, Value::Null));
        let (url, server) = serve_with_hook(responses, move |index, _| {
            if index == held {
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        });
        let home = home(&url);
        let child = Command::new(BIN)
            .arg("--home")
            .arg(home.path())
            .args([
                "--json",
                "skill",
                "state",
                "reset",
                "sample",
                "--account-id",
                ACCOUNT,
                "--yes",
            ])
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        let result = json_output(&child.wait_with_output().unwrap(), 130);
        release_tx.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(result["errors"][0]["code"], "SKILL_INTERRUPTED");
        if submitting {
            assert_eq!(result["status"], "unknown");
            assert_eq!(journal(home.path()).1, "pending");
            assert_eq!(result["errors"][0]["details"]["commit_state"], "unknown");
        } else {
            assert_eq!(result["status"], "failed");
            assert_eq!(
                Connection::open(home.path().join("state.sqlite3"))
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM skill_commands", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[test]
fn dry_run_of_already_accepted_pending_record_only_queries_original_receipt() {
    let mut bad = receipt(false, "reset", false);
    bad["data"]["result_tree_digest"] = json!("b".repeat(64));
    let original = receipt(false, "reset", false);
    let (url, server) = serve(vec![
        user(),
        (200, envelope(current(false))),
        (200, receipt(false, "reset", true)),
        (200, bad),
        user(),
        (200, original.clone()),
    ]);
    let home = home(&url);
    run_state(
        home.path(),
        &["reset", "sample", "--account-id", ACCOUNT, "--yes"],
        1,
    );
    assert_eq!(
        run_state(
            home.path(),
            &["reset", "sample", "--account-id", ACCOUNT, "--dry-run"],
            0
        ),
        original
    );
    assert_eq!(journal(home.path()).1, "pending");
    assert_eq!(
        server
            .join()
            .unwrap()
            .iter()
            .filter(|r| r.starts_with("POST "))
            .count(),
        2
    );
}

#[test]
fn interactive_confirmation_is_single_and_ctrl_c_does_not_wait_for_stdin() {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    for decision in ["yes", "no", "interrupt"] {
        let mut responses = vec![
            user(),
            (200, envelope(current(false))),
            (200, receipt(false, "reset", true)),
        ];
        if decision == "yes" {
            responses.push((200, receipt(false, "reset", false)));
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        let (mut master_fd, mut slave_fd) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master_fd,
                    &mut slave_fd,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let mut master = unsafe { File::from_raw_fd(master_fd) };
        let slave = unsafe { File::from_raw_fd(slave_fd) };
        let mut child = Command::new(BIN)
            .arg("--home")
            .arg(home.path())
            .args([
                "--json",
                "skill",
                "state",
                "reset",
                "sample",
                "--account-id",
                ACCOUNT,
            ])
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdin(Stdio::from(slave))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = child.stderr.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut ready = Some(ready_tx);
            let mut bytes = Vec::new();
            let mut byte = [0];
            while stderr.read(&mut byte).unwrap() > 0 {
                bytes.push(byte[0]);
                assert!(bytes.len() < 128 * 1024);
                if bytes.ends_with(b"Publish this state change for new sessions? [y/N] ") {
                    ready.take().unwrap().send(()).unwrap();
                }
            }
            bytes
        });
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        let expected = match decision {
            "yes" => {
                master.write_all(b"yes\n").unwrap();
                0
            }
            "no" => {
                master.write_all(b"no\n").unwrap();
                1
            }
            _ => {
                assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
                130
            }
        };
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
            panic!("confirmation did not stop");
        }
        let result = json_output(&child.wait_with_output().unwrap(), expected);
        let stderr = String::from_utf8(reader.join().unwrap()).unwrap();
        assert_eq!(stderr.matches("Publish this state change").count(), 1);
        assert!(stderr.contains("sample/memory"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), if decision == "yes" { 4 } else { 3 });
        if decision == "yes" {
            assert_eq!(result["status"], "published");
        } else {
            assert_eq!(
                Connection::open(home.path().join("state.sqlite3"))
                    .unwrap()
                    .query_row("SELECT COUNT(*) FROM skill_commands", [], |r| r
                        .get::<_, i64>(0))
                    .unwrap(),
                0
            );
        }
    }
}

#[path = "skill_state_output/state_mutation.rs"]
mod output;
#[path = "support/skill_output.rs"]
mod output_support;
