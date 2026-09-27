#![cfg(unix)]
#[path = "support/skill_migration.rs"]
mod migration;
#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use migration::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use state::*;
use std::path::Path;
use support::*;

fn command(home: &Path, extra: &[&str], code: i32) -> Value {
    let mut args = vec![
        "--json",
        "skill",
        "state",
        "migrate",
        "sample",
        "--account-id",
        ACCOUNT,
        "--from-revision",
        "r1",
        "--to-revision",
        "r2",
    ];
    args.extend(extra);
    json_output(&run(home, &args), code)
}
fn journal(home: &Path) -> (Value, String, Option<String>) {
    let (raw, state, id): (String, String, Option<String>) =
        Connection::open(home.join("state.sqlite3"))
            .unwrap()
            .query_row(
                "SELECT request_json,state,operation_id FROM skill_commands",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
    (serde_json::from_str(&raw).unwrap(), state, id)
}
fn count(home: &Path) -> i64 {
    Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
        .unwrap()
}

#[test]
fn explicit_scope_revisions_and_confirmation_required_before_network() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec![],
        vec!["sample"],
        vec!["sample", "--scope", "account-directory"],
        vec![
            "sample",
            "--account-id",
            ACCOUNT,
            "--from-revision",
            "r0",
            "--to-revision",
            "r2",
        ],
        vec![
            "sample",
            "--account-id",
            ACCOUNT,
            "--from-revision",
            "latest",
            "--to-revision",
            "r2",
        ],
    ] {
        let mut cmd = vec!["skill", "state", "migrate"];
        cmd.extend(args);
        assert_eq!(run(home.path(), &cmd).status.code(), Some(2));
    }
    assert_eq!(
        command(home.path(), &[], 2)["errors"][0]["code"],
        "CONFIRMATION_REQUIRED"
    );
    let same = run(
        home.path(),
        &[
            "--json",
            "skill",
            "state",
            "migrate",
            "sample",
            "--account-id",
            ACCOUNT,
            "--from-revision",
            "1",
            "--to-revision",
            "r1",
            "--yes",
        ],
    );
    assert_eq!(
        json_output(&same, 2)["errors"][0]["code"],
        "INVALID_REQUEST"
    );
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn preview_has_exact_sides_both_baselines_and_no_journal_even_when_conflicted() {
    for conflict in [false, true] {
        let (url, server) = serve(reads(conflict));
        let home = home(&url);
        let out = command(home.path(), &["--dry-run"], i32::from(conflict));
        assert_eq!(out["committed"], false);
        assert_eq!(out["data"]["before"], current());
        assert_eq!(out["data"]["incoming_source"], "source_published");
        assert_eq!(count(home.path()), 0);
        let calls = server.join().unwrap();
        let request = body(&calls[2]);
        assert_eq!(request["selector"]["skill"], SKILL);
        assert_eq!(request["selector"]["from_revision"], OP);
        assert_eq!(request["selector"]["to_revision"], REVISION);
        assert_eq!(request["expected"], current());
        assert_eq!(request["dry_run"], true);
    }
}

#[test]
fn accepted_ready_and_conflict_keep_exact_request_and_status_last() {
    for conflict in [false, true] {
        let status = if conflict { "conflicted" } else { "ready" };
        let mut responses = reads(conflict);
        responses.extend([
            (200, view(false, conflict)),
            user(),
            (200, receipt(conflict, status)),
        ]);
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = command(home.path(), &["--yes", "--no-wait"], i32::from(conflict));
        assert_eq!(out["committed"], true);
        assert_eq!(out["data"]["result"]["status"], status);
        let last = json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            i32::from(conflict),
        );
        assert_eq!(last, out);
        let (saved, state, id) = journal(home.path());
        assert_eq!(state, "received");
        assert_eq!(id.as_deref(), Some(SKILL));
        let calls = server.join().unwrap();
        assert_eq!(saved["command"], "state_migration");
        assert_eq!(saved["request"], body(&calls[3]));
        let mut preview = body(&calls[2]);
        preview["dry_run"] = json!(false);
        assert_eq!(preview, saved["request"]);
        assert!(calls[5].starts_with("GET /api/v1/skills/state/migration/operations?key="));
    }
}

#[test]
fn lost_response_recovers_original_key_without_reselecting_or_reposting() {
    let mut responses: Vec<Response> = reads(false)
        .into_iter()
        .map(|(_, v)| Response::Json(v))
        .collect();
    responses.extend([
        Response::Disconnect,
        Response::Json(receipt(false, "ready")),
    ]);
    let (url, server) = serve_raw(responses, |_| {});
    let home = home(&url);
    command(home.path(), &["--yes"], 0);
    let calls = server.join().unwrap();
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("POST /api/v1/skills/state/migrate "))
            .count(),
        2
    );
    assert!(calls[4].starts_with("GET /api/v1/skills/state/migration/operations?key="));
    assert_eq!(journal(home.path()).1, "received");
}

#[test]
fn only_definite_key_absence_allows_identical_replay() {
    let mut responses: Vec<Response> = reads(false)
        .into_iter()
        .map(|(_, v)| Response::Json(v))
        .collect();
    responses.extend([
        Response::Disconnect,
        Response::Rejected(404, rejected("OPERATION_NOT_FOUND")),
        Response::Json(view(false, false)),
    ]);
    let (url, server) = serve_raw(responses, |_| {});
    let home = home(&url);
    command(home.path(), &["--yes"], 0);
    let calls = server.join().unwrap();
    assert_eq!(body(&calls[3]), body(&calls[5]));
}

#[test]
fn mismatched_acceptance_retains_original_key_and_restart_preserves_supersession() {
    let mut forged = view(false, true);
    forged["data"]["incoming_digest"] = json!("e".repeat(64));
    let mut responses = reads(true);
    responses.extend([(200, forged), user(), (200, receipt(true, "superseded"))]);
    let (url, server) = serve(responses);
    let home = home(&url);
    let unknown = command(home.path(), &["--yes"], 1);
    assert_eq!(unknown["status"], "unknown");
    let retained = journal(home.path());
    assert_eq!(retained.1, "pending");
    assert_eq!(
        unknown["errors"][0]["details"]["idempotency_key"],
        retained.0["request"]["idempotency_key"]
    );
    let out = command(home.path(), &["--yes"], 1);
    assert_eq!(out["status"], "superseded");
    assert_eq!(out["data"]["result"]["status"], "conflicted");
    assert_eq!(out["data"]["replacement_id"], OP);
    assert_eq!(journal(home.path()).1, "received");
    let calls = server.join().unwrap();
    assert!(calls[5].starts_with("GET /api/v1/skills/state/migration/operations?key="));
}

#[test]
fn dry_run_recovery_never_replays_or_acknowledges_pending_journal() {
    for exists in [false, true] {
        let mut forged = view(false, false);
        forged["data"]["result_tree_digest"] = json!("e".repeat(64));
        let mut responses = reads(false);
        responses.extend([(200, forged), user()]);
        if exists {
            responses.push((200, receipt(false, "ready")));
        } else {
            responses.extend([
                (404, rejected("OPERATION_NOT_FOUND")),
                (200, view(true, false)),
            ]);
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        let original = journal(home.path());
        let out = command(home.path(), &["--dry-run"], 0);
        assert_eq!(out["committed"], exists);
        assert_eq!(journal(home.path()), original);
        let calls = server.join().unwrap();
        if !exists {
            let mut request = body(&calls[6]);
            request["dry_run"] = json!(false);
            assert_eq!(request, original.0["request"]);
        }
    }
}

#[test]
fn status_id_routes_to_incremental_receipt_and_preserves_original_conflict() {
    for status in ["conflicted", "ready", "superseded"] {
        let mut responses = vec![(404, rejected("OPERATION_NOT_FOUND")); 4];
        responses.push((200, receipt(true, status)));
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "status",
                    SKILL,
                    "--wait",
                    "--timeout",
                    "5",
                ],
            ),
            i32::from(status != "ready"),
        );
        assert_eq!(out["data"]["result"]["status"], "conflicted");
        assert_eq!(out["data"]["current_status"], status);
        let calls = server.join().unwrap();
        assert!(calls[4].starts_with(&format!(
            "GET /api/v1/skills/state/migration/operations/{SKILL} "
        )));
    }
}

#[test]
fn precondition_rejection_is_final_without_automatic_new_plan() {
    let mut responses = reads(false);
    responses.push((409, rejected("STATE_PRECONDITION_CHANGED")));
    let (url, server) = serve(responses);
    let home = home(&url);
    let out = command(home.path(), &["--yes"], 1);
    assert_eq!(out["errors"][0]["code"], "STATE_PRECONDITION_CHANGED");
    assert_eq!(journal(home.path()).1, "received");
    assert_eq!(server.join().unwrap().len(), 4);
}

#[test]
fn untrusted_receipt_lookup_cannot_authorize_replay() {
    for retryable in [false, true] {
        let mut forged = view(false, false);
        forged["data"]["current_digest"] = json!("e".repeat(64));
        let mut missing = rejected("OPERATION_NOT_FOUND");
        if retryable {
            missing["retryable"] = json!(true);
        } else {
            missing["operation_id"] = json!(OP);
        }
        let mut responses = reads(false);
        responses.extend([(200, forged), user(), (404, missing)]);
        let (url, server) = serve(responses);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        let retained = journal(home.path());
        assert_eq!(command(home.path(), &["--yes"], 1)["status"], "unknown");
        assert_eq!(journal(home.path()), retained);
        assert_eq!(server.join().unwrap().len(), 6);
    }
}

#[test]
fn preview_rejects_forged_identity_sides_diffs_and_partial_results_before_journaling() {
    for field in [
        "identity",
        "side",
        "sequence",
        "checkpoint",
        "partial",
        "path",
    ] {
        let mut preview = view(true, false);
        match field {
            "identity" => preview["data"]["before"]["account_id"] = json!(OP),
            "side" => preview["data"]["base_source"] = json!("last_migrated"),
            "sequence" => preview["data"]["migration_sequence"] = json!(1),
            "checkpoint" => preview["data"]["result_checkpoint_id"] = json!(SECOND),
            "partial" => {
                preview["data"]["conflicts"] = view(true, true)["data"]["conflicts"].clone()
            }
            _ => {
                preview["data"]["changes"][0]["path"] = json!("elsewhere");
                preview["data"]["changes"][0]["current"]["path"] = json!("elsewhere");
            }
        }
        let mut responses = reads(false);
        responses[2] = (200, preview);
        let (url, server) = serve(responses);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        assert_eq!(count(home.path()), 0);
        assert_eq!(server.join().unwrap().len(), 3);
    }
}

#[test]
fn package_update_batch_skips_pending_migration() {
    let mut forged = view(false, false);
    forged["data"]["current_digest"] = json!("e".repeat(64));
    let mut responses = reads(false);
    responses.extend([
        (200, forged),
        user(),
        (200, envelope(json!({"generation":1,"items":[]}))),
    ]);
    let (url, server) = serve(responses);
    let home = home(&url);
    command(home.path(), &["--yes"], 1);
    let retained = journal(home.path());
    json_output(
        &run(
            home.path(),
            &["--json", "skill", "update", "--all", "--yes"],
        ),
        0,
    );
    assert_eq!(journal(home.path()), retained);
    assert_eq!(server.join().unwrap().len(), 6);
}

#[test]
fn interruption_before_and_after_journal_preserves_acceptance_boundary() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    for submitting in [false, true] {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut responses = if submitting {
            reads(false)
        } else {
            vec![user(), (200, envelope(current()))]
        };
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
                "migrate",
                "sample",
                "--account-id",
                ACCOUNT,
                "--from-revision",
                "r1",
                "--to-revision",
                "r2",
                "--yes",
            ])
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        let out = json_output(&child.wait_with_output().unwrap(), 130);
        release_tx.send(()).unwrap();
        server.join().unwrap();
        assert_eq!(out["errors"][0]["code"], "SKILL_INTERRUPTED");
        if submitting {
            assert_eq!(journal(home.path()).1, "pending");
            assert_eq!(out["errors"][0]["details"]["commit_state"], "unknown");
        } else {
            assert_eq!(count(home.path()), 0);
        }
    }
}

#[test]
fn migration_confirmation_is_single_and_cancellable() {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    for decision in ["yes", "no", "interrupt"] {
        let mut responses = reads(false);
        if decision == "yes" {
            responses.push((200, view(false, false)));
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
                "migrate",
                "sample",
                "--account-id",
                ACCOUNT,
                "--from-revision",
                "r1",
                "--to-revision",
                "r2",
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
                if bytes.ends_with(
                    b"Publish this migration to the target branch for new sessions? [y/N] ",
                ) {
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
        assert_eq!(stderr.matches("Publish this migration").count(), 1);
        assert!(stderr.contains("sample/memory"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), if decision == "yes" { 4 } else { 3 });
        if decision == "yes" {
            assert_eq!(result["status"], "ready");
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

#[path = "skill_state_output/migration.rs"]
mod output;
#[path = "support/skill_output.rs"]
mod output_support;
