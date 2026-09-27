#![cfg(unix)]
#[path = "support/skill_conflicts.rs"]
mod conflicts;
#[path = "support/skill_resolution.rs"]
mod resolution_support;
#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use agent_remote_cli::skills::state_snapshot::{CaptureCancellation, StateLimits, StateSnapshot};
use resolution_support::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use state::*;
use std::path::Path;
use support::*;

fn command(home: &Path, extra: &[&str], code: i32) -> Value {
    let mut args = vec!["--json", "skill", "state", "resolve", OP];
    args.extend(extra);
    let output = run(home, &args);
    assert_eq!(
        output.status.code(),
        Some(code),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    json_output(&output, code)
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
fn input() -> (tempfile::TempDir, StateSnapshot) {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("chosen"), b"after").unwrap();
    let snapshot = StateSnapshot::file(
        &root.path().join("chosen"),
        StateLimits::ITEM,
        &CaptureCancellation::default(),
    )
    .unwrap();
    (root, snapshot)
}

#[test]
fn method_scope_and_confirmation_are_required_before_network_or_journal() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec![],
        vec!["--file", "x"],
        vec!["--path", "x", "--directory", "tree"],
        vec!["--use", "current", "--file", "x", "--path", "x"],
        vec!["--use", "current", "--path", "../x"],
    ] {
        let mut cmd = vec!["skill", "state", "resolve", OP];
        cmd.extend(args);
        assert_eq!(run(home.path(), &cmd).status.code(), Some(2));
    }
    let out = command(home.path(), &["--use", "current"], 2);
    assert_eq!(out["errors"][0]["code"], "CONFIRMATION_REQUIRED");
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn side_preview_and_real_resolution_bind_same_request_and_save_exact_journal() {
    for migration in [false, true] {
        let choice = side(None);
        let mut responses = reads(migration);
        responses.push((200, resolution(migration, choice.clone(), true, true)));
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = command(home.path(), &["--use", "incoming", "--dry-run"], 0);
        assert_eq!(out["data"]["verification"], "verified");
        assert_eq!(out["committed"], false);
        let calls = server.join().unwrap();
        assert_eq!(body(calls.last().unwrap())["dry_run"], true);
        let count: i64 = Connection::open(home.path().join("state.sqlite3"))
            .unwrap()
            .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
        let mut responses = reads(migration);
        responses.extend([
            (200, resolution(migration, choice.clone(), true, true)),
            (200, resolution(migration, choice, true, true)),
        ]);
        // Last receipt is the committed original, not a preview.
        responses.last_mut().unwrap().1 = resolution(migration, side(None), false, true);
        let (url, server) = serve(responses);
        let home = support::home(&url);
        let out = command(home.path(), &["--use", "incoming", "--yes", "--no-wait"], 0);
        assert_eq!(out["status"], "published");
        let calls = server.join().unwrap();
        let before = body(&calls[calls.len() - 2]);
        let after = body(calls.last().unwrap());
        assert_eq!(before["idempotency_key"], after["idempotency_key"]);
        assert_eq!(after["dry_run"], false);
        let (saved, status, id) = journal(home.path());
        let saved: Value = serde_json::from_str(&saved).unwrap();
        assert_eq!(saved["command"], "state_resolution");
        assert_eq!(saved["request"], after);
        assert_eq!(status, "received");
        assert_eq!(id.as_deref(), Some(REVISION));
    }
}

#[test]
fn custom_dry_run_posts_only_manifest_never_creates_upload_or_mutation_record() {
    for migration in [false, true] {
        let (input, snapshot) = input();
        let choice = custom(&snapshot, true);
        let mut responses = reads(migration);
        responses.push((200, metadata(migration, choice.clone(), &snapshot, true)));
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = command(
            home.path(),
            &[
                "--path",
                "sample/memory",
                "--file",
                input.path().join("chosen").to_str().unwrap(),
                "--dry-run",
            ],
            0,
        );
        assert_eq!(out["data"]["verification"], "metadata");
        assert_eq!(out["data"]["preview"]["data"]["content_verified"], false);
        let calls = server.join().unwrap();
        let last = calls.last().unwrap();
        assert!(last.starts_with("POST /api/v1/skills/state/"));
        assert!(last.contains("/content-preview "));
        let payload = body(last);
        assert_eq!(payload["choice"], choice);
        assert_eq!(
            payload["manifest"],
            serde_json::to_value(snapshot.manifest()).unwrap()
        );
        assert!(payload.get("idempotency_key").is_none());
        assert!(payload.get("dry_run").is_none());
        assert!(!calls
            .iter()
            .any(|c| c.contains("/uploads") || c.contains("/resolve ")));
    }
}

#[test]
fn custom_content_is_fixed_before_review_uploaded_then_verified_before_acceptance() {
    for migration in [false, true] {
        let (input, snapshot) = input();
        let choice = custom(&snapshot, true);
        let mut responses = reads(migration);
        let preview_index = responses.len();
        responses.extend([
            (200, metadata(migration, choice.clone(), &snapshot, true)),
            (200, upload(&snapshot)),
            (200, upload(&snapshot)),
            (200, file_receipt(&snapshot)),
            (200, stored(&snapshot)),
            (200, resolution(migration, choice.clone(), true, true)),
            (200, resolution(migration, choice, false, true)),
        ]);
        let path = input.path().join("chosen");
        let changed = path.clone();
        let (url, server) = serve_with_hook(responses, move |index, _| {
            if index == preview_index {
                std::fs::write(&changed, b"changed since preview").unwrap();
            }
        });
        let home = home(&url);
        command(
            home.path(),
            &[
                "--path",
                "sample/memory",
                "--file",
                path.to_str().unwrap(),
                "--yes",
            ],
            0,
        );
        let calls = server.join().unwrap();
        let bytes = calls.iter().find(|c| c.starts_with("PUT ")).unwrap();
        assert_eq!(bytes.split_once("\r\n\r\n").unwrap().1, "after");
        let actual = body(calls.last().unwrap());
        assert_eq!(actual["choice"]["file_tree_digest"], snapshot.tree_digest());
        let (saved, _, _) = journal(home.path());
        assert!(!saved.contains("changed since preview"));
        assert!(!saved.contains(path.to_str().unwrap()));
    }
}

#[test]
fn incomplete_choice_is_saved_as_pending_without_claiming_publication() {
    for migration in [false, true] {
        let choice = side(Some("sample/memory"));
        let mut responses = reads(migration);
        responses.extend([
            (200, resolution(migration, choice.clone(), true, false)),
            (200, resolution(migration, choice, false, false)),
        ]);
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = command(
            home.path(),
            &["--path", "sample/memory", "--use", "incoming", "--yes"],
            1,
        );
        assert_eq!(out["status"], "pending");
        assert_eq!(out["committed"], true);
        assert_eq!(out["data"]["result"]["result_checkpoint_id"], Value::Null);
        server.join().unwrap();
        assert_eq!(journal(home.path()).1, "received");
    }
}

#[test]
fn mismatched_verified_custom_candidate_stops_before_journal_and_real_resolve() {
    let (input, snapshot) = input();
    let choice = custom(&snapshot, true);
    let mut responses = reads(false);
    let mut verified = resolution(false, choice.clone(), true, true);
    verified["data"]["result_tree_digest"] = json!("e".repeat(64));
    responses.extend([
        (200, metadata(false, choice, &snapshot, true)),
        (200, upload(&snapshot)),
        (200, upload(&snapshot)),
        (200, file_receipt(&snapshot)),
        (200, stored(&snapshot)),
        (200, verified),
    ]);
    let (url, server) = serve(responses);
    let home = home(&url);
    command(
        home.path(),
        &[
            "--path",
            "sample/memory",
            "--file",
            input.path().join("chosen").to_str().unwrap(),
            "--yes",
        ],
        1,
    );
    let calls = server.join().unwrap();
    assert_eq!(body(calls.last().unwrap())["dry_run"], true);
    let count: i64 = Connection::open(home.path().join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn lost_acceptance_recovers_original_key_without_reselecting_or_resubmitting() {
    for migration in [false, true] {
        let choice = side(None);
        let preview = resolution(migration, choice.clone(), true, true);
        let accepted = resolution(migration, choice, false, true);
        let mut responses: Vec<_> = reads(migration)
            .into_iter()
            .map(|(code, v)| {
                if code == 200 {
                    Response::Json(v)
                } else {
                    Response::Rejected(code, v)
                }
            })
            .collect();
        responses.extend([
            Response::Json(preview),
            Response::Disconnect,
            Response::Json(if migration {
                receipt(accepted)
            } else {
                accepted
            }),
        ]);
        let (url, server) = serve_raw(responses, |_| {});
        let home = home(&url);
        let out = command(home.path(), &["--use", "incoming", "--yes"], 0);
        assert_eq!(out["operation_id"], REVISION);
        let calls = server.join().unwrap();
        let posted = calls
            .iter()
            .filter(|c| c.starts_with("POST "))
            .collect::<Vec<_>>();
        assert_eq!(posted.len(), 2);
        let key = body(posted[1])["idempotency_key"]
            .as_str()
            .unwrap()
            .to_owned();
        assert!(calls
            .last()
            .unwrap()
            .contains(&format!("resolution-operations?key={key}")));
        assert_eq!(journal(home.path()).1, "received");
    }
}

#[test]
fn original_custom_request_survives_restart_missing_input_and_exact_replay() {
    for migration in [false, true] {
        let (input, snapshot) = input();
        let path = input.path().join("chosen");
        let choice = custom(&snapshot, true);
        let accepted = resolution(migration, choice.clone(), false, true);
        let mut forged = accepted.clone();
        forged["data"]["result_tree_digest"] = json!("f".repeat(64));
        let mut responses = reads(migration);
        responses.extend([
            (200, metadata(migration, choice.clone(), &snapshot, true)),
            (200, upload(&snapshot)),
            (200, upload(&snapshot)),
            (200, file_receipt(&snapshot)),
            (200, stored(&snapshot)),
            (200, resolution(migration, choice, true, true)),
            (200, forged),
            user(),
            (404, conflicts::rejection("OPERATION_NOT_FOUND")),
            (200, accepted.clone()),
            user(),
            (
                200,
                if migration {
                    receipt(accepted)
                } else {
                    accepted
                },
            ),
        ]);
        let (url, server) = serve(responses);
        let home = home(&url);
        let args = [
            "--path",
            "sample/memory",
            "--file",
            path.to_str().unwrap(),
            "--yes",
        ];
        let unknown = command(home.path(), &args, 1);
        assert_eq!(unknown["status"], "unknown");
        assert_eq!(unknown["errors"][0]["details"]["commit_state"], "unknown");
        let first = journal(home.path());
        assert_eq!(first.1, "pending");
        std::fs::remove_file(&path).unwrap();
        command(home.path(), &args, 0);
        let final_record = journal(home.path());
        assert_eq!(first.0, final_record.0);
        assert_eq!(final_record.1, "received");
        let status = json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            0,
        );
        assert_eq!(status["operation_id"], REVISION);
        let calls = server.join().unwrap();
        let submits = calls
            .iter()
            .filter(|c| c.contains("/resolve ") && !body(c)["dry_run"].as_bool().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(submits.len(), 2);
        assert_eq!(body(submits[0]), body(submits[1]));
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.contains("/content-preview "))
                .count(),
            1
        );
    }
}

#[test]
fn dry_run_recovery_queries_original_receipt_without_acknowledging_local_pending_record() {
    let choice = side(None);
    let accepted = resolution(false, choice.clone(), false, true);
    let mut forged = accepted.clone();
    forged["data"]["result_tree_digest"] = json!("f".repeat(64));
    let mut responses = reads(false);
    responses.extend([
        (200, resolution(false, choice, true, true)),
        (200, forged),
        user(),
        (200, accepted),
    ]);
    let (url, server) = serve(responses);
    let home = home(&url);
    command(home.path(), &["--use", "incoming", "--yes"], 1);
    let before = journal(home.path());
    let result = command(home.path(), &["--use", "incoming", "--dry-run"], 0);
    assert_eq!(result["committed"], true);
    assert_eq!(journal(home.path()), before);
    let calls = server.join().unwrap();
    assert!(calls
        .last()
        .unwrap()
        .starts_with("GET /api/v1/skills/state/resolution-operations?key="));
}

#[test]
fn plan_cas_rejection_is_definite_and_stale_acceptance_preserves_old_choices() {
    for migration in [false, true] {
        let choice = side(None);
        let mut stale = resolution(migration, choice.clone(), false, false);
        stale["status"] = json!("superseded");
        stale["data"]["status"] = json!("superseded");
        stale["data"]["plan_revision"] = json!(0);
        stale["data"]["choices"] = json!([]);
        stale["data"]["replacement_id"] = json!(SKILL);
        if migration {
            stale["data"]["stale_reasons"] = json!(["target_head_changed"]);
            stale["data"]["recomputation_possible"] = json!(true);
        } else {
            stale["data"]["stale_reason"] = json!("head_changed");
        }
        for rejection in [true, false] {
            let mut responses = reads(migration);
            responses.push((200, resolution(migration, choice.clone(), true, true)));
            responses.push(if rejection {
                (409, conflicts::rejection("PLAN_REVISION_CONFLICT"))
            } else {
                (200, stale.clone())
            });
            let (url, server) = serve(responses);
            let home = home(&url);
            let out = command(home.path(), &["--use", "incoming", "--yes"], 1);
            assert_eq!(out["committed"], !rejection);
            assert_eq!(journal(home.path()).1, "received");
            server.join().unwrap();
        }
    }
}

#[test]
fn status_id_falls_through_only_missing_domains_and_keeps_original_migration_result() {
    for migration in [false, true] {
        let accepted = resolution(migration, side(None), false, true);
        let mut responses = vec![
            (404, conflicts::rejection("OPERATION_NOT_FOUND")),
            (404, conflicts::rejection("OPERATION_NOT_FOUND")),
        ];
        if migration {
            responses.push((404, conflicts::rejection("OPERATION_NOT_FOUND")));
            responses.push((200, receipt(accepted)));
        } else {
            responses.push((200, accepted));
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        let out = json_output(
            &run(
                home.path(),
                &["--json", "skill", "status", REVISION, "--wait"],
            ),
            0,
        );
        assert_eq!(out["operation_id"], REVISION);
        let calls = server.join().unwrap();
        assert!(calls.last().unwrap().starts_with(&format!(
            "GET /api/v1/skills/state/{}resolution-operations/{REVISION} ",
            if migration { "migration/" } else { "" }
        )));
    }
    let (url, server) = serve(vec![
        (404, conflicts::rejection("OPERATION_NOT_FOUND")),
        (404, conflicts::rejection("OPERATION_NOT_FOUND")),
        (403, conflicts::rejection("FORBIDDEN")),
    ]);
    let home = home(&url);
    let out = json_output(
        &run(home.path(), &["--json", "skill", "status", REVISION]),
        1,
    );
    assert_eq!(out["errors"][0]["code"], "FORBIDDEN");
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn forged_preview_identity_or_publication_authority_stops_before_upload() {
    for migration in [false, true] {
        for field in [
            "account_id",
            "current_tree_digest",
            "directory_tree_digest",
            "plan_revision",
            "content_verified",
            "ready_to_publish",
            "target_revision_id",
        ] {
            let (input, snapshot) = input();
            let mut result = metadata(migration, custom(&snapshot, true), &snapshot, true);
            result["data"][field] = match field {
                "account_id" | "target_revision_id" => json!(SKILL),
                "plan_revision" => json!(1),
                "content_verified" | "ready_to_publish" => json!(true),
                _ => json!("f".repeat(64)),
            };
            let mut responses = reads(migration);
            responses.push((200, result));
            let (url, server) = serve(responses);
            let home = home(&url);
            let result = command(
                home.path(),
                &[
                    "--path",
                    "sample/memory",
                    "--file",
                    input.path().join("chosen").to_str().unwrap(),
                    "--yes",
                ],
                1,
            );
            assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
            assert!(!server
                .join()
                .unwrap()
                .iter()
                .any(|c| c.contains("/uploads")));
        }
    }
}

#[test]
fn directory_capture_preserves_all_runtime_data_and_rejects_export_bundle_input() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join(".git")).unwrap();
    std::fs::write(root.path().join(".git/config"), b"runtime").unwrap();
    std::fs::write(
        root.path().join("lfs"),
        b"version https://git-lfs.github.com/spec/v1\n",
    )
    .unwrap();
    let snapshot = StateSnapshot::directory(
        root.path(),
        StateLimits::DIRECTORY,
        &CaptureCancellation::default(),
    )
    .unwrap();
    let mut responses = reads(false);
    responses.push((
        200,
        metadata(false, custom(&snapshot, false), &snapshot, true),
    ));
    let (url, server) = serve(responses);
    let home = home(&url);
    command(
        home.path(),
        &["--directory", root.path().to_str().unwrap(), "--dry-run"],
        0,
    );
    let calls = server.join().unwrap();
    assert_eq!(
        body(calls.last().unwrap())["manifest"]["entries"][0]["path"],
        ".git"
    );
    std::fs::create_dir(root.path().join("objects")).unwrap();
    std::fs::write(root.path().join("manifest.json"), b"{}").unwrap();
    std::fs::write(
        root.path().join("checkpoint.json"),
        br#"{"format":"agent-remote-skill-checkpoint-v1"}"#,
    )
    .unwrap();
    let (url, server) = serve(reads(false));
    let home = support::home(&url);
    let out = command(
        home.path(),
        &["--directory", root.path().to_str().unwrap(), "--dry-run"],
        1,
    );
    assert_eq!(out["errors"][0]["code"], "INVALID_RESOLUTION_SOURCE");
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn custom_confirmation_precedes_upload_and_remains_single_and_cancellable() {
    use std::fs::File;
    use std::io::{Read, Write};
    use std::os::fd::FromRawFd;
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};
    for decision in ["yes", "no", "interrupt"] {
        let (input, snapshot) = input();
        let choice = custom(&snapshot, true);
        let mut responses = reads(false);
        responses.push((200, metadata(false, choice.clone(), &snapshot, true)));
        if decision == "yes" {
            responses.extend([
                (200, upload(&snapshot)),
                (200, upload(&snapshot)),
                (200, file_receipt(&snapshot)),
                (200, stored(&snapshot)),
                (200, resolution(false, choice.clone(), true, true)),
                (200, resolution(false, choice, false, true)),
            ]);
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
                "resolve",
                OP,
                "--path",
                "sample/memory",
                "--file",
                input.path().join("chosen").to_str().unwrap(),
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
                    b"Save this choice and publish if all conflicts are resolved? [y/N] ",
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
        assert_eq!(stderr.matches("Save this choice").count(), 1);
        assert!(stderr.contains("sample/memory"));
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), if decision == "yes" { 9 } else { 3 });
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

#[test]
fn resolution_interruption_distinguishes_planning_from_unknown_acceptance() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    for submitting in [false, true] {
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut responses = reads(false);
        if submitting {
            responses.push((200, resolution(false, side(None), true, true)));
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
                "--json", "skill", "state", "resolve", OP, "--use", "incoming", "--yes",
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
fn unsafe_local_inputs_fail_actionably_without_any_upload() {
    use std::os::unix::fs::symlink;
    for absolute_link in [true, false] {
        let root = tempfile::tempdir().unwrap();
        let (url, server) = serve(reads(false));
        let home = home(&url);
        let args = if absolute_link {
            symlink("/outside/runtime", root.path().join("runtime")).unwrap();
            vec!["--directory", root.path().to_str().unwrap(), "--dry-run"]
        } else {
            let file = std::fs::File::create(root.path().join("oversized")).unwrap();
            file.set_len(1024 * 1024 * 1024 + 1).unwrap();
            vec![
                "--path",
                "sample/memory",
                "--file",
                root.path().to_str().unwrap(),
                "--dry-run",
            ]
        };
        let mut args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        if !absolute_link {
            args[3] = root.path().join("oversized").to_str().unwrap().to_owned();
        }
        let refs: Vec<_> = args.iter().map(String::as_str).collect();
        let out = command(home.path(), &refs, 1);
        assert_eq!(
            out["errors"][0]["code"],
            if absolute_link {
                "RUNTIME_LINK_METADATA_REQUIRED"
            } else {
                "QUOTA_EXCEEDED"
            }
        );
        assert_eq!(server.join().unwrap().len(), 2);
    }
}

#[test]
fn package_batch_skips_pending_resolution_without_touching_its_original_key() {
    let choice = side(None);
    let mut forged = resolution(false, choice.clone(), false, true);
    forged["data"]["result_tree_digest"] = json!("f".repeat(64));
    let mut responses = reads(false);
    responses.extend([
        (200, resolution(false, choice, true, true)),
        (200, forged),
        user(),
        (
            200,
            envelope(json!({"generation":1,"items":[],"local_items":[]})),
        ),
    ]);
    let (url, server) = serve(responses);
    let home = home(&url);
    command(home.path(), &["--use", "incoming", "--yes"], 1);
    let before = journal(home.path());
    json_output(
        &run(
            home.path(),
            &["--json", "skill", "update", "--all", "--yes"],
        ),
        0,
    );
    assert_eq!(journal(home.path()), before);
    let calls = server.join().unwrap();
    assert!(!calls.iter().any(|c| c.contains("resolution-operations")));
    assert!(calls.last().unwrap().starts_with("GET /api/v1/skills"));
}

#[test]
fn ambiguous_missing_key_receipt_never_authorizes_automatic_replay() {
    for misleading in ["retryable", "operation_id"] {
        let choice = side(None);
        let mut forged = resolution(false, choice.clone(), false, true);
        forged["data"]["result_tree_digest"] = json!("f".repeat(64));
        let mut absent = conflicts::rejection("OPERATION_NOT_FOUND");
        absent[misleading] = if misleading == "retryable" {
            json!(true)
        } else {
            json!(REVISION)
        };
        let mut responses = reads(false);
        responses.extend([
            (200, resolution(false, choice, true, true)),
            (200, forged),
            user(),
            (404, absent),
        ]);
        let (url, server) = serve(responses);
        let home = home(&url);
        command(home.path(), &["--use", "incoming", "--yes"], 1);
        let before = journal(home.path());
        let result = command(home.path(), &["--use", "incoming", "--yes"], 1);
        assert_eq!(result["status"], "unknown");
        assert_eq!(journal(home.path()), before);
        assert_eq!(
            server
                .join()
                .unwrap()
                .iter()
                .filter(|c| c.starts_with("POST "))
                .count(),
            2
        );
    }
}

#[test]
fn migration_preview_rejects_missing_target_or_altered_branch_provenance() {
    for field in ["affected", "state_epoch", "checkpoint_id", "changes"] {
        let mut preview = resolution(true, side(None), true, true);
        match field {
            "affected" => preview["data"]["affected"] = json!([]),
            "state_epoch" => preview["data"]["affected"][0][field] = json!(99),
            "checkpoint_id" => preview["data"]["affected"][0][field] = json!(SKILL),
            _ => preview["data"]["affected"][0][field] = json!([]),
        }
        let mut responses = reads(true);
        responses.push((200, preview));
        let (url, server) = serve(responses);
        let home = home(&url);
        command(home.path(), &["--use", "incoming", "--yes"], 1);
        let calls = server.join().unwrap();
        assert_eq!(body(calls.last().unwrap())["dry_run"], true);
        let count: i64 = Connection::open(home.path().join("state.sqlite3"))
            .unwrap()
            .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[path = "skill_state_output/resolution.rs"]
mod output;
#[path = "support/skill_output.rs"]
mod output_support;
