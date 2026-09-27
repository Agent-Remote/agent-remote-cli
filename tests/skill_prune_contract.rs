#![cfg(unix)]
#[path = "support/skill_prune.rs"]
mod prune;
#[path = "support/skill_cli.rs"]
mod support;

use prune::*;
use rusqlite::Connection;
use serde_json::{json, Value};
use std::path::Path;
use support::{home, json_output, run, ACCOUNT, OP, SKILL};

fn command(home: &Path, extra: &[&str], code: i32) -> Value {
    let mut args = vec![
        "--json",
        "skill",
        "state",
        "prune",
        "sample",
        "--account-id",
        ACCOUNT,
    ];
    args.extend(extra);
    let output = run(home, &args);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(CONFIRMATION));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(CONFIRMATION));
    json_output(&output, code)
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
fn explicit_scope_and_confirmation_are_required_before_network() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec![],
        vec!["sample"],
        vec!["--scope", "account-directory"],
        vec![
            "sample",
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
        ],
    ] {
        let mut cmd = vec!["skill", "state", "prune"];
        cmd.extend(args);
        assert_eq!(run(home.path(), &cmd).status.code(), Some(2));
    }
    assert_eq!(
        command(home.path(), &[], 2)["errors"][0]["code"],
        "CONFIRMATION_REQUIRED"
    );
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn dry_run_traverses_every_page_and_does_not_journal() {
    let (url, server) = serve(reads(1101));
    let home = home(&url);
    let output = command(home.path(), &["--dry-run"], 0);
    assert_eq!(output["status"], "preview");
    assert_eq!(output["committed"], false);
    assert_eq!(output["data"]["rows"].as_array().unwrap().len(), 1101);
    assert_eq!(output["data"]["disclosure_rows"], 1101);
    assert_eq!(count(home.path()), 0);
    let calls = server.join().unwrap();
    assert_eq!(calls.len(), 13);
    assert_eq!(body(&calls[1])["selector"]["skill"], "sample");
    assert_eq!(body(&calls[2])["selector"]["skill"], SKILL);
    assert!(calls[1..]
        .iter()
        .all(|c| c.starts_with("POST /api/v1/skills/state/prune/preview ")));
}

#[test]
fn accepted_request_is_small_and_status_last_recovers_complete_original_details() {
    let mut replies = reads(101);
    replies.extend([
        Reply::Receipt(101),
        Reply::User,
        Reply::Receipt(101),
        Reply::Data(200, entries(0, 101)),
        Reply::Data(200, entries(100, 101)),
        Reply::Data(200, progress()),
    ]);
    let (url, server) = serve(replies);
    let home = home(&url);
    let accepted = command(home.path(), &["--yes", "--no-wait"], 0);
    assert_eq!(accepted["status"], "accepted");
    let saved = journal(home.path());
    assert_eq!(saved.0["command"], "state_prune");
    assert_eq!(saved.1, "received");
    assert_eq!(saved.2.as_deref(), Some(OP));
    assert!(saved.0.to_string().len() < 4096);
    assert!(saved.0.get("rows").is_none());
    let last = json_output(
        &run(home.path(), &["--json", "skill", "status", "--last"]),
        0,
    );
    assert_eq!(last["data"]["receipt"], accepted["data"]);
    assert_eq!(last["data"]["rows"].as_array().unwrap().len(), 101);
    assert_eq!(last["data"]["deletion_progress"]["retrying_tasks"], 1);
    let calls = server.join().unwrap();
    assert_eq!(body(&calls[3]), saved.0["request"]);
    assert_eq!(body(&calls[3]).as_object().unwrap().len(), 2);
    assert!(calls[5].starts_with("GET /api/v1/skills/state/prune/operations?key="));
    assert!(calls[6..].iter().all(|c| c.starts_with("GET ")));
}

#[test]
fn lost_acceptance_only_replays_after_definite_original_key_absence() {
    for missing in [false, true] {
        let mut replies = reads(1);
        replies.push(Reply::Disconnect);
        if missing {
            replies.push(Reply::Data(404, rejected("OPERATION_NOT_FOUND")));
        }
        replies.push(Reply::Receipt(1));
        let (url, server) = serve(replies);
        let home = home(&url);
        command(home.path(), &["--yes"], 0);
        let calls = server.join().unwrap();
        assert!(calls[3].starts_with("GET /api/v1/skills/state/prune/operations?key="));
        if missing {
            assert_eq!(body(&calls[2]), body(&calls[4]));
        }
        assert_eq!(journal(home.path()).1, "received");
    }
}

#[test]
fn changed_receipt_retains_original_key_and_restart_does_not_preview() {
    let mut replies = reads(1);
    replies.extend([Reply::Tampered(1), Reply::User, Reply::Receipt(1)]);
    let (url, server) = serve(replies);
    let home = home(&url);
    let unknown = command(home.path(), &["--yes"], 1);
    assert_eq!(unknown["status"], "unknown");
    let original = journal(home.path());
    assert_eq!(original.1, "pending");
    command(home.path(), &["--yes"], 0);
    assert_eq!(journal(home.path()).0, original.0);
    let calls = server.join().unwrap();
    assert!(calls[4].starts_with("GET /api/v1/skills/state/prune/operations?key="));
    assert_eq!(
        calls
            .iter()
            .filter(|c| c.starts_with("POST /api/v1/skills/state/prune/preview "))
            .count(),
        1
    );
}

#[test]
fn incomplete_or_inconsistent_disclosure_never_creates_a_command() {
    for kind in [
        "offset",
        "summary",
        "early-confirmation",
        "duplicate",
        "loss-count",
        "scope",
    ] {
        let mut first = page(0, 101);
        let mut second = page(100, 101);
        match kind {
            "offset" => second["data"]["offset"] = json!(99),
            "summary" => {
                second["data"]["summary"]["binding"]["plan_digest"] = json!("f".repeat(64))
            }
            "early-confirmation" => first["data"]["confirmation"] = json!(CONFIRMATION),
            "duplicate" => second["data"]["rows"][0] = rows(0, 1)[0].clone(),
            "loss-count" => {
                first["data"]["summary"]["history_losses"] = json!(102);
                second["data"]["summary"]["history_losses"] = json!(102);
            }
            "scope" => second["data"]["summary"]["binding"]["selector"]["account_id"] = json!(OP),
            _ => unreachable!(),
        }
        let mut replies = vec![Reply::User, Reply::Data(200, first)];
        if kind != "early-confirmation" {
            replies.push(Reply::Data(200, second));
        }
        let (url, server) = serve(replies);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        assert_eq!(count(home.path()), 0);
        let calls = server.join().unwrap();
        assert!(!calls
            .iter()
            .any(|c| c.starts_with("POST /api/v1/skills/state/prune HTTP")));
    }
}

#[test]
fn pending_dry_run_does_not_silently_replan_or_submit() {
    let mut replies = reads(1);
    replies.extend([
        Reply::Tampered(1),
        Reply::User,
        Reply::Data(404, rejected("OPERATION_NOT_FOUND")),
    ]);
    let (url, server) = serve(replies);
    let home = home(&url);
    command(home.path(), &["--yes"], 1);
    let before = journal(home.path());
    let result = command(home.path(), &["--dry-run"], 1);
    assert_eq!(result["data"]["disclosure_available"], false);
    assert_eq!(result["data"]["recovering_original_request"], true);
    assert_eq!(journal(home.path()), before);
    let calls = server.join().unwrap();
    assert!(calls[4].starts_with("GET /api/v1/skills/state/prune/operations?key="));
}

#[test]
fn directory_early_prune_preserves_explicit_scope_on_every_page() {
    let mut replies = vec![Reply::User];
    for offset in [0, 100] {
        let mut response = page(offset, 101);
        response["data"]["summary"]["binding"]["selector"] =
            json!({"scope":"account-directory","account_id":ACCOUNT,"skill":null});
        response["data"]["summary"]["binding"]["all_unreferenced"] = json!(true);
        replies.push(Reply::Data(200, response));
    }
    let (url, server) = serve(replies);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "prune",
                "--scope",
                "account-directory",
                "--account-id",
                ACCOUNT,
                "--all-unreferenced",
                "--dry-run",
            ],
        ),
        0,
    );
    assert_eq!(output["data"]["rows"].as_array().unwrap().len(), 101);
    for call in &server.join().unwrap()[1..] {
        assert_eq!(body(call)["selector"]["scope"], "account-directory");
        assert!(body(call)["selector"]["skill"].is_null());
        assert_eq!(body(call)["all_unreferenced"], true);
    }
    assert_eq!(count(home.path()), 0);
}

#[test]
fn lookup_authentication_or_protocol_failure_never_authorizes_replay() {
    for (status, response) in [
        (401, json!({"detail":"Unauthorized"})),
        (200, json!({"schema_version":999})),
    ] {
        let mut replies = reads(1);
        replies.extend([
            Reply::Tampered(1),
            Reply::User,
            Reply::Data(status, response),
        ]);
        let (url, server) = serve(replies);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        let before = journal(home.path());
        assert_eq!(command(home.path(), &["--yes"], 1)["status"], "unknown");
        assert_eq!(journal(home.path()), before);
        let calls = server.join().unwrap();
        assert_eq!(calls.len(), 5);
        assert!(calls[4].starts_with("GET /api/v1/skills/state/prune/operations?key="));
    }
}

#[test]
fn definite_head_change_finishes_original_attempt_without_replanning() {
    let mut replies = reads(1);
    replies.push(Reply::Data(409, rejected("HEAD_CHANGED")));
    let (url, server) = serve(replies);
    let home = home(&url);
    let result = command(home.path(), &["--yes"], 1);
    assert_eq!(result["errors"][0]["code"], "HEAD_CHANGED");
    assert_eq!(journal(home.path()).1, "received");
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn status_by_id_uses_prune_only_after_definite_absence_in_older_domains() {
    let mut replies = (0..5)
        .map(|_| Reply::Data(404, rejected("OPERATION_NOT_FOUND")))
        .collect::<Vec<_>>();
    replies.extend([
        Reply::Receipt(1),
        Reply::Data(200, entries(0, 1)),
        Reply::Data(200, progress()),
    ]);
    let (url, server) = serve(replies);
    let home = home(&url);
    let output = json_output(&run(home.path(), &["--json", "skill", "status", OP]), 0);
    assert_eq!(output["status"], "accepted");
    assert_eq!(output["data"]["rows"].as_array().unwrap().len(), 1);
    let calls = server.join().unwrap();
    assert!(calls[5].starts_with(&format!("GET /api/v1/skills/state/prune/operations/{OP} ")));
}

#[test]
fn status_rejects_incomplete_details_and_inconsistent_physical_progress() {
    for bad_details in [true, false] {
        let mut replies = reads(1);
        replies.extend([Reply::Receipt(1), Reply::User, Reply::Receipt(1)]);
        let mut detail = entries(0, 1);
        if bad_details {
            detail["data"]["rows"] = json!([]);
        }
        replies.push(Reply::Data(200, detail));
        if !bad_details {
            let mut physical = progress();
            physical["data"]["pending_file_bytes"] = json!(11);
            replies.push(Reply::Data(200, physical));
        }
        let (url, server) = serve(replies);
        let home = home(&url);
        command(home.path(), &["--yes"], 0);
        let before = journal(home.path());
        json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            1,
        );
        assert_eq!(journal(home.path()), before);
        server.join().unwrap();
    }
}

#[test]
fn package_batch_skips_pending_prune_without_touching_original_request() {
    let mut replies = reads(1);
    replies.extend([
        Reply::Tampered(1),
        Reply::User,
        Reply::Data(
            200,
            support::envelope(json!({"generation":1,"items":[],"local_items":[]})),
        ),
    ]);
    let (url, server) = serve(replies);
    let home = home(&url);
    command(home.path(), &["--yes"], 1);
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
    assert_eq!(calls.len(), 5);
    assert!(calls[4].starts_with("GET /api/v1/skills?"));
}

#[test]
fn oversized_or_short_preview_never_authorizes_a_command() {
    for oversized in [false, true] {
        let mut response = page(0, 1);
        if oversized {
            response["unexpected_padding"] = json!("x".repeat(1024 * 1024));
        } else {
            response["data"]["rows"] = json!([]);
        }
        let (url, server) = serve(vec![Reply::User, Reply::Data(200, response)]);
        let home = home(&url);
        command(home.path(), &["--yes"], 1);
        assert_eq!(count(home.path()), 0);
        assert_eq!(server.join().unwrap().len(), 2);
    }
}
