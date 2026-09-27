#![cfg(unix)]
#[path = "support/skill_cli.rs"]
mod support;

use serde_json::{json, Value};
use support::*;

fn system() -> Value {
    json!({"name":"ego-browser","origin":"system","read_only":true,"selected":true,"selection_reason":"session_snapshot","release":{"version":"original-release"}})
}

fn account() -> Value {
    json!({"account_id":ACCOUNT,"revision_selection_reason":"user_default","directory_mode":"managed_v1","directory_epoch":9,
        "directory_checkpoint_id":OP,"state_id":SKILL,"state_epoch":7,"checkpoint_id":OP,
        "state_expired":false,"preparation":"initialized","publication_conflicts":1,"migration_conflicts":0,
        "latest_publication_conflict_id":OP,"latest_migration_conflict_id":null,
        "last_recorded_sync_at":"2026-09-23T01:02:03Z","unknown_sync_times":true})
}

fn snapshot() -> Value {
    json!({"session_id":OP,"account_id":ACCOUNT,"basis":"session_snapshot","snapshot_id":SKILL,
        "snapshot_status":"retired","content_retained":false,"runtime_backend":"native",
        "library_generation":12,"directory_epoch":3,"starting_checkpoint_id":OP,"tree_digest":"a".repeat(64),
        "system_items":[system()],"items":[{"name":"sample","skill_id":SKILL,"origin":"user_library",
            "revision_id":REVISION,"installation_epoch":2,"state_id":SKILL,"state_epoch":4,"checkpoint_id":OP,
            "checkpoint_retained":false,"resolution":installation()["effective"]}],
        "next_cursor":"sample","project_discovery":"not_inspected","model_loaded":false})
}

#[test]
fn original_session_page_preserves_identity_and_explicit_continuation() {
    let value = snapshot();
    let (url, server) = serve(vec![
        (200, envelope(value.clone())),
        (200, envelope(value.clone())),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "list",
                "--session",
                OP,
                "--effective",
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(result["data"], value);
    let output = run(
        home.path(),
        &[
            "skill",
            "list",
            "--session",
            OP,
            "--effective",
            "--limit",
            "1",
        ],
    );
    assert!(output.status.success());
    let display = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        display.contains("original-release")
            && display.contains("--cursor sample")
            && display.contains("not_inspected")
    );
    assert!(!home.path().join("state.sqlite3").exists());
    assert!(server
        .join()
        .unwrap()
        .iter()
        .all(|r| r.starts_with(&format!("GET /api/v1/skills/sessions/{OP}?limit=1 "))));
}

#[test]
fn legacy_unknown_and_last_page_never_invent_selection() {
    let mut value = snapshot();
    value["basis"] = json!("legacy_unrecorded");
    for key in [
        "snapshot_id",
        "snapshot_status",
        "content_retained",
        "library_generation",
        "directory_epoch",
        "starting_checkpoint_id",
        "tree_digest",
        "next_cursor",
    ] {
        value[key] = Value::Null;
    }
    value["items"] = json!([]);
    value["system_items"] = json!([]);
    let mut page = snapshot();
    page["items"][0]["name"] = json!("zebra");
    page["items"][0]["origin"] = json!("account_local");
    page["next_cursor"] = Value::Null;
    let (url, server) = serve(vec![
        (200, envelope(value.clone())),
        (200, envelope(page.clone())),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "list", "--session", OP, "--effective"]
            ),
            0
        )["data"],
        value
    );
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "list",
                    "--session",
                    OP,
                    "--effective",
                    "--cursor",
                    "sample"
                ]
            ),
            0
        )["data"],
        page
    );
    assert!(server.join().unwrap()[1].contains("limit=100&cursor=sample"));
}

#[test]
fn session_flags_reject_ambiguous_scope_before_network() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["skill", "list", "--session", OP],
        vec![
            "skill",
            "list",
            "--session",
            OP,
            "--effective",
            "--account-id",
            ACCOUNT,
        ],
        vec![
            "skill",
            "list",
            "--session",
            OP,
            "--effective",
            "--tool",
            "claude",
        ],
        vec!["skill", "list", "--limit", "1"],
        vec!["skill", "list", "--cursor", "sample"],
        vec![
            "skill",
            "list",
            "--session",
            OP,
            "--effective",
            "--limit",
            "201",
        ],
    ] {
        assert_eq!(run(home.path(), &args).status.code(), Some(2));
    }
}

#[test]
fn account_diagnostics_and_system_catalog_survive_typed_output() {
    let mut detail = installation();
    detail["account_state"] = account();
    let listing =
        json!({"generation":4,"items":[detail.clone()],"local_items":[],"system_items":[system()]});
    let (url, server) = serve(vec![
        (200, envelope(listing.clone())),
        (200, envelope(detail.clone())),
        (200, envelope(detail.clone())),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "list",
                    "--account-id",
                    ACCOUNT,
                    "--effective",
                    "--include-system"
                ]
            ),
            0
        )["data"],
        listing
    );
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "info", SKILL, "--account-id", ACCOUNT]
            ),
            0
        )["data"],
        detail
    );
    let output = run(
        home.path(),
        &["skill", "info", SKILL, "--account-id", ACCOUNT],
    );
    assert!(output.status.success());
    let display = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        display.contains("Last recorded content sync")
            && display.contains("Historical sync times missing")
    );
    assert!(server.join().unwrap()[0].contains("include_system=true"));
}

#[test]
fn malformed_original_session_evidence_is_rejected() {
    for key in [
        "session", "revision", "epoch", "loading", "cursor", "system", "order", "legacy",
    ] {
        let mut value = snapshot();
        match key {
            "session" => value["session_id"] = json!(ACCOUNT),
            "revision" => value["items"][0]["revision_id"] = json!(SKILL),
            "epoch" => value["items"][0]["state_epoch"] = json!(0),
            "loading" => value["model_loaded"] = json!(true),
            "cursor" => value["next_cursor"] = json!("unseen"),
            "system" => value["system_items"][0]["read_only"] = json!(false),
            "order" => {
                value["items"]
                    .as_array_mut()
                    .unwrap()
                    .push(snapshot()["items"][0].clone());
            }
            "legacy" => value["basis"] = json!("legacy_unrecorded"),
            _ => unreachable!(),
        }
        let (url, server) = serve(vec![(200, envelope(value))]);
        let home = home(&url);
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "list",
                    "--session",
                    OP,
                    "--effective",
                    "--limit",
                    "1",
                ],
            ),
            1,
        );
        server.join().unwrap();
    }
}

#[test]
fn account_diagnostics_cannot_switch_requested_account_or_hide_conflicts() {
    for key in ["account", "conflict", "state"] {
        let mut detail = installation();
        detail["account_state"] = account();
        match key {
            "account" => detail["account_state"]["account_id"] = json!(OP),
            "conflict" => detail["account_state"]["publication_conflicts"] = json!(0),
            "state" => detail["account_state"]["state_id"] = Value::Null,
            _ => unreachable!(),
        }
        let (url, server) = serve(vec![(200, envelope(detail))]);
        let home = home(&url);
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "info", SKILL, "--account-id", ACCOUNT],
            ),
            1,
        );
        server.join().unwrap();
    }
}
