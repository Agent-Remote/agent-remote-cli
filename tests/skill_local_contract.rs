#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use rusqlite::Connection;
use serde_json::{json, Value};
use support::*;

fn reads(details: Value) -> Vec<(u16, Value)> {
    vec![
        (200, json!({"data":{"id":OP}})),
        (
            200,
            envelope(json!({"generation":2,"items":[installation()],"local_items":[]})),
        ),
        (200, envelope(details)),
    ]
}

#[test]
fn local_list_and_details_preserve_identity_and_disabled_entries() {
    for (args, data) in [
        (
            vec!["list", "--account-id", ACCOUNT, "--effective"],
            json!({"generation":2,"items":[],"local_items":[local_skill()]}),
        ),
        (
            vec!["info", "notes", "--account-id", ACCOUNT],
            local_skill(),
        ),
    ] {
        let expected = envelope(data);
        let (url, server) = serve(vec![(200, expected.clone())]);
        let home = home(&url);
        let mut command = vec!["--json", "skill"];
        command.extend(args);
        assert_eq!(json_output(&run(home.path(), &command), 0), expected);
        assert!(server.join().unwrap()[0].contains(&format!("account_id={ACCOUNT}")));
    }
    let mut item = local_skill();
    item["name"] = json!("notes\u{1b}[31m");
    let (url, server) = serve(vec![(200, envelope(item))]);
    let home = home(&url);
    let output = run(
        home.path(),
        &["skill", "info", SKILL, "--account-id", ACCOUNT],
    );
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("account_local") && text.contains("Source checkpoint"));
    assert!(!text.contains('\u{1b}'));
    server.join().unwrap();
}

#[test]
fn local_mutations_use_original_name_then_exact_account_identity() {
    for command in ["enable", "disable", "inherit"] {
        let mut responses = reads(local_skill());
        let result = operation("stored", "stored");
        responses.push((200, result.clone()));
        let (url, server) = serve(responses);
        let home = home(&url);
        assert_eq!(
            json_output(
                &run(
                    home.path(),
                    &[
                        "--json",
                        "skill",
                        command,
                        "notes",
                        "--account-id",
                        ACCOUNT,
                        "--yes"
                    ]
                ),
                0
            ),
            result
        );
        let requests = server.join().unwrap();
        assert!(requests[2].starts_with(&format!(
            "GET /api/v1/skills/installations/notes?account_id={ACCOUNT} HTTP/1.1"
        )));
        let posted: Value =
            serde_json::from_str(requests[3].split_once("\r\n\r\n").unwrap().1).unwrap();
        assert_eq!(posted["skill"], SKILL);
        assert_eq!(posted["scope"]["account_id"], ACCOUNT);
        assert_eq!(posted["command"], command);
    }
}

#[test]
fn local_unsupported_commands_stop_before_journal_or_post() {
    for args in [
        vec!["pin", "notes", "--revision", "r1"],
        vec!["unpin", "notes"],
        vec!["inherit", "notes", "--field", "revision"],
    ] {
        let (url, server) = serve(reads(local_skill()));
        let home = home(&url);
        let mut command = vec!["--json", "skill"];
        command.extend(args);
        command.extend(["--account-id", ACCOUNT, "--dry-run"]);
        let result = json_output(&run(home.path(), &command), 2);
        assert_eq!(
            result["errors"][0]["code"],
            "LOCAL_SKILL_COMMAND_UNSUPPORTED"
        );
        assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
        let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
        let count: i64 = db
            .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }
}

#[test]
fn same_name_collision_is_not_bypassed_by_library_listing() {
    let conflict = json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,
        "retryable":false,"data":null,"errors":[{"code":"SKILL_SOURCE_CONFLICT","message":"use stable ID","object_id":null,"details":{}}]});
    let mut responses = reads(installation());
    *responses.last_mut().unwrap() = (409, conflict.clone());
    let (url, server) = serve(responses);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "disable", "sample", "--yes"]
            ),
            1
        ),
        conflict
    );
    let requests = server.join().unwrap();
    assert!(requests[2].starts_with("GET /api/v1/skills/installations/sample HTTP/1.1"));
    assert!(requests.iter().all(|r| r.starts_with("GET ")));
}

#[test]
fn mismatched_detail_identity_cannot_redirect_mutations() {
    for (requested, mut detail) in [(SKILL, local_skill()), ("notes", local_skill())] {
        if requested == SKILL {
            detail["id"] = json!(OP);
        } else {
            detail["name"] = json!("another-skill");
        }
        let (url, server) = serve(reads(detail));
        let home = home(&url);
        let result = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "disable",
                    requested,
                    "--account-id",
                    ACCOUNT,
                    "--yes",
                ],
            ),
            1,
        );
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    }
}

#[test]
fn local_missing_account_scope_is_an_argument_error() {
    let failure = json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,
        "retryable":false,"data":null,"errors":[{"code":"LOCAL_SKILL_SCOPE_REQUIRED","message":"local skill requires its account","object_id":null,"details":{}}]});
    for mutation in [false, true] {
        let responses = if mutation {
            let mut values = reads(local_skill());
            *values.last_mut().unwrap() = (409, failure.clone());
            values
        } else {
            vec![(409, failure.clone())]
        };
        let (url, server) = serve(responses);
        let home = home(&url);
        let args = if mutation {
            vec!["--json", "skill", "enable", "notes", "--yes"]
        } else {
            vec!["--json", "skill", "info", "notes"]
        };
        assert_eq!(json_output(&run(home.path(), &args), 2), failure);
        assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    }
}
