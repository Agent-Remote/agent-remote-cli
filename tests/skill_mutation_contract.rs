#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use rusqlite::Connection;
use serde_json::{json, Value};
use support::*;

const USER: &str = "55555555-5555-4555-8555-555555555555";
fn user() -> (u16, Value) {
    (200, json!({"data":{"id":USER}}))
}
fn library() -> (u16, Value) {
    (
        200,
        envelope(json!({"generation":7,"items":[installation()]})),
    )
}
fn mutation_operation(status: &str, readiness: &str) -> Value {
    let mut result = operation(status, readiness);
    result["data"]["generation"] = json!(8);
    result
}

fn receipt() -> Value {
    let mut result = operation("stored", "stored");
    result["data"]["generation"] = json!(8);
    result
}
fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn database(home: &std::path::Path) -> Connection {
    Connection::open(home.join("state.sqlite3")).unwrap()
}

#[test]
fn skill_mutations_submit_exact_scopes_and_retain_operation_ids() {
    let cases = [
        (
            vec!["enable", "sample", "--yes"],
            "/rules",
            json!({"command":"enable","scope":{"tools":[],"account_id":null}}),
        ),
        (
            vec!["disable", "sample", "--tool", "claude", "--yes"],
            "/rules",
            json!({"command":"disable","scope":{"tools":["claude"],"account_id":null},"all_scopes":false}),
        ),
        (
            vec!["disable", "sample", "--all-scopes", "--yes"],
            "/rules",
            json!({"command":"disable","scope":{"tools":[],"account_id":null},"all_scopes":true}),
        ),
        (
            vec![
                "pin",
                "sample",
                "--account-id",
                ACCOUNT,
                "--revision",
                "r2",
                "--yes",
            ],
            "/rules",
            json!({"command":"pin","scope":{"tools":[],"account_id":ACCOUNT},"revision":"r2"}),
        ),
        (
            vec!["unpin", "sample", "--tool", "claude", "--yes"],
            "/rules",
            json!({"command":"unpin","scope":{"tools":["claude"],"account_id":null}}),
        ),
        (
            vec![
                "inherit",
                "sample",
                "--account-id",
                ACCOUNT,
                "--field",
                "enabled",
                "--yes",
            ],
            "/rules",
            json!({"command":"inherit","scope":{"tools":[],"account_id":ACCOUNT},"field":"enabled"}),
        ),
        (
            vec!["inherit", "sample", "--tool", "claude", "--yes"],
            "/rules",
            json!({"command":"inherit","scope":{"tools":["claude"],"account_id":null},"field":"all"}),
        ),
        (
            vec!["remove", "sample", "--yes"],
            "/removals",
            json!({"command":"remove"}),
        ),
        (
            vec!["rollback", "sample", "--yes"],
            "/rollbacks",
            json!({"command":"rollback","revision":null}),
        ),
        (
            vec!["rollback", "sample", "--revision", "r1", "--yes"],
            "/rollbacks",
            json!({"command":"rollback","revision":"r1"}),
        ),
    ];
    for (args, endpoint, change) in cases {
        let mut responses = vec![user(), library()];
        responses.push((200, envelope(installation())));
        responses.push((200, receipt()));
        let (url, server) = serve(responses);
        let home = home(&url);
        let mut command = vec!["--json", "skill"];
        command.extend(args);
        assert_eq!(json_output(&run(home.path(), &command), 0), receipt());
        let requests = server.join().unwrap();
        assert_eq!(requests.len(), 4);
        let posted = requests.last().unwrap();
        assert!(posted.starts_with(&format!("POST /api/v1/skills{endpoint} HTTP/1.1")));
        let payload = body(posted);
        assert_eq!(payload["skill"], SKILL);
        assert_eq!(payload["expected_generation"], 7);
        for (key, value) in change.as_object().unwrap() {
            assert_eq!(&payload[key], value);
        }
        let db = database(home.path());
        let row: (String, String, String, String) = db
            .query_row(
                "SELECT user_id, state, operation_id, request_json FROM skill_commands",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(row.0, USER);
        assert_eq!(row.1, "received");
        assert_eq!(row.2, OP);
        assert_eq!(serde_json::from_str::<Value>(&row.3).unwrap(), payload);
        assert!(!row.3.contains("skill-user-token"));
    }
}

#[test]
fn skill_dry_run_reads_the_library_without_post_or_recovery_record() {
    let (url, server) = serve(vec![user(), library(), (200, envelope(installation()))]);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "disable",
                "sample",
                "--all-scopes",
                "--dry-run",
            ],
        ),
        0,
    );
    assert_eq!(output["status"], "planned");
    assert_eq!(output["committed"], false);
    assert_eq!(output["data"]["request"]["expected_generation"], 7);
    assert_eq!(server.join().unwrap().len(), 3);
    let count: i64 = database(home.path())
        .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 0);
}

#[test]
fn skill_mutations_require_confirmation_and_scopes_before_network() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["enable", "sample"],
        vec!["pin", "sample", "--revision", "r2", "--yes"],
        vec!["unpin", "sample", "--yes"],
        vec!["inherit", "sample", "--yes"],
        vec![
            "enable", "sample", "--tool", "claude", "--tool", "claude", "--yes",
        ],
    ] {
        let mut command = vec!["--json", "skill"];
        command.extend(args);
        let result = json_output(&run(home.path(), &command), 2);
        assert_eq!(result["committed"], false);
    }
    for args in [
        vec![
            "disable",
            "sample",
            "--all-scopes",
            "--tool",
            "claude",
            "--yes",
        ],
        vec!["rollback", "sample", "--account-id", ACCOUNT, "--yes"],
        vec![
            "pin",
            "sample",
            "--tool",
            "claude",
            "--revision",
            "../r2",
            "--yes",
        ],
        vec!["enable", "sample", "--no-wait", "--timeout", "2", "--yes"],
    ] {
        let mut command = vec!["skill"];
        command.extend(args);
        assert_eq!(run(home.path(), &command).status.code(), Some(2));
    }
}

#[test]
fn skill_mutation_lost_reply_recovers_by_key_without_reapplying() {
    let (url, server) = serve(vec![
        user(),
        library(),
        (200, envelope(installation())),
        (0, Value::Null),
        (200, receipt()),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "enable", "sample", "--yes"]
            ),
            0
        ),
        receipt()
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 5);
    let key = body(&requests[3])["idempotency_key"]
        .as_str()
        .unwrap()
        .to_owned();
    assert!(requests[4].starts_with(&format!("GET /api/v1/skills/operations?key={key} HTTP/1.1")));
    assert_eq!(
        requests.iter().filter(|r| r.starts_with("POST ")).count(),
        1
    );
}

#[test]
fn skill_mutation_restart_preserves_generation_and_exact_request() {
    let unavailable = json!({"error":{"code":"UNAVAILABLE","message":"private server detail"}});
    let missing = json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":"OPERATION_NOT_FOUND","message":"operation not found","object_id":null,"details":{}}]});
    let (url, server) = serve(vec![
        user(),
        library(),
        (200, envelope(installation())),
        (0, Value::Null),
        (503, unavailable.clone()),
        (503, unavailable),
        user(),
        (404, missing),
        (200, receipt()),
    ]);
    let home = home(&url);
    let args = ["--json", "skill", "enable", "sample", "--yes"];
    let first = json_output(&run(home.path(), &args), 1);
    assert_eq!(first["status"], "unknown");
    assert_eq!(first["retryable"], true);
    assert_eq!(first["errors"][0]["details"]["commit_state"], "unknown");
    let pending: i64 = database(home.path())
        .query_row(
            "SELECT count(*) FROM skill_commands WHERE state='pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 1);
    assert_eq!(json_output(&run(home.path(), &args), 0), receipt());
    let requests = server.join().unwrap();
    assert_eq!(body(&requests[3]), body(&requests[8]));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("GET /api/v1/skills?effective="))
            .count(),
        1
    );
}

#[test]
fn skill_mutations_preserve_commit_on_unsupported_targets_and_wait_timeout() {
    for no_wait in [false, true] {
        let pending = mutation_operation("pending", "pending");
        let (url, server) = serve(vec![
            user(),
            library(),
            (200, envelope(installation())),
            (200, pending.clone()),
        ]);
        let home = home(&url);
        let mut args = vec!["--json", "skill", "disable", "sample", "--yes"];
        if no_wait {
            args.push("--no-wait");
        } else {
            args.extend(["--timeout", "1"]);
        }
        assert_eq!(
            json_output(&run(home.path(), &args), if no_wait { 0 } else { 3 }),
            pending
        );
        server.join().unwrap();
    }
    let failed = mutation_operation("failed", "unsupported");
    let (url, server) = serve(vec![
        user(),
        library(),
        (200, envelope(installation())),
        (200, failed.clone()),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "disable", "sample", "--yes", "--no-wait"],
        ),
        1,
    );
    assert_eq!(result, failed);
    assert_eq!(result["committed"], true);
    server.join().unwrap();
}

#[test]
fn skill_status_last_recovers_received_and_uncertain_commands_without_posting() {
    for received in [false, true] {
        let (url, server) = serve(vec![user(), (200, receipt())]);
        let home = home(&url);
        let paths =
            agent_remote_cli::config::AppPaths::new(Some(home.path().to_path_buf())).unwrap();
        let state = agent_remote_cli::local_state::LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();
        let record = agent_remote_cli::local_state::SkillCommandRecord {
            server_url: url,
            user_id: USER.to_owned(),
            intent_digest: "e".repeat(64),
            idempotency_key: "persisted-original-key".to_owned(),
            request_json: "{}".to_owned(),
        };
        state.begin_skill_command(&record).unwrap();
        if received {
            state.receive_skill_command(&record, Some(OP)).unwrap();
        }
        let result = json_output(
            &run(home.path(), &["--json", "skill", "status", "--last"]),
            0,
        );
        assert_eq!(result, receipt());
        let requests = server.join().unwrap();
        let path = if received {
            format!("/api/v1/skills/operations/{OP}")
        } else {
            "/api/v1/skills/operations?key=persisted-original-key".to_owned()
        };
        assert!(requests[1].starts_with(&format!("GET {path} HTTP/1.1")));
        assert!(requests.iter().all(|r| r.starts_with("GET ")));
    }
}

#[test]
fn skill_generation_conflict_is_not_automatically_replanned() {
    let conflict = json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":"GENERATION_CONFLICT","message":"library changed","object_id":null,"details":{"current":8,"expected":7}}]});
    let (url, server) = serve(vec![
        user(),
        library(),
        (200, envelope(installation())),
        (409, conflict.clone()),
    ]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &["--json", "skill", "enable", "sample", "--yes"]
            ),
            1
        ),
        conflict
    );
    assert_eq!(server.join().unwrap().len(), 4);
    let pending: i64 = database(home.path())
        .query_row(
            "SELECT count(*) FROM skill_commands WHERE state='pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 0);
}

#[test]
fn skill_authentication_failure_does_not_retry_the_mutation() {
    let (url, server) = serve(vec![
        user(),
        library(),
        (200, envelope(installation())),
        (
            401,
            json!({"error":{"code":"COMMON_UNAUTHORIZED","message":"private-refresh"}}),
        ),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &["--json", "skill", "enable", "sample", "--yes"],
        ),
        1,
    );
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["retryable"], false);
    assert_eq!(result["errors"][0]["code"], "COMMON_UNAUTHORIZED");
    assert_eq!(server.join().unwrap().len(), 4);
    let pending: i64 = database(home.path())
        .query_row(
            "SELECT count(*) FROM skill_commands WHERE state='pending'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(pending, 1);
}
