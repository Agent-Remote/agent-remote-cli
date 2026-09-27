#![cfg(unix)]

#[path = "support/skill_conflicts.rs"]
mod conflicts;
#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use conflicts::*;
use serde_json::json;
use state::*;
use support::*;

#[test]
fn conflict_selectors_reject_ambiguous_scope_before_login() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["conflicts"],
        vec!["conflicts", "sample"],
        vec![
            "conflicts",
            "sample",
            "--account-id",
            ACCOUNT,
            "--scope",
            "account-directory",
        ],
        vec![
            "conflicts",
            "sample",
            "--account-id",
            ACCOUNT,
            "--limit",
            "201",
        ],
        vec![
            "conflicts",
            "sample",
            "--account-id",
            ACCOUNT,
            "--migration-cursor",
            "invalid",
        ],
        vec!["diff", "--conflict", OP, "--checkpoint", SECOND],
        vec!["diff", "sample", "--conflict", OP],
        vec!["diff", "--conflict", OP, "--account-id", ACCOUNT],
        vec!["diff", "--conflict", OP, "--scope", "account-directory"],
        vec!["diff", "--cursor", "path"],
    ] {
        let mut cmd = vec!["--json", "skill", "state"];
        cmd.extend(args);
        assert_eq!(run(home.path(), &cmd).status.code(), Some(2), "{cmd:?}");
    }
}

#[test]
fn conflict_list_resolves_name_once_and_keeps_independent_pages() {
    let (url, server) = serve(vec![
        (200, envelope(installation())),
        (
            200,
            envelope(json!({"items":[publication_summary()],"next_cursor":OP})),
        ),
        (
            200,
            envelope(json!({"items":[migration_summary()],"next_cursor":OP})),
        ),
    ]);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "conflicts",
                "sample",
                "--account-id",
                ACCOUNT,
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(output["data"]["selector"]["skill"], SKILL);
    assert_eq!(
        output["data"]["publications"]["items"][0],
        publication_summary()
    );
    assert_eq!(
        output["data"]["migrations"]["items"][0],
        migration_summary()
    );
    assert_eq!(
        output["data"]["migrations"]["items"][0]["installation_epoch"],
        9007199254740993_i64
    );
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/skills/installations/sample?account_id={ACCOUNT} "
    )));
    for (request, path) in requests[1..]
        .iter()
        .zip(["conflicts", "migration/conflicts"])
    {
        assert!(request.starts_with(&format!(
            "GET /api/v1/skills/state/{path}?account_id={ACCOUNT}&skill={SKILL}&limit=1 "
        )));
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer skill-user-token"));
    }
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn directory_conflict_pages_continue_independently() {
    let (url, server) = serve(vec![
        (200, envelope(json!({"items":[],"next_cursor":null})));
        2
    ]);
    let home = home(&url);
    json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "conflicts",
                "--scope",
                "account-directory",
                "--account-id",
                ACCOUNT,
                "--cursor",
                OP,
                "--migration-cursor",
                SECOND,
            ],
        ),
        0,
    );
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(&format!(
        "GET /api/v1/skills/state/conflicts?account_id={ACCOUNT}&limit=100&cursor={OP} "
    )));
    assert!(requests[1].starts_with(&format!("GET /api/v1/skills/state/migration/conflicts?account_id={ACCOUNT}&limit=100&cursor={SECOND} ")));
}

#[test]
fn publication_diff_preserves_exact_sources_and_binary_metadata() {
    let mut info = publication();
    info["summary"] = json!("ignored future field");
    let mut diff = conflict_diff(false);
    diff["next_cursor"] = json!("sample/memory");
    let (url, server) = serve(vec![
        (200, conflict_envelope(info)),
        (200, envelope(diff.clone())),
    ]);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "diff",
                "--conflict",
                OP,
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(output["data"]["kind"], "publication");
    assert_eq!(output["data"]["conflict"], publication());
    assert_eq!(output["data"]["diff"], diff);
    assert_eq!(output["committed"], false);
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn migration_diff_keeps_saved_input_and_live_drift_separate() {
    let mut diff = conflict_diff(true);
    let cursor = migration_cursor(OP, "sample/memory");
    diff["next_cursor"] = json!(cursor);
    let (url, server) = serve(vec![
        (404, rejection("CONFLICT_NOT_FOUND")),
        (200, conflict_envelope(migration())),
        (200, envelope(diff.clone())),
    ]);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "diff",
                "--conflict",
                OP,
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(output["data"]["kind"], "migration");
    assert_eq!(output["data"]["conflict"], migration());
    assert_eq!(output["data"]["diff"], diff);
    let requests = server.join().unwrap();
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/skills/state/migration/conflicts/{OP} "
    )));
    assert!(requests[2].starts_with(&format!(
        "GET /api/v1/skills/state/migration/conflicts/{OP}/diff?limit=1 "
    )));
}

#[test]
fn migration_cursor_is_bound_to_attempt_and_saved_digests() {
    use base64::{engine::general_purpose::URL_SAFE, Engine};
    let wrong_digest = URL_SAFE.encode(
        json!([
            OP,
            "f".repeat(64),
            "b".repeat(64),
            "c".repeat(64),
            "sample/earlier"
        ])
        .to_string(),
    );
    for cursor in [
        migration_cursor(SECOND, "sample/earlier"),
        wrong_digest,
        "sample/earlier".to_owned(),
    ] {
        let (url, server) = serve(vec![
            (404, rejection("CONFLICT_NOT_FOUND")),
            (200, conflict_envelope(migration())),
        ]);
        let home = home(&url);
        let output = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "diff",
                    "--conflict",
                    OP,
                    "--cursor",
                    &cursor,
                ],
            ),
            1,
        );
        assert_eq!(output["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        assert_eq!(server.join().unwrap().len(), 2);
    }
    let long_path = vec!["a".repeat(240); 14].join("/");
    let long_cursor = migration_cursor(OP, &long_path);
    assert!(long_cursor.len() > 4096);
    for cursor in [migration_cursor(OP, "sample/earlier"), long_cursor] {
        let (url, server) = serve(vec![
            (404, rejection("CONFLICT_NOT_FOUND")),
            (200, conflict_envelope(migration())),
            (200, envelope(conflict_diff(true))),
        ]);
        let home = home(&url);
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "diff",
                    "--conflict",
                    OP,
                    "--cursor",
                    &cursor,
                ],
            ),
            0,
        );
        let request = server.join().unwrap().pop().unwrap();
        assert!(request.contains("&cursor="));
        let query = request.lines().next().unwrap().split(' ').nth(1).unwrap();
        let parsed = reqwest::Url::parse(&format!("http://localhost{query}")).unwrap();
        assert_eq!(
            parsed.query_pairs().find(|(k, _)| k == "cursor").unwrap().1,
            cursor
        );
    }
}

#[test]
fn only_definite_conflict_absence_permits_migration_lookup() {
    for code in ["STATE_EXPIRED", "ACCOUNT_NOT_FOUND", "INVALID_REQUEST"] {
        let (url, server) = serve(vec![(409, rejection(code))]);
        let home = home(&url);
        let output = json_output(
            &run(
                home.path(),
                &["--json", "skill", "state", "diff", "--conflict", OP],
            ),
            1,
        );
        assert_eq!(output["errors"][0]["code"], code);
        assert_eq!(server.join().unwrap().len(), 1);
    }
    let (url, server) = serve(vec![(0, json!(null))]);
    let home = home(&url);
    let output = json_output(
        &run(
            home.path(),
            &["--json", "skill", "state", "diff", "--conflict", OP],
        ),
        1,
    );
    assert_eq!(output["errors"][0]["code"], "SKILL_TRANSPORT_FAILED");
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn forged_provenance_and_envelopes_are_rejected_before_diff() {
    for (is_migration, pointer, replacement) in [
        (false, "/id", json!(SECOND)),
        (false, "/base/source", json!("target_original")),
        (false, "/incoming/reference_id", json!(SKILL)),
        (false, "/branches/0/state_epoch", json!(0)),
        (
            false,
            "/choices",
            json!([{"path":null,"unit":[],"use":"current","file_tree_digest":"a".repeat(64),"directory_tree_digest":null}]),
        ),
        (true, "/original/operation_id", json!(SECOND)),
        (true, "/incoming/tree_digest", json!("d".repeat(64))),
        (true, "/live/target/state_id", json!(SKILL)),
        (true, "/incoming/revision_id", json!(REVISION)),
        (true, "/incoming/checkpoint_id", json!(SECOND)),
        (true, "/live/source/revision_id", json!(REVISION)),
        (true, "/directory/checkpoint_id", json!(OP)),
    ] {
        let mut info = if is_migration {
            migration()
        } else {
            publication()
        };
        *info.pointer_mut(pointer).unwrap() = replacement;
        let mut responses = vec![];
        if is_migration {
            responses.push((404, rejection("CONFLICT_NOT_FOUND")));
        }
        responses.push((200, conflict_envelope(info)));
        let (url, server) = serve(responses);
        let home = home(&url);
        let output = json_output(
            &run(
                home.path(),
                &["--json", "skill", "state", "diff", "--conflict", OP],
            ),
            1,
        );
        assert_eq!(
            output["errors"][0]["code"], "INVALID_SKILL_RESPONSE",
            "{pointer}"
        );
        server.join().unwrap();
    }
    for field in ["committed", "retryable"] {
        let mut response = conflict_envelope(publication());
        response[field] = json!(true);
        let (url, server) = serve(vec![(200, response)]);
        let home = home(&url);
        let output = json_output(
            &run(
                home.path(),
                &["--json", "skill", "state", "diff", "--conflict", OP],
            ),
            1,
        );
        assert_eq!(output["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        server.join().unwrap();
    }
}

#[test]
fn forged_diff_identity_paths_and_cursors_are_rejected() {
    for migration_kind in [false, true] {
        for variant in 0..5 {
            let mut diff = conflict_diff(migration_kind);
            match variant {
                0 => {
                    diff[if migration_kind {
                        "migration_id"
                    } else {
                        "publication_id"
                    }] = json!(SECOND)
                }
                1 => diff["items"][0]["current"]["path"] = json!("another"),
                2 => diff["items"][0]["current"]["sha256"] = json!("bad"),
                3 => {
                    diff["next_cursor"] = json!(if migration_kind {
                        migration_cursor(SECOND, "sample/memory")
                    } else {
                        "wrong-path".to_owned()
                    })
                }
                _ => {
                    diff["items"][0]["base"] = json!(null);
                    diff["items"][0]["current"] = json!(null);
                }
            }
            let mut responses = vec![];
            if migration_kind {
                responses.push((404, rejection("CONFLICT_NOT_FOUND")));
            }
            responses.push((
                200,
                conflict_envelope(if migration_kind {
                    migration()
                } else {
                    publication()
                }),
            ));
            responses.push((200, envelope(diff)));
            let (url, server) = serve(responses);
            let home = home(&url);
            let output = json_output(
                &run(
                    home.path(),
                    &[
                        "--json",
                        "skill",
                        "state",
                        "diff",
                        "--conflict",
                        OP,
                        "--limit",
                        "1",
                    ],
                ),
                1,
            );
            assert_eq!(output["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
            server.join().unwrap();
        }
    }
}

#[test]
fn conflict_terminal_output_escapes_remote_metadata() {
    let mut value = migration();
    value["live"]["recomputation_reasons"] = json!(["changed\u{1b}[31m\nforged"]);
    let mut diff = conflict_diff(true);
    diff["items"][0]["incoming"] = json!(link("sample/memory", "../shared", false));
    let (url, server) = serve(vec![
        (404, rejection("CONFLICT_NOT_FOUND")),
        (200, conflict_envelope(value)),
        (200, envelope(diff)),
    ]);
    let home = home(&url);
    let output = run(home.path(), &["skill", "state", "diff", "--conflict", OP]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(
        text.contains("source_published")
            && text.contains("Saved incoming")
            && text.contains("Source head advanced")
    );
    server.join().unwrap();
}

#[test]
fn interrupted_conflict_diff_emits_one_uncommitted_result() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_raw(
        vec![
            Response::Json(conflict_envelope(publication())),
            Response::Disconnect,
        ],
        move |index| {
            if index == 1 {
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&url);
    let child = Command::new(BIN)
        .arg("--home")
        .arg(home.path())
        .args(["--json", "skill", "state", "diff", "--conflict", OP])
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
    let result = json_output(&child.wait_with_output().unwrap(), 130);
    release_tx.send(()).unwrap();
    assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    assert_eq!(result["errors"][0]["code"], "SKILL_INTERRUPTED");
    assert_eq!(result["committed"], false);
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn conflict_lists_reject_wrong_accounts_sources_and_repeating_pages() {
    for (migrations, variant) in [
        (false, 0),
        (false, 1),
        (false, 2),
        (true, 0),
        (true, 1),
        (true, 2),
    ] {
        let mut item = if migrations {
            migration_summary()
        } else {
            publication_summary()
        };
        let next = match variant {
            0 => {
                item["account_id"] = json!(SKILL);
                json!(null)
            }
            1 => json!(SECOND),
            _ if migrations => {
                item["skill_id"] = json!(SECOND);
                json!(null)
            }
            _ => json!(OP),
        };
        let page = envelope(json!({"items":[item],"next_cursor":next}));
        let mut responses = vec![];
        if migrations {
            responses.push((200, envelope(json!({"items":[],"next_cursor":null}))));
        }
        responses.push((200, page));
        let (url, server) = serve(responses);
        let home = home(&url);
        let output = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "conflicts",
                    SKILL,
                    "--account-id",
                    ACCOUNT,
                    "--limit",
                    "1",
                    "--cursor",
                    if !migrations && variant == 2 {
                        OP
                    } else {
                        REVISION
                    },
                ],
            ),
            1,
        );
        assert_eq!(output["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        server.join().unwrap();
    }
}
