#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use agent_remote_cli::skills::snapshot::{PackageLimits, PackageSnapshot};
use rusqlite::Connection;
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use support::*;

const UPLOAD: &str = "66666666-6666-4666-8666-666666666666";
const SECOND: &str = "77777777-7777-4777-8777-777777777777";
const USER: &str = "88888888-8888-4888-8888-888888888888";

fn source() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("SKILL.md"),
        "---\nname: sample\n---\nOriginal instructions\n",
    )
    .unwrap();
    root
}
fn user() -> (u16, Value) {
    (200, json!({"data":{"id":USER}}))
}
fn library() -> (u16, Value) {
    (
        200,
        envelope(json!({"generation":2,"items":[],"local_items":[]})),
    )
}
fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn tree(root: &Path) -> Value {
    let captured = PackageSnapshot::capture(root, PackageLimits::default()).unwrap();
    json!({"tree_digest":captured.tree_digest(),"manifest":captured.manifest()})
}
fn upload(tree: &Value) -> (u16, Value) {
    let mut response = envelope(
        json!({"id":UPLOAD,"status":"staged","tree_digest":tree["tree_digest"],
        "manifest":tree["manifest"],"reserved_bytes":64,"expires_at":"2099-01-01T00:00:00Z"}),
    );
    response["status"] = json!("staged");
    (200, response)
}
fn file(tree: &Value) -> (u16, Value) {
    let mut response = envelope(
        json!({"upload_id":UPLOAD,"digest":tree["manifest"]["entries"][0]["sha256"],"created":true}),
    );
    response["status"] = json!("persisted");
    (200, response)
}
fn complete(tree: &Value) -> (u16, Value) {
    let mut response = envelope(tree.clone());
    response["status"] = json!("stored");
    response["committed"] = json!(true);
    (200, response)
}
fn transfer(tree: &Value) -> Vec<(u16, Value)> {
    vec![upload(tree), file(tree), complete(tree)]
}
fn journal_count(home: &Path) -> i64 {
    Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
        .unwrap()
}
fn add_args(root: &Path) -> Vec<&str> {
    vec!["--json", "skill", "add", root.to_str().unwrap(), "--yes"]
}

#[test]
fn source_list_is_read_only_without_login_and_yes_does_not_select() {
    let root = tempfile::tempdir().unwrap();
    for name in ["one", "two"] {
        fs::create_dir(root.path().join(name)).unwrap();
        fs::write(root.path().join(name).join("SKILL.md"), "Instructions").unwrap();
    }
    let local_home = tempfile::tempdir().unwrap();
    let listed = json_output(
        &run(
            local_home.path(),
            &[
                "--json",
                "skill",
                "add",
                root.path().to_str().unwrap(),
                "--list",
            ],
        ),
        0,
    );
    assert_eq!(listed["data"]["candidates"].as_array().unwrap().len(), 2);
    assert!(!local_home.path().join("state.sqlite3").exists());
    let (url, server) = serve(vec![user()]);
    let home = home(&url);
    let rejected = json_output(&run(home.path(), &add_args(root.path())), 2);
    assert_eq!(rejected["errors"][0]["code"], "SELECTION_REQUIRED");
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn dry_run_captures_complete_identity_without_upload_or_journal() {
    let root = source();
    let expected = tree(root.path());
    let (url, server) = serve(vec![user(), library()]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "add",
                root.path().to_str().unwrap(),
                "--dry-run",
            ],
        ),
        0,
    );
    assert_eq!(result["status"], "planned");
    let item = &result["data"]["request"]["items"][0];
    assert_eq!(item["tree_digest"], expected["tree_digest"]);
    assert_eq!(item["source"]["kind"], "local");
    assert_eq!(item["source"]["locator"].as_str().unwrap().len(), 64);
    assert_eq!(result["data"]["request"]["expected_generation"], 2);
    assert!(!result.to_string().contains(root.path().to_str().unwrap()));
    assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    assert_eq!(journal_count(home.path()), 0);
}

#[test]
fn all_packages_complete_before_one_atomic_installation() {
    let root = tempfile::tempdir().unwrap();
    let mut responses = vec![user(), library()];
    for name in ["alpha", "beta"] {
        let path = root.path().join(name);
        fs::create_dir(&path).unwrap();
        fs::write(path.join("SKILL.md"), format!("Instructions for {name}\n")).unwrap();
        responses.extend(transfer(&tree(&path)));
    }
    let mut receipt = operation("stored", "stored");
    receipt["data"]["skill_ids"] = json!([SKILL, SECOND]);
    receipt["data"]["revision_ids"] = json!([REVISION, UPLOAD]);
    responses.push((200, receipt.clone()));
    let (url, server) = serve(responses);
    let home = home(&url);
    let mut args = add_args(root.path());
    args.push("--all");
    assert_eq!(json_output(&run(home.path(), &args), 0), receipt);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 9);
    assert!(requests[4].starts_with(&format!(
        "POST /api/v1/skills/content/uploads/{UPLOAD}/complete "
    )));
    assert!(requests[7].starts_with(&format!(
        "POST /api/v1/skills/content/uploads/{UPLOAD}/complete "
    )));
    assert!(requests[8].starts_with("POST /api/v1/skills/installations "));
    let command = body(&requests[8]);
    assert_eq!(command["items"].as_array().unwrap().len(), 2);
    assert_eq!(command["items"][0]["name"], "alpha");
    assert_eq!(command["items"][1]["name"], "beta");
    assert_eq!(command["scope"], json!({"tools":[],"account_id":null}));
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    let saved: String = db
        .query_row("SELECT request_json FROM skill_commands", [], |r| r.get(0))
        .unwrap();
    assert_eq!(serde_json::from_str::<Value>(&saved).unwrap(), command);
}

#[test]
fn source_changes_after_capture_cannot_change_uploaded_bytes() {
    let root = source();
    let expected = tree(root.path());
    let mut responses = vec![user(), library()];
    responses.extend(transfer(&expected));
    responses.push((200, operation("stored", "stored")));
    let path = root.path().join("SKILL.md");
    let (url, server) = serve_with_hook(responses, move |index, _| {
        if index == 1 {
            fs::write(&path, "changed after capture").unwrap();
        }
    });
    let home = home(&url);
    json_output(&run(home.path(), &add_args(root.path())), 0);
    let requests = server.join().unwrap();
    assert!(requests[3].ends_with("Original instructions\n"));
    assert_eq!(
        body(&requests[5])["items"][0]["tree_digest"],
        expected["tree_digest"]
    );
}

#[test]
fn interrupted_file_upload_queries_same_plan_and_reuses_captured_bytes() {
    let root = source();
    let expected = tree(root.path());
    let responses = vec![
        user(),
        library(),
        upload(&expected),
        (0, Value::Null),
        upload(&expected),
        file(&expected),
        complete(&expected),
        (200, operation("stored", "stored")),
    ];
    let (url, server) = serve(responses);
    let home = home(&url);
    json_output(&run(home.path(), &add_args(root.path())), 0);
    let requests = server.join().unwrap();
    assert!(requests[4].starts_with(&format!("GET /api/v1/skills/content/uploads/{UPLOAD} ")));
    assert_eq!(requests[3], requests[5]);
}

#[test]
fn install_restart_uses_original_completed_content_without_source_or_replanning() {
    for accepted in [false, true] {
        let root = source();
        let expected = tree(root.path());
        let unavailable = json!({"error":{"code":"UNAVAILABLE","message":"temporary"}});
        let mut responses = vec![user(), library()];
        responses.extend(transfer(&expected));
        responses.extend([
            (0, Value::Null),
            (503, unavailable.clone()),
            (503, unavailable),
            user(),
        ]);
        if !accepted {
            responses.push((404,json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":"OPERATION_NOT_FOUND","message":"missing","object_id":null,"details":{}}]})));
        }
        let receipt = operation("stored", "stored");
        responses.push((200, receipt.clone()));
        let (url, server) = serve(responses);
        let home = home(&url);
        let first = json_output(&run(home.path(), &add_args(root.path())), 1);
        assert_eq!(first["status"], "unknown");
        fs::remove_file(root.path().join("SKILL.md")).unwrap();
        assert_eq!(
            json_output(&run(home.path(), &add_args(root.path())), 0),
            receipt
        );
        let requests = server.join().unwrap();
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("GET /api/v1/skills?effective="))
                .count(),
            1
        );
        assert_eq!(
            requests
                .iter()
                .filter(|r| r.starts_with("POST /api/v1/skills/content/uploads "))
                .count(),
            1
        );
        if !accepted {
            assert_eq!(body(&requests[5]), body(requests.last().unwrap()));
        }
    }
}

#[test]
fn forged_upload_receipts_stop_before_installation_and_are_not_retried() {
    for phase in ["begin", "file", "complete"] {
        let root = source();
        let expected = tree(root.path());
        let mut responses = vec![user(), library()];
        let mut steps = transfer(&expected);
        match phase {
            "begin" => {
                steps[0].1["data"]["manifest"]["entries"][0]["mode"] = json!(511);
                steps.truncate(1);
            }
            "file" => {
                steps[1].1["data"]["upload_id"] = json!(SECOND);
                steps.truncate(2);
            }
            _ => steps[2].1["data"]["tree_digest"] = json!("0".repeat(64)),
        }
        responses.extend(steps);
        let (url, server) = serve(responses);
        let home = home(&url);
        let result = json_output(&run(home.path(), &add_args(root.path())), 1);
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        assert!(server
            .join()
            .unwrap()
            .iter()
            .all(|r| !r.starts_with("POST /api/v1/skills/installations ")));
        assert_eq!(journal_count(home.path()), 0);
    }
}

#[test]
fn source_selection_flags_fail_before_credentials_or_network() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["--all", "--skill", "sample"],
        vec!["--list", "--all"],
        vec!["--list", "--skill", "sample"],
        vec!["--path", "../outside"],
        vec!["--tool", "claude", "--account-id", ACCOUNT],
    ] {
        let mut command = vec!["skill", "add", "missing"];
        command.extend(args);
        assert_eq!(run(home.path(), &command).status.code(), Some(2));
    }
}

#[test]
fn direct_and_subpath_selection_use_the_same_local_source_identity() {
    let root = tempfile::tempdir().unwrap();
    fs::create_dir(root.path().join("sample")).unwrap();
    fs::write(root.path().join("sample/SKILL.md"), "Instructions").unwrap();
    let (url, server) = serve(vec![user(), library(), user(), library()]);
    let home = home(&url);
    let direct_path = root.path().join("sample");
    let direct = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "add",
                direct_path.to_str().unwrap(),
                "--dry-run",
            ],
        ),
        0,
    );
    let nested = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "add",
                root.path().to_str().unwrap(),
                "--path",
                "sample",
                "--dry-run",
            ],
        ),
        0,
    );
    assert_eq!(
        direct["data"]["request"]["items"],
        nested["data"]["request"]["items"]
    );
    server.join().unwrap();
}

#[test]
fn expired_upload_does_not_create_an_installation_command() {
    let root = source();
    let expected = tree(root.path());
    let mut expired = upload(&expected);
    expired.1["status"] = json!("expired");
    expired.1["data"]["status"] = json!("expired");
    let (url, server) = serve(vec![user(), library(), expired]);
    let home = home(&url);
    let result = json_output(&run(home.path(), &add_args(root.path())), 1);
    assert_eq!(result["errors"][0]["code"], "UPLOAD_EXPIRED");
    assert_eq!(result["errors"][0]["object_id"], UPLOAD);
    assert_eq!(journal_count(home.path()), 0);
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn lost_upload_begin_reply_reuses_the_original_idempotency_key() {
    let root = source();
    let expected = tree(root.path());
    let mut responses = vec![user(), library(), (0, Value::Null)];
    responses.extend(transfer(&expected));
    responses.push((200, operation("stored", "stored")));
    let (url, server) = serve(responses);
    let home = home(&url);
    json_output(&run(home.path(), &add_args(root.path())), 0);
    let requests = server.join().unwrap();
    assert_eq!(body(&requests[2]), body(&requests[3]));
}
