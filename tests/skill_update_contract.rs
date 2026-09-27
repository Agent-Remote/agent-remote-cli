#![cfg(unix)]
#[path = "support/skill_git.rs"]
mod git_support;
#[path = "support/skill_cli.rs"]
mod support;

use agent_remote_cli::skills::snapshot::{PackageLimits, PackageSnapshot};
use git_support::{git, GitFixture};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;
use support::*;

const USER: &str = "88888888-8888-4888-8888-888888888888";
const UPLOAD: &str = "66666666-6666-4666-8666-666666666666";
fn user() -> (u16, Value) {
    (200, json!({"data":{"id":USER}}))
}
fn library(items: Vec<Value>, generation: i64) -> (u16, Value) {
    (
        200,
        envelope(json!({"generation":generation,"items":items,"local_items":[]})),
    )
}
fn details(item: &Value) -> (u16, Value) {
    (200, envelope(item.clone()))
}
fn body(request: &str) -> Value {
    serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap()
}
fn package(root: &Path) -> Value {
    let snapshot = PackageSnapshot::capture(root, PackageLimits::default()).unwrap();
    json!({"tree_digest":snapshot.tree_digest(),"manifest":snapshot.manifest()})
}
fn git_item(fixture: &GitFixture) -> Value {
    let mut item = installation();
    item["source"] = json!({"kind":"git","locator":fixture.url,"subpath":"one"});
    item["tracking"] = json!({"ref_kind":"branch","ref":"main","commit":fixture.commit});
    item["revisions"][0]["provenance"] = item["tracking"].clone();
    item["revisions"][0]["content_digest"] =
        package(&fixture.repo.join("one"))["tree_digest"].clone();
    item
}
fn source() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("SKILL.md"),
        "---\nname: sample\n---\nNew instructions\n",
    )
    .unwrap();
    root
}
fn transfer(tree: &Value) -> Vec<(u16, Value)> {
    let mut plan = envelope(
        json!({"id":UPLOAD,"status":"staged","tree_digest":tree["tree_digest"],"manifest":tree["manifest"],"reserved_bytes":100,"expires_at":"2099-01-01T00:00:00Z"}),
    );
    plan["status"] = json!("staged");
    let mut file = envelope(
        json!({"upload_id":UPLOAD,"digest":tree["manifest"]["entries"][0]["sha256"],"created":true}),
    );
    file["status"] = json!("persisted");
    let mut complete = envelope(tree.clone());
    complete["status"] = json!("stored");
    complete["committed"] = json!(true);
    vec![(200, plan), (200, file), (200, complete)]
}
fn journal_count(home: &Path) -> i64 {
    rusqlite::Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |row| row.get(0))
        .unwrap()
}

#[test]
fn check_reads_complete_sources_and_reports_pinned_local_and_changes_without_mutation() {
    let fixture = GitFixture::new();
    let up_to_date = git_item(&fixture);
    let mut pinned = up_to_date.clone();
    pinned["id"] = json!(ACCOUNT);
    pinned["name"] = json!("pinned");
    pinned["tracking"]["ref_kind"] = json!("fixed");
    pinned["source"]["locator"] = json!("https://127.0.0.1:1/unreachable.git");
    let mut local = installation();
    local["id"] = json!(UPLOAD);
    local["name"] = json!("local");
    let (server, requests) = serve(vec![library(vec![up_to_date.clone(), pinned, local], 2)]);
    let home = home(&server);
    let output = fixture
        .cli(home.path())
        .args(["skill", "check"])
        .output()
        .unwrap();
    let result = json_output(&output, 0);
    let rows = result["data"]["items"].as_array().unwrap();
    assert_eq!(
        rows.iter()
            .map(|row| row["status"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["up_to_date", "pinned", "local_source"]
    );
    assert_eq!(result["committed"], false);
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/skills?"));
    if home.path().join("state.sqlite3").exists() {
        let db = rusqlite::Connection::open(home.path().join("state.sqlite3")).unwrap();
        assert_eq!(
            db.query_row(
                "SELECT count(*) FROM sqlite_master WHERE name='skill_commands'",
                [],
                |row| row.get::<_, i64>(0)
            )
            .unwrap(),
            0
        );
    }
    fs::write(
        fixture.repo.join("one/SKILL.md"),
        "---\nname: sample\n---\nNew upstream content\n",
    )
    .unwrap();
    git(&fixture.repo, &["add", "one"]);
    git(&fixture.repo, &["commit", "-m", "changed"]);
    let (server, requests) = serve(vec![details(&up_to_date)]);
    let home = support::home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "check", "sample"])
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(result["data"]["items"][0]["status"], "update_available");
    assert_eq!(requests.join().unwrap().len(), 1);
}

#[test]
fn local_update_requires_explicit_source_and_preserves_original_identity_across_devices() {
    let root = source();
    let tree = package(root.path());
    let item = installation();
    let (server, requests) = serve(vec![user(), library(vec![item.clone()], 2), details(&item)]);
    let home = home(&server);
    let output = run(
        home.path(),
        &["--json", "skill", "update", "sample", "--yes"],
    );
    assert_eq!(
        json_output(&output, 2)["errors"][0]["code"],
        "LOCAL_SOURCE_REQUIRED"
    );
    assert_eq!(journal_count(home.path()), 0);
    assert_eq!(requests.join().unwrap().len(), 3);
    let mut responses = vec![user(), library(vec![item.clone()], 2), details(&item)];
    responses.extend(transfer(&tree));
    responses.push((200, operation("stored", "stored")));
    let (server, requests) = serve(responses);
    let home = support::home(&server);
    let output = run(
        home.path(),
        &[
            "--json",
            "skill",
            "update",
            "sample",
            "--from",
            root.path().to_str().unwrap(),
            "--yes",
        ],
    );
    json_output(&output, 0);
    let requests = requests.join().unwrap();
    let request = body(requests.last().unwrap());
    assert!(requests
        .last()
        .unwrap()
        .starts_with("POST /api/v1/skills/updates "));
    assert_eq!(request["item"]["source"], item["source"]);
    assert_eq!(request["item"]["tree_digest"], tree["tree_digest"]);
    assert_eq!(request["stage"], false);
    assert_eq!(request["switch_tracking"], false);
    assert_eq!(request["skill"], SKILL);
    assert_eq!(journal_count(home.path()), 1);
    assert!(!request.to_string().contains(root.path().to_str().unwrap()));
}

#[test]
fn dry_run_has_complete_content_and_never_uploads_or_journals() {
    let root = source();
    let item = installation();
    let (server, requests) = serve(vec![user(), library(vec![item.clone()], 2), details(&item)]);
    let home = home(&server);
    let output = run(
        home.path(),
        &[
            "--json",
            "skill",
            "update",
            "sample",
            "--from",
            root.path().to_str().unwrap(),
            "--dry-run",
        ],
    );
    let result = json_output(&output, 0);
    assert_eq!(result["status"], "planned");
    assert_eq!(
        result["data"]["request"]["item"]["tree_digest"],
        package(root.path())["tree_digest"]
    );
    assert_eq!(journal_count(home.path()), 0);
    assert!(requests
        .join()
        .unwrap()
        .iter()
        .all(|r| r.starts_with("GET ")));
}

#[test]
fn fixed_git_requires_ref_and_stage_reuses_retained_content_without_upload() {
    let fixture = GitFixture::new();
    let mut item = git_item(&fixture);
    item["tracking"]["ref_kind"] = json!("fixed");
    let (server, requests) = serve(vec![user(), library(vec![item.clone()], 2), details(&item)]);
    let home = home(&server);
    let output = fixture
        .cli(home.path())
        .args(["skill", "update", "sample", "--yes"])
        .output()
        .unwrap();
    assert_eq!(
        json_output(&output, 2)["errors"][0]["code"],
        "SOURCE_PINNED"
    );
    assert_eq!(requests.join().unwrap().len(), 3);
    let mut receipt = operation("stored", "stored");
    receipt["data"]["changed"] = json!(false);
    receipt["data"]["generation"] = json!(2);
    let (server, requests) = serve(vec![
        user(),
        library(vec![item.clone()], 2),
        details(&item),
        (200, receipt.clone()),
    ]);
    let home = support::home(&server);
    let output = fixture
        .cli(home.path())
        .args([
            "skill", "update", "sample", "--ref", "v1", "--stage", "--yes",
        ])
        .output()
        .unwrap();
    assert_eq!(json_output(&output, 0), receipt);
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 4);
    let request = body(&requests[3]);
    assert_eq!(request["stage"], true);
    assert_eq!(request["switch_tracking"], true);
    assert_eq!(
        request["item"]["provenance"],
        json!({"ref_kind":"tag","ref":"v1","commit":fixture.commit})
    );
}

#[test]
fn changed_name_path_and_known_moved_tag_fail_before_upload() {
    for kind in ["name", "path", "tag"] {
        let fixture = GitFixture::new();
        let mut item = git_item(&fixture);
        if kind == "name" {
            fs::write(
                fixture.repo.join("one/SKILL.md"),
                "---\nname: renamed\n---\nChanged",
            )
            .unwrap();
            git(&fixture.repo, &["add", "one"]);
            git(&fixture.repo, &["commit", "-m", "rename"]);
        } else if kind == "path" {
            item["source"]["subpath"] = json!("missing");
        } else {
            item["revisions"][0]["provenance"] =
                json!({"ref_kind":"tag","ref":"v1","commit":"a".repeat(40)});
        }
        let (server, requests) =
            serve(vec![user(), library(vec![item.clone()], 2), details(&item)]);
        let home = home(&server);
        let mut command = fixture.cli(home.path());
        command.args(["skill", "update", "sample", "--yes"]);
        if kind == "tag" {
            command.args(["--ref", "v1"]);
        }
        let result = json_output(&command.output().unwrap(), 1);
        assert_eq!(
            result["errors"][0]["code"],
            if kind == "tag" {
                "SOURCE_DRIFT"
            } else {
                "SOURCE_LAYOUT_CHANGED"
            }
        );
        if kind != "tag" {
            assert_eq!(result["errors"][0]["details"]["expected"]["name"], "sample");
        }
        assert_eq!(requests.join().unwrap().len(), 3);
    }
}

#[test]
fn single_update_recovers_the_original_request_before_reading_a_missing_source() {
    let root = source();
    let item = installation();
    let tree = package(root.path());
    let unavailable = json!({"error":{"code":"UNAVAILABLE","message":"temporary"}});
    let mut responses = vec![user(), library(vec![item.clone()], 2), details(&item)];
    responses.extend(transfer(&tree));
    responses.extend([
        (0, Value::Null),
        (503, unavailable.clone()),
        (503, unavailable),
        user(),
        (200, operation("stored", "stored")),
    ]);
    let (server, requests) = serve(responses);
    let home = home(&server);
    let args = [
        "--json",
        "skill",
        "update",
        "sample",
        "--from",
        root.path().to_str().unwrap(),
        "--yes",
    ];
    assert_eq!(
        json_output(&run(home.path(), &args), 1)["status"],
        "unknown"
    );
    fs::remove_file(root.path().join("SKILL.md")).unwrap();
    assert_eq!(json_output(&run(home.path(), &args), 0)["operation_id"], OP);
    let requests = requests.join().unwrap();
    assert_eq!(requests.len(), 11);
    assert!(requests[10].starts_with("GET /api/v1/skills/operations?key="));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /api/v1/skills/updates "))
            .count(),
        1
    );
}

#[test]
fn batch_recovers_missing_library_items_before_fresh_source_acquisition() {
    let mut fixture = GitFixture::new();
    let item = git_item(&fixture);
    let unavailable = json!({"error":{"code":"UNAVAILABLE","message":"temporary"}});
    let responses = vec![
        user(),
        library(vec![item.clone()], 2),
        library(vec![item.clone()], 2),
        details(&item),
        (0, Value::Null),
        (503, unavailable.clone()),
        (503, unavailable),
        user(),
        (200, operation("stored", "stored")),
        library(vec![], 3),
    ];
    let (server, requests) = serve(responses);
    let home = home(&server);
    let output = fixture
        .cli(home.path())
        .args(["skill", "update", "--all", "--yes"])
        .output()
        .unwrap();
    assert_eq!(
        json_output(&output, 1)["data"]["items"][0]["status"],
        "unknown"
    );
    fixture.server.kill().unwrap();
    fixture.server.wait().unwrap();
    fs::remove_dir_all(&fixture.repo).unwrap();
    let output = fixture
        .cli(home.path())
        .args(["skill", "update", "--all", "--yes"])
        .output()
        .unwrap();
    let result = json_output(&output, 0);
    assert_eq!(result["committed"], true);
    assert_eq!(result["data"]["items"][0]["result"]["operation_id"], OP);
    let requests = requests.join().unwrap();
    assert!(requests[8].starts_with("GET /api/v1/skills/operations?key="));
    assert_eq!(
        requests
            .iter()
            .filter(|r| r.starts_with("POST /api/v1/skills/updates "))
            .count(),
        1
    );
}

#[test]
fn invalid_update_combinations_fail_without_credentials_or_network() {
    let home = tempfile::tempdir().unwrap();
    for flags in [
        vec!["--all", "--ref", "main"],
        vec!["--all", "--stage"],
        vec!["--all", "--from", "./source"],
        vec!["sample", "--all"],
        vec![],
        vec!["sample", "--ref", "main", "--from", "./source"],
    ] {
        let mut args = vec!["skill", "update"];
        args.extend(flags);
        assert_eq!(run(home.path(), &args).status.code(), Some(2));
    }
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn batch_keeps_partial_success_and_each_fresh_item_has_its_own_generation() {
    let fixture = GitFixture::new();
    fs::create_dir(fixture.repo.join("two")).unwrap();
    fs::write(
        fixture.repo.join("two/SKILL.md"),
        "---\nname: other\n---\nSecond skill",
    )
    .unwrap();
    git(&fixture.repo, &["add", "two"]);
    git(&fixture.repo, &["commit", "-m", "second"]);
    let mut first = git_item(&fixture);
    let first_digest = first["revisions"][0]["content_digest"].clone();
    let mut cached = first["revisions"][0].clone();
    cached["id"] = json!("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa");
    cached["number"] = json!(2);
    first["revisions"][0]["content_digest"] = json!("b".repeat(64));
    first["revisions"].as_array_mut().unwrap().push(cached);
    let mut second = first.clone();
    second["id"] = json!("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb");
    second["name"] = json!("other");
    second["source"]["subpath"] = json!("two");
    second["revisions"][1]["id"] = json!("cccccccc-cccc-4ccc-8ccc-cccccccccccc");
    second["revisions"][1]["content_digest"] =
        package(&fixture.repo.join("two"))["tree_digest"].clone();
    let mut bad = first.clone();
    bad["id"] = json!(UPLOAD);
    bad["name"] = json!("unavailable");
    bad["source"]["locator"] = json!("https://127.0.0.1:1/unavailable.git");
    let mut pinned = first.clone();
    pinned["id"] = json!(ACCOUNT);
    pinned["name"] = json!("pinned");
    pinned["tracking"]["ref_kind"] = json!("fixed");
    pinned["source"]["subpath"] = json!("historical");
    let mut local = installation();
    local["id"] = json!(OP);
    local["name"] = json!("local");
    let items = vec![local, pinned, bad.clone(), first.clone(), second.clone()];
    let mut receipt_one = operation("stored", "stored");
    receipt_one["data"]["revision_ids"] = json!([first["revisions"][1]["id"]]);
    let mut receipt_two = receipt_one.clone();
    receipt_two["operation_id"] = json!(UPLOAD);
    receipt_two["data"]["generation"] = json!(4);
    receipt_two["data"]["skill_ids"] = json!([second["id"]]);
    receipt_two["data"]["revision_ids"] = json!([second["revisions"][1]["id"]]);
    let (server, requests) = serve(vec![
        user(),
        library(items.clone(), 2),
        library(items.clone(), 2),
        details(&bad),
        library(items.clone(), 2),
        details(&first),
        (200, receipt_one.clone()),
        library(items, 3),
        details(&second),
        (200, receipt_two.clone()),
    ]);
    let home = home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "update", "--all", "--yes"])
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["status"], "partial");
    assert_eq!(result["committed"], true);
    let rows = result["data"]["items"].as_array().unwrap();
    assert_eq!(rows.len(), 5);
    assert_eq!(rows[0]["status"], "local_source");
    assert_eq!(rows[1]["status"], "pinned");
    assert_eq!(rows[2]["status"], "failed");
    assert_eq!(rows[3]["result"], receipt_one);
    assert_eq!(rows[4]["result"], receipt_two);
    assert_eq!(result["errors"][0]["object_id"], UPLOAD);
    let requests = requests.join().unwrap();
    let posts = requests
        .iter()
        .filter(|r| r.starts_with("POST "))
        .collect::<Vec<_>>();
    assert_eq!(posts.len(), 2);
    assert_eq!(body(posts[0])["expected_generation"], 2);
    assert_eq!(body(posts[1])["expected_generation"], 3);
    assert_eq!(body(posts[0])["item"]["tree_digest"], first_digest);
    assert_ne!(
        body(posts[0])["idempotency_key"],
        body(posts[1])["idempotency_key"]
    );
}

#[test]
fn check_reports_source_failure_without_mutating_and_rejects_mismatched_details() {
    let fixture = GitFixture::new();
    let mut item = git_item(&fixture);
    item["source"]["subpath"] = json!("missing");
    let (server, requests) = serve(vec![details(&item)]);
    let home = home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "check", "sample"])
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["errors"][0]["code"], "SOURCE_LAYOUT_CHANGED");
    assert_eq!(result["committed"], false);
    assert_eq!(requests.join().unwrap().len(), 1);
    let mut wrong = item.clone();
    wrong["name"] = json!("different");
    let (server, requests) = serve(vec![
        user(),
        library(vec![wrong.clone()], 2),
        details(&wrong),
    ]);
    let home = support::home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "update", "sample", "--yes"])
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
    assert_eq!(requests.join().unwrap().len(), 3);
    assert_eq!(journal_count(home.path()), 0);
}

#[test]
fn forged_update_receipt_keeps_unknown_acceptance_and_the_original_key() {
    let fixture = GitFixture::new();
    let item = git_item(&fixture);
    let mut forged = operation("stored", "stored");
    forged["data"]["skill_ids"] = json!([UPLOAD]);
    let (server, requests) = serve(vec![
        user(),
        library(vec![item.clone()], 2),
        details(&item),
        (200, forged),
    ]);
    let home = home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "update", "sample", "--yes"])
            .output()
            .unwrap(),
        1,
    );
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["errors"][0]["details"]["commit_state"], "unknown");
    assert_eq!(result["retryable"], false);
    let requests = requests.join().unwrap();
    assert_eq!(
        result["errors"][0]["details"]["idempotency_key"],
        body(&requests[3])["idempotency_key"]
    );
    let state: String = rusqlite::Connection::open(home.path().join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT state FROM skill_commands", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "pending");
}

#[test]
fn interrupt_during_update_submission_retains_unknown_acceptance_and_exits_130() {
    use std::process::Stdio;
    use std::sync::mpsc;
    use std::time::Duration;
    let fixture = GitFixture::new();
    let item = git_item(&fixture);
    let (ready_send, ready) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (server, requests) = serve_with_hook(
        vec![
            user(),
            library(vec![item.clone()], 2),
            details(&item),
            (0, Value::Null),
        ],
        move |index, _| {
            if index == 3 {
                ready_send.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&server);
    let child = fixture
        .cli(home.path())
        .args(["skill", "update", "sample", "--yes"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    ready.recv_timeout(Duration::from_secs(10)).unwrap();
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let output = child.wait_with_output().unwrap();
    release.send(()).unwrap();
    let result = json_output(&output, 130);
    assert_eq!(result["status"], "unknown");
    assert_eq!(result["errors"][0]["code"], "SKILL_INTERRUPTED");
    assert_eq!(result["errors"][0]["details"]["commit_state"], "unknown");
    let requests = requests.join().unwrap();
    assert_eq!(
        result["errors"][0]["details"]["idempotency_key"],
        body(&requests[3])["idempotency_key"]
    );
    let state: String = rusqlite::Connection::open(home.path().join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT state FROM skill_commands", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "pending");
}

#[test]
fn tracked_branch_is_stable_when_remote_head_changes_or_a_same_named_tag_appears() {
    let fixture = GitFixture::new();
    let item = git_item(&fixture);
    git(&fixture.repo, &["checkout", "-b", "alternate"]);
    fs::write(
        fixture.repo.join("one/SKILL.md"),
        "---\nname: sample\n---\nDifferent default branch",
    )
    .unwrap();
    git(&fixture.repo, &["add", "one"]);
    git(&fixture.repo, &["commit", "-m", "alternate"]);
    git(&fixture.repo, &["tag", "main"]);
    let (server, requests) = serve(vec![details(&item)]);
    let home = home(&server);
    let result = json_output(
        &fixture
            .cli(home.path())
            .args(["skill", "check", "sample"])
            .output()
            .unwrap(),
        0,
    );
    assert_eq!(result["data"]["items"][0]["status"], "up_to_date");
    assert_eq!(
        result["data"]["items"][0]["result"]["data"]["observed"]["provenance"],
        item["tracking"]
    );
    assert_eq!(requests.join().unwrap().len(), 1);
}
