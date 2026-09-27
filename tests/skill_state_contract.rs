#![cfg(unix)]

#[path = "support/skill_state.rs"]
mod state;
#[path = "support/skill_cli.rs"]
mod support;

use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

use agent_remote_cli::skills::manifest::Manifest;
use serde_json::json;
use state::*;
use support::*;

#[test]
fn state_scope_and_cursor_validation_happens_before_login() {
    let home = tempfile::tempdir().unwrap();
    for args in [
        vec!["list"],
        vec!["list", "sample"],
        vec![
            "list",
            "sample",
            "--scope",
            "account-directory",
            "--account-id",
            ACCOUNT,
        ],
        vec!["list", "--scope", "item", "--account-id", ACCOUNT],
        vec!["list", "sample", "--account-id", ACCOUNT, "--limit", "201"],
        vec!["list", "sample", "--account-id", ACCOUNT, "--cursor", "bad"],
        vec!["diff", "--account-id", ACCOUNT],
        vec![
            "diff",
            "sample",
            "--account-id",
            ACCOUNT,
            "--cursor",
            "sample/memory",
        ],
        vec!["diff", "--checkpoint", OP, "--account-id", ACCOUNT],
        vec!["info", OP, "--cursor", "sample"],
        vec![
            "export",
            "--scope",
            "account-directory",
            "--checkpoint",
            OP,
            "--output",
            "unused",
        ],
    ] {
        let mut cmd = vec!["--json", "skill", "state"];
        cmd.extend(args);
        let output = run(home.path(), &cmd);
        assert_eq!(
            output.status.code(),
            Some(2),
            "{cmd:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn state_list_preserves_historical_epochs_and_separate_pending_cursors() {
    let history = json!({"items":[checkpoint(false)],"next_cursor":OP});
    let pending_page = json!({"items":[pending()],"next_cursor":SECOND});
    let (url, server) = serve(vec![
        (200, envelope(history.clone())),
        (200, envelope(pending_page.clone())),
    ]);
    let home = home(&url);
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "list",
                SKILL,
                "--account-id",
                ACCOUNT,
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(result["data"]["checkpoints"], history);
    assert_eq!(result["data"]["pending"], pending_page);
    let requests = server.join().unwrap();
    assert!(requests[0].starts_with(&format!("GET /api/v1/skills/state/checkpoints?account_id={ACCOUNT}&scope=item&skill={SKILL}&limit=1 ")));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/skills/state/pending?account_id={ACCOUNT}&scope=item&skill={SKILL}&limit=1 "
    )));
    assert!(requests.iter().all(|r| r
        .to_ascii_lowercase()
        .contains("authorization: bearer skill-user-token")));
    assert!(!home.path().join("state.sqlite3").exists());
}

#[test]
fn state_history_continues_each_directory_stream_independently() {
    let (url, server) = serve(vec![
        (200, envelope(json!({"items":[],"next_cursor":null}))),
        (200, envelope(json!({"items":[],"next_cursor":null}))),
    ]);
    let home = home(&url);
    json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "list",
                "--scope",
                "account-directory",
                "--account-id",
                ACCOUNT,
                "--cursor",
                OP,
                "--pending-cursor",
                SECOND,
            ],
        ),
        0,
    );
    let requests = server.join().unwrap();
    assert!(requests[0].contains(&format!("scope=account-directory&limit=100&cursor={OP}")));
    assert!(requests[1].contains(&format!(
        "scope=account-directory&limit=100&cursor={SECOND}"
    )));
}

#[test]
fn state_queries_reject_wrong_scope_forged_pending_and_repeating_pages() {
    for (history, pending_response) in [
        (json!({"items":[checkpoint(true)],"next_cursor":null}), None),
        (
            json!({"items":[checkpoint(false)],"next_cursor":SECOND}),
            None,
        ),
        (
            json!({"items":[checkpoint(false),checkpoint(false)],"next_cursor":null}),
            None,
        ),
        (
            json!({"items":[],"next_cursor":null}),
            Some({
                let mut p = pending();
                p["exportable_from_server"] = json!(true);
                envelope(json!({"items":[p],"next_cursor":null}))
            }),
        ),
    ] {
        let mut responses = vec![(200, envelope(history))];
        if let Some(p) = pending_response {
            responses.push((200, p));
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        let result = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "list",
                    "sample",
                    "--account-id",
                    ACCOUNT,
                ],
            ),
            1,
        );
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        server.join().unwrap();
    }
}

#[test]
fn state_info_retains_expired_metadata_and_directory_member_identities() {
    let mut expired = checkpoint(false);
    expired["retained"] = json!(false);
    expired["storage_location"] = json!("expired");
    let mut response = envelope(expired.clone());
    response["status"] = json!("state_expired");
    let (url, server) = serve(vec![(200, response)]);
    let home = home(&url);
    let result = json_output(
        &run(home.path(), &["--json", "skill", "state", "info", OP]),
        0,
    );
    assert_eq!(result["data"]["checkpoint"], expired);
    assert_eq!(result["status"], "state_expired");
    server.join().unwrap();
    let members = json!({"checkpoint_id":OP,"items":[{"entry_name":"sample","state_id":SECOND,"checkpoint_id":REVISION,"skill_id":SKILL,"origin":"user_library","revision_id":REVISION,"installation_epoch":5,"state_epoch":3}],"next_cursor":"sample"});
    let (url, server) = serve(vec![
        (200, envelope(checkpoint(true))),
        (200, envelope(members.clone())),
    ]);
    let home = support::home(&url);
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "info",
                OP,
                "--members",
                "--limit",
                "1",
            ],
        ),
        0,
    );
    assert_eq!(result["data"]["members"], members);
    server.join().unwrap();
}

#[test]
fn state_diff_preserves_baseline_and_fixes_continuation_to_exact_checkpoint() {
    let mut first = diff();
    first["next_cursor"] = json!("sample/memory");
    let (url, server) = serve(vec![(200, envelope(first.clone()))]);
    let home = home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "diff",
                    "sample",
                    "--account-id",
                    ACCOUNT,
                    "--limit",
                    "1"
                ]
            ),
            0
        )["data"],
        first
    );
    assert!(server.join().unwrap()[0].starts_with(&format!(
        "GET /api/v1/skills/state/diff?account_id={ACCOUNT}&scope=item&skill=sample&limit=1 "
    )));
    let mut more = diff();
    more["items"] = json!([]);
    let (url, server) = serve(vec![(200, envelope(more.clone()))]);
    let home = support::home(&url);
    assert_eq!(
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "diff",
                    "--checkpoint",
                    OP,
                    "--cursor",
                    "sample/memory"
                ]
            ),
            0
        )["data"],
        more
    );
    assert!(server.join().unwrap()[0].starts_with(&format!(
        "GET /api/v1/skills/state/checkpoints/{OP}/diff?limit=100&cursor=sample%2Fmemory "
    )));
}

#[test]
fn state_diff_rejects_substituted_checkpoint_or_unchanged_entries() {
    for data in [
        {
            let mut d = diff();
            d["checkpoint_id"] = json!(SECOND);
            d
        },
        {
            let mut d = diff();
            d["items"][0]["base"] = d["items"][0]["current"].clone();
            d
        },
    ] {
        let (url, server) = serve(vec![(200, envelope(data))]);
        let home = home(&url);
        let result = json_output(
            &run(
                home.path(),
                &["--json", "skill", "state", "diff", "--checkpoint", OP],
            ),
            1,
        );
        assert_eq!(result["errors"][0]["code"], "INVALID_SKILL_RESPONSE");
        server.join().unwrap();
    }
}

#[test]
fn export_verifies_binary_bytes_deduplicates_and_retains_links_without_instantiating_them() {
    let bytes = b"binary\0\xff";
    let entry = file("sample/data", bytes);
    let mut duplicate = entry.clone();
    duplicate.path = "sample/duplicate".to_owned();
    let manifest = Manifest {
        version: 1,
        entries: vec![
            directory("sample"),
            entry.clone(),
            duplicate,
            directory("sample/empty"),
            link("sample/link", "data", false),
            link("sample/runtime", "/usr/bin/python3", true),
        ],
    };
    let mut cp = checkpoint(false);
    let tree = tree(&mut cp, &manifest);
    let (url, server) = serve_raw(
        vec![
            Response::Json(envelope(cp)),
            Response::Json(envelope(tree.clone())),
            Response::File {
                bytes: bytes.to_vec(),
                digest: entry.sha256.clone(),
                length: bytes.len(),
            },
        ],
        |_| {},
    );
    let home = home(&url);
    let dest = home.path().join("export");
    fs::create_dir(&dest).unwrap();
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "export",
                SKILL,
                "--checkpoint",
                OP,
                "--output",
                dest.to_str().unwrap(),
            ],
        ),
        0,
    );
    assert_eq!(result["data"]["file_objects"], 1);
    assert_eq!(
        fs::read(dest.join("objects").join(&entry.sha256)).unwrap(),
        bytes
    );
    assert_eq!(
        serde_json::from_slice::<Manifest>(&fs::read(dest.join("manifest.json")).unwrap()).unwrap(),
        manifest
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&fs::read(dest.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(metadata["tree_digest"], tree["tree_digest"]);
    assert!(!dest.join("sample").exists());
    assert_eq!(
        fs::metadata(dest.join("objects").join(&entry.sha256))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 3);
    assert!(requests[2].contains(&format!("/files/{} ", entry.sha256)));
    assert!(fs::read_dir(home.path()).unwrap().all(|p| !p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".skill-export-")));
}

#[test]
fn export_rejects_wrong_account_source_scope_and_expired_content_before_download() {
    for (mut cp, extra, code) in [
        (
            checkpoint(false),
            vec!["--account-id", SECOND],
            "STATE_SCOPE_MISMATCH",
        ),
        (
            {
                let mut cp = checkpoint(false);
                cp["skill_id"] = json!(SECOND);
                cp
            },
            vec![],
            "STATE_SCOPE_MISMATCH",
        ),
        (checkpoint(true), vec![], "STATE_SCOPE_MISMATCH"),
        (
            {
                let mut cp = checkpoint(false);
                cp["retained"] = json!(false);
                cp["storage_location"] = json!("expired");
                cp
            },
            vec![],
            "STATE_EXPIRED",
        ),
    ] {
        let expired = cp["retained"] == false;
        let mut response = envelope(cp.take());
        if expired {
            response["status"] = json!("state_expired");
        }
        let (url, server) = serve(vec![(200, response)]);
        let home = home(&url);
        let dest = home.path().join("export");
        let mut args = vec![
            "--json",
            "skill",
            "state",
            "export",
            SKILL,
            "--checkpoint",
            OP,
            "--output",
            dest.to_str().unwrap(),
        ];
        args.extend(extra);
        let result = json_output(&run(home.path(), &args), 1);
        assert_eq!(result["errors"][0]["code"], code);
        assert!(!dest.exists());
        server.join().unwrap();
    }
}

#[test]
fn export_requires_directory_scope_for_cross_item_dependencies() {
    let manifest = Manifest {
        version: 1,
        entries: vec![
            directory("notes"),
            file("notes/data", b"data"),
            directory("sample"),
            link("sample/link", "../notes/data", false),
        ],
    };
    let mut cp = checkpoint(false);
    let mut tree = tree(&mut cp, &manifest);
    tree["dependency_roots"] = json!(["notes"]);
    let (url, server) = serve(vec![(200, envelope(cp)), (200, envelope(tree))]);
    let home = home(&url);
    let dest = home.path().join("export");
    let result = json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "export",
                SKILL,
                "--checkpoint",
                OP,
                "--output",
                dest.to_str().unwrap(),
            ],
        ),
        1,
    );
    assert_eq!(result["errors"][0]["code"], "STATE_SCOPE_MISMATCH");
    assert!(!dest.exists());
    server.join().unwrap();
}

#[test]
fn export_missing_corrupt_or_misclassified_bytes_never_publish_a_bundle() {
    for (actual, declared, binary) in [
        (b"bad!".as_slice(), 4, false),
        (b"dat".as_slice(), 4, false),
        (b"data".as_slice(), 5, false),
        (b"data".as_slice(), 4, true),
    ] {
        let mut entry = file("sample/data", b"data");
        if binary {
            entry.content_kind = agent_remote_cli::skills::manifest::ContentKind::Binary;
        }
        let manifest = Manifest {
            version: 1,
            entries: vec![directory("sample"), entry.clone()],
        };
        let mut cp = checkpoint(false);
        let tree = tree(&mut cp, &manifest);
        let (url, server) = serve_raw(
            vec![
                Response::Json(envelope(cp)),
                Response::Json(envelope(tree)),
                Response::File {
                    bytes: actual.to_vec(),
                    digest: entry.sha256,
                    length: declared,
                },
            ],
            |_| {},
        );
        let home = home(&url);
        let dest = home.path().join("export");
        json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "export",
                    SKILL,
                    "--checkpoint",
                    OP,
                    "--output",
                    dest.to_str().unwrap(),
                ],
            ),
            1,
        );
        assert!(!dest.exists());
        server.join().unwrap();
        assert!(fs::read_dir(home.path()).unwrap().all(|p| !p
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".skill-export-")));
    }
}

#[test]
fn export_preserves_nonempty_and_symlink_destinations() {
    for use_link in [false, true] {
        let manifest = Manifest {
            version: 1,
            entries: vec![directory("sample")],
        };
        let mut cp = checkpoint(false);
        let tree = tree(&mut cp, &manifest);
        let (url, server) = serve(vec![(200, envelope(cp)), (200, envelope(tree))]);
        let home = home(&url);
        let dest = home.path().join("export");
        let original = home.path().join("original");
        fs::create_dir(&original).unwrap();
        fs::write(original.join("keep"), b"keep").unwrap();
        if use_link {
            symlink(&original, &dest).unwrap();
        } else {
            fs::create_dir(&dest).unwrap();
            fs::write(dest.join("keep"), b"keep").unwrap();
        }
        let result = json_output(
            &run(
                home.path(),
                &[
                    "--json",
                    "skill",
                    "state",
                    "export",
                    SKILL,
                    "--checkpoint",
                    OP,
                    "--output",
                    dest.to_str().unwrap(),
                ],
            ),
            1,
        );
        assert_eq!(result["errors"][0]["code"], "SKILL_EXPORT_FAILED");
        assert_eq!(fs::read(dest.join("keep")).unwrap(), b"keep");
        assert_eq!(fs::read(original.join("keep")).unwrap(), b"keep");
        server.join().unwrap();
    }
}

#[test]
fn export_rechecks_destination_after_download_without_overwriting_a_new_file() {
    let entry = file("sample/data", b"data");
    let manifest = Manifest {
        version: 1,
        entries: vec![directory("sample"), entry.clone()],
    };
    let mut cp = checkpoint(false);
    let tree = tree(&mut cp, &manifest);
    let output = tempfile::tempdir().unwrap();
    let dest = output.path().join("export");
    let raced = dest.clone();
    let (url, server) = serve_raw(
        vec![
            Response::Json(envelope(cp)),
            Response::Json(envelope(tree)),
            Response::File {
                bytes: b"data".to_vec(),
                digest: entry.sha256,
                length: 4,
            },
        ],
        move |index| {
            if index == 2 {
                fs::create_dir(&raced).unwrap();
                fs::write(raced.join("keep"), b"new").unwrap();
            }
        },
    );
    let home = home(&url);
    json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "export",
                SKILL,
                "--checkpoint",
                OP,
                "--output",
                dest.to_str().unwrap(),
            ],
        ),
        1,
    );
    assert_eq!(fs::read(dest.join("keep")).unwrap(), b"new");
    assert!(!dest.join("manifest.json").exists());
    server.join().unwrap();
}

#[test]
fn explicitly_removed_checkpoint_can_export_a_verified_empty_manifest() {
    let manifest = Manifest {
        version: 1,
        entries: vec![],
    };
    let mut cp = checkpoint(false);
    let mut tree = tree(&mut cp, &manifest);
    tree["locally_removed"] = json!(true);
    let (url, server) = serve(vec![(200, envelope(cp)), (200, envelope(tree))]);
    let home = home(&url);
    let dest = home.path().join("export");
    json_output(
        &run(
            home.path(),
            &[
                "--json",
                "skill",
                "state",
                "export",
                SKILL,
                "--checkpoint",
                OP,
                "--output",
                dest.to_str().unwrap(),
            ],
        ),
        0,
    );
    assert_eq!(fs::read_dir(dest.join("objects")).unwrap().count(), 0);
    assert!(dest.join("checkpoint.json").is_file());
    server.join().unwrap();
}

#[test]
fn interrupted_export_discards_private_staging_and_reports_no_remote_mutation() {
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration;
    let manifest = Manifest {
        version: 1,
        entries: vec![directory("sample"), file("sample/data", b"data")],
    };
    let mut cp = checkpoint(false);
    let tree = tree(&mut cp, &manifest);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_raw(
        vec![
            Response::Json(envelope(cp)),
            Response::Json(envelope(tree)),
            Response::Disconnect,
        ],
        move |index| {
            if index == 2 {
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&url);
    let dest = home.path().join("export");
    let child = Command::new(BIN)
        .arg("--home")
        .arg(home.path())
        .args([
            "--json",
            "skill",
            "state",
            "export",
            SKILL,
            "--checkpoint",
            OP,
            "--output",
        ])
        .arg(&dest)
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
    assert_eq!(result["committed"], false);
    assert!(!dest.exists());
    assert!(fs::read_dir(home.path()).unwrap().all(|p| !p
        .unwrap()
        .file_name()
        .to_string_lossy()
        .starts_with(".skill-export-")));
}

#[path = "support/skill_output.rs"]
mod output_support;
#[path = "skill_state_output/query.rs"]
mod query_output;
