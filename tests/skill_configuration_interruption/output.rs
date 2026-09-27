//! Blocked final output must preserve receipts and remain cancellable.

use super::*;

fn wait_for_output(child: &Child, stderr: bool) {
    use std::os::fd::AsRawFd;
    let fd = if stderr {
        child.stderr.as_ref().unwrap().as_raw_fd()
    } else {
        child.stdout.as_ref().unwrap().as_raw_fd()
    };
    let mut descriptor = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 10000) }, 1);
}

#[test]
fn blocked_accepted_rule_and_update_results_keep_the_received_operation() {
    for kind in ["rule", "update"] {
        for json_mode in [true, false] {
            let root = source();
            let snapshot = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
            let mut item = installation();
            item["revisions"][0]["content_digest"] = json!(snapshot.tree_digest());
            let mut receipt = operation("stored", "stored");
            receipt["data"]["warnings"] = json!(vec!["output warning ".repeat(30); 1000]);
            let (url, server) = serve(vec![
                user(),
                library(),
                (200, envelope(item)),
                (200, receipt.clone()),
                user(),
                (200, receipt),
            ]);
            let home = home(&url);
            let args = if kind == "rule" {
                vec!["enable", "sample", "--yes"]
            } else {
                vec![
                    "update",
                    "sample",
                    "--from",
                    root.path().to_str().unwrap(),
                    "--yes",
                ]
            };
            let mut child = spawn_mode(home.path(), &args, Stdio::null(), json_mode);
            wait_for_output(&child, !json_mode);
            interrupt(&child);
            stopped(&mut child);
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(130));
            assert!(!String::from_utf8_lossy(&output.stdout).contains("SKILL_INTERRUPTED"));
            let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
            let (state, operation): (String, String) = db
                .query_row(
                    "SELECT state, operation_id FROM skill_commands",
                    [],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert_eq!((state.as_str(), operation.as_str()), ("received", OP));
            let recovered = json_output(
                &run(home.path(), &["--json", "skill", "status", "--last"]),
                0,
            );
            assert_eq!(recovered["operation_id"], OP);
            assert_eq!(recovered["committed"], true);
            let calls = server.join().unwrap();
            assert_eq!(
                calls
                    .iter()
                    .filter(|request| request.starts_with("POST "))
                    .count(),
                1
            );
            assert!(calls[5].starts_with(&format!("GET /api/v1/skills/operations/{OP} ")));
        }
    }
}

#[test]
fn blocked_batch_update_output_remains_interruptible_without_journaling() {
    let items: Vec<Value> = (0..300)
        .map(|index| {
            let mut item = installation();
            item["id"] = json!(format!("{index:08x}-3333-4333-8333-333333333333"));
            item["name"] = json!(format!("local-{index}"));
            item
        })
        .collect();
    let listing = envelope(json!({"generation":2,"items":items}));
    assert!(listing.to_string().len() < 1024 * 1024);
    for json_mode in [true, false] {
        let (url, server) = serve(vec![user(), (200, listing.clone())]);
        let home = home(&url);
        let mut child = spawn_mode(
            home.path(),
            &["update", "--all", "--dry-run"],
            Stdio::null(),
            json_mode,
        );
        wait_for_output(&child, !json_mode);
        interrupt(&child);
        stopped(&mut child);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(130));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE_INTERRUPTED"));
        assert_eq!(count(home.path()), 0);
        assert!(server
            .join()
            .unwrap()
            .iter()
            .all(|request| request.starts_with("GET ")));
    }
}

#[test]
fn interruption_result_itself_cannot_block_on_an_unread_output_pipe() {
    let mut receipt = operation("pending", "pending");
    receipt["data"]["warnings"] = json!(vec!["retained pending result ".repeat(30); 700]);
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_with_hook(
        vec![
            user(),
            library(),
            (200, envelope(installation())),
            (200, receipt),
            (0, json!({})),
        ],
        move |index, request| {
            if index == 4 {
                assert!(request.starts_with("GET /api/v1/skills/operations/"));
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&url);
    let mut child = spawn(home.path(), &["enable", "sample", "--yes"], Stdio::null());
    ready(&ready_rx, &mut child, "operation waiting");
    interrupt(&child);
    stopped(&mut child);
    let output = child.wait_with_output().unwrap();
    assert_eq!(output.status.code(), Some(130));
    assert!(!output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE_INTERRUPTED"));
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    let state: String = db
        .query_row("SELECT state FROM skill_commands", [], |row| row.get(0))
        .unwrap();
    assert_eq!(state, "received");
    release_tx.send(()).unwrap();
    assert_eq!(server.join().unwrap().len(), 5);
}
