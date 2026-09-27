#![cfg(unix)]
#[path = "support/skill_prune.rs"]
mod prune;
#[path = "support/skill_cli.rs"]
mod support;

use prune::*;
use rusqlite::Connection;
use std::os::fd::AsRawFd;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::{home, run, ACCOUNT, BIN};

fn stopped(child: &mut Child, code: i32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            assert_eq!(status.code(), Some(code));
            return;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("prune did not stop while its output pipe was blocked");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn blocked_disclosure_output_is_cancellable_without_submission_or_extra_output() {
    for mode in ["dry-run", "submit", "status", "deadline"] {
        let mut replies = reads(1101);
        if matches!(mode, "status" | "deadline") {
            replies.extend([Reply::Receipt(1101), Reply::User, Reply::Receipt(1101)]);
            for offset in (0..1101).step_by(100) {
                replies.push(Reply::Data(200, entries(offset, 1101)));
            }
            replies.push(Reply::Data(200, progress()));
        }
        let (url, server) = serve(replies);
        let home = home(&url);
        let prune = [
            "--json",
            "skill",
            "state",
            "prune",
            "sample",
            "--account-id",
            ACCOUNT,
        ];
        let mut args = prune.to_vec();
        args.push(if mode == "dry-run" {
            "--dry-run"
        } else {
            "--yes"
        });
        if matches!(mode, "status" | "deadline") {
            assert!(run(home.path(), &args).status.success());
            args = vec!["--json", "skill", "status", "--last"];
            if mode == "deadline" {
                args.extend(["--wait", "--timeout", "2"]);
            }
        }
        let mut child = Command::new(BIN)
            .arg("--home")
            .arg(home.path())
            .args(args)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let fd = if mode == "submit" {
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
        assert_ne!(descriptor.revents & libc::POLLIN, 0);
        // Keep both pipes unread: the disclosure is larger than their capacity.
        let code = if mode == "deadline" {
            1
        } else {
            assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
            130
        };
        stopped(&mut child, code);
        let count: i64 = Connection::open(home.path().join("state.sqlite3"))
            .unwrap()
            .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, i64::from(matches!(mode, "status" | "deadline")));
        let calls = server.join().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|c| c.starts_with("POST /api/v1/skills/state/prune HTTP"))
                .count(),
            count as usize
        );
    }
}

#[test]
fn interruption_during_preview_or_submission_preserves_correct_acceptance_state() {
    for submitting in [false, true] {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let mut replies = if submitting {
            reads(1)
        } else {
            vec![Reply::User]
        };
        replies.push(Reply::Block(ready_tx, release_rx));
        let (url, server) = serve(replies);
        let home = home(&url);
        let mut child = Command::new(BIN)
            .arg("--home")
            .arg(home.path())
            .args([
                "--json",
                "skill",
                "state",
                "prune",
                "sample",
                "--account-id",
                ACCOUNT,
                "--yes",
            ])
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
        stopped(&mut child, 130);
        let output = support::json_output(&child.wait_with_output().unwrap(), 130);
        assert_eq!(output["errors"][0]["code"], "SKILL_INTERRUPTED");
        let database = Connection::open(home.path().join("state.sqlite3")).unwrap();
        if submitting {
            assert_eq!(output["errors"][0]["details"]["commit_state"], "unknown");
            let state: String = database
                .query_row("SELECT state FROM skill_commands", [], |r| r.get(0))
                .unwrap();
            assert_eq!(state, "pending");
        } else {
            let count: i64 = database
                .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
                .unwrap();
            assert_eq!(count, 0);
        }
        release_tx.send(()).unwrap();
        server.join().unwrap();
    }
}
