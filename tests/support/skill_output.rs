#![allow(dead_code)]

use super::support::BIN;
use rusqlite::Connection;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

pub fn terminal() -> (File, File) {
    let (mut master, mut slave) = (-1, -1);
    assert_eq!(
        unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    (unsafe { File::from_raw_fd(master) }, unsafe {
        File::from_raw_fd(slave)
    })
}

pub fn spawn(home: &Path, args: &[&str], json: bool, input: Stdio) -> Child {
    let mut command = Command::new(BIN);
    command.arg("--home").arg(home);
    if json {
        command.arg("--json");
    }
    command
        .args(["skill", "state"])
        .args(args)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("NO_COLOR", "1")
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

pub fn readable(child: &Child, stderr: bool) {
    let mut descriptor = libc::pollfd {
        fd: if stderr {
            child.stderr.as_ref().unwrap().as_raw_fd()
        } else {
            child.stdout.as_ref().unwrap().as_raw_fd()
        },
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 10000) }, 1);
}

pub fn signal(child: &Child) {
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
}

pub fn stopped(mut child: Child) -> Output {
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("state command failed to exit on interruption");
    }
    let output = child.wait_with_output().unwrap();
    assert_eq!(
        output.status.code(),
        Some(130),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    output
}

pub fn interrupt_output(child: Child, stderr: bool) -> Output {
    readable(&child, stderr);
    signal(&child);
    stopped(child)
}

pub fn count(home: &Path) -> i64 {
    Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |row| row.get(0))
        .unwrap()
}

pub fn received(home: &Path, operation: &str) {
    let (status, id): (String, String) = Connection::open(home.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT state,operation_id FROM skill_commands", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .unwrap();
    assert_eq!((status.as_str(), id.as_str()), ("received", operation));
}

/// Hold receipt persistence after the actual HTTP response was sent, then interrupt.
pub fn interrupt_receipt_write(
    responses: Vec<(u16, serde_json::Value)>,
    args: &[&str],
    operation: &str,
    json: bool,
) {
    use super::support::{home, json_output, serve_with_hook};
    use std::sync::mpsc;
    let last = responses.len() - 1;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_with_hook(responses, move |index, request| {
        if index == last {
            assert!(request.starts_with("POST "));
            ready_tx.send(()).unwrap();
            release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
        }
    });
    let home = home(&url);
    let mut child = spawn(home.path(), args, json, Stdio::null());
    if let Err(error) = ready_rx.recv_timeout(Duration::from_secs(10)) {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("receipt request missing: {error}");
    }
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    db.execute_batch("BEGIN EXCLUSIVE").unwrap();
    release_tx.send(()).unwrap();
    let requests = server.join().unwrap();
    let payload: serde_json::Value =
        serde_json::from_str(requests[last].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(payload["dry_run"], false);
    // The server has written the complete small response; receipt persistence cannot pass the lock.
    std::thread::sleep(Duration::from_millis(250));
    signal(&child);
    std::thread::sleep(Duration::from_millis(50));
    db.execute_batch("ROLLBACK").unwrap();
    let output = stopped(child);
    received(home.path(), operation);
    if json {
        let result = json_output(&output, 130);
        assert_eq!(result["committed"], true);
        assert_eq!(result["operation_id"], operation);
        assert_eq!(result["errors"], serde_json::json!([]));
    } else {
        assert!(output.stdout.is_empty());
        assert!(output.stderr.is_empty());
    }
}
