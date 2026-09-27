#![cfg(unix)]
#[path = "support/skill_cli.rs"]
mod support;

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use agent_remote_cli::skills::snapshot::{PackageLimits, PackageSnapshot};
use rusqlite::Connection;
use serde_json::{json, Value};
use support::*;

const USER: &str = "88888888-8888-4888-8888-888888888888";
const UPLOAD: &str = "66666666-6666-4666-8666-666666666666";

fn user() -> (u16, Value) {
    (200, json!({"data":{"id":USER}}))
}
fn library() -> (u16, Value) {
    (
        200,
        envelope(json!({"generation":2,"items":[installation()]})),
    )
}
fn source() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("SKILL.md"),
        "---\nname: sample\n---\nInstructions\n",
    )
    .unwrap();
    root
}
fn count(path: &Path) -> i64 {
    if !path.join("state.sqlite3").exists() {
        return 0;
    }
    Connection::open(path.join("state.sqlite3"))
        .unwrap()
        .query_row("SELECT count(*) FROM skill_commands", [], |r| r.get(0))
        .unwrap()
}
fn spawn(path: &Path, args: &[&str], input: Stdio) -> Child {
    spawn_mode(path, args, input, true)
}
fn spawn_mode(path: &Path, args: &[&str], input: Stdio, json: bool) -> Child {
    let mut command = Command::new(BIN);
    command.arg("--home").arg(path);
    if json {
        command.arg("--json");
    }
    command
        .arg("skill")
        .args(args)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(input)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn interrupt(child: &Child) {
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGINT) }, 0);
}
fn stopped(child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(10));
    }
    if child.try_wait().unwrap().is_none() {
        child.kill().unwrap();
        child.wait().unwrap();
        panic!("configuration command ignored interruption");
    }
}
fn terminal() -> (File, File) {
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
fn prompt(child: &mut Child, ending: &'static [u8]) -> std::thread::JoinHandle<Vec<u8>> {
    let mut stderr = child.stderr.take().unwrap();
    let (send, receive) = mpsc::channel();
    let reader = std::thread::spawn(move || {
        let mut send = Some(send);
        let mut bytes = Vec::new();
        let mut byte = [0];
        while stderr.read(&mut byte).unwrap() > 0 {
            bytes.push(byte[0]);
            assert!(bytes.len() < 256 * 1024);
            if bytes.ends_with(ending) {
                if let Some(send) = send.take() {
                    send.send(()).unwrap();
                }
            }
        }
        bytes
    });
    if let Err(error) = receive.recv_timeout(Duration::from_secs(10)) {
        let _ = child.kill();
        child.wait().unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        panic!(
            "prompt {error}: stdout={output}, stderr={}",
            String::from_utf8_lossy(&reader.join().unwrap())
        );
    }
    reader
}

#[test]
fn blocked_preparation_reads_interrupt_without_a_configuration_request() {
    for kind in ["rule", "add", "update"] {
        for stage in 0..2 {
            let root = source();
            let (ready_tx, ready_rx) = mpsc::channel();
            let (release_tx, release_rx) = mpsc::channel();
            let mut responses = if stage == 0 { vec![] } else { vec![user()] };
            responses.push((0, json!({})));
            let (url, server) = serve_with_hook(responses, move |index, request| {
                if index == stage {
                    assert!(request.starts_with("GET "));
                    ready_tx.send(()).unwrap();
                    release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
                }
            });
            let home = home(&url);
            let args = match kind {
                "rule" => vec!["disable", "sample", "--yes"],
                "add" => vec!["add", root.path().to_str().unwrap(), "--yes"],
                _ => vec![
                    "update",
                    "sample",
                    "--from",
                    root.path().to_str().unwrap(),
                    "--yes",
                ],
            };
            let mut child = spawn(home.path(), &args, Stdio::null());
            ready(&ready_rx, &mut child, &format!("{kind}/{stage}"));
            interrupt(&child);
            stopped(&mut child);
            let result = json_output(&child.wait_with_output().unwrap(), 130);
            assert!(!result["committed"].as_bool().unwrap());
            assert_eq!(count(home.path()), 0);
            release_tx.send(()).unwrap();
            assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
        }
    }
}

#[test]
fn real_terminal_selection_and_confirmation_can_be_interrupted_without_input() {
    for (kind, json_mode) in ["selection", "add", "rule", "update"]
        .into_iter()
        .flat_map(|kind| [false, true].map(|json| (kind, json)))
    {
        let root = source();
        if kind == "selection" {
            fs::remove_file(root.path().join("SKILL.md")).unwrap();
            for name in ["one", "two"] {
                fs::create_dir(root.path().join(name)).unwrap();
                fs::write(root.path().join(name).join("SKILL.md"), "Instructions").unwrap();
            }
        }
        let mut responses = vec![user()];
        if kind != "selection" {
            responses.push(library());
        }
        if matches!(kind, "rule" | "update") {
            responses.push((200, envelope(installation())));
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        let (_master, slave) = terminal();
        let args = match kind {
            "rule" => vec!["enable", "sample"],
            "update" => vec!["update", "sample", "--from", root.path().to_str().unwrap()],
            _ => vec!["add", root.path().to_str().unwrap()],
        };
        let mut child = spawn_mode(home.path(), &args, Stdio::from(slave), json_mode);
        let reader = prompt(
            &mut child,
            if kind == "selection" {
                b"or * for all: "
            } else {
                b"[y/N] "
            },
        );
        interrupt(&child);
        stopped(&mut child);
        let output = child.wait_with_output().unwrap();
        if json_mode {
            let result = json_output(&output, 130);
            assert_eq!(result["committed"], false);
        } else {
            assert_eq!(output.status.code(), Some(130));
            assert!(output.stdout.is_empty());
        }
        assert_eq!(count(home.path()), 0);
        reader.join().unwrap();
        assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
    }
}

#[test]
fn terminal_rule_confirmation_keeps_yes_and_no_behavior() {
    for yes in [false, true] {
        let mut responses = vec![user(), library(), (200, envelope(installation()))];
        if yes {
            responses.push((200, operation("stored", "stored")));
        }
        let (url, server) = serve(responses);
        let home = home(&url);
        let (mut master, slave) = terminal();
        let mut child = spawn(home.path(), &["enable", "sample"], Stdio::from(slave));
        let reader = prompt(&mut child, b"[y/N] ");
        master
            .write_all(if yes { b"yes\n" } else { b"no\n" })
            .unwrap();
        stopped(&mut child);
        json_output(&child.wait_with_output().unwrap(), if yes { 0 } else { 1 });
        reader.join().unwrap();
        assert_eq!(count(home.path()), i64::from(yes));
        let calls = server.join().unwrap();
        assert_eq!(
            calls
                .iter()
                .filter(|r| r.starts_with("POST /api/v1/skills/rules "))
                .count(),
            usize::from(yes)
        );
    }
}

#[test]
fn every_package_upload_stage_interrupts_before_installation_acceptance() {
    let root = source();
    let snapshot = PackageSnapshot::capture(root.path(), PackageLimits::default()).unwrap();
    let mut upload = envelope(
        json!({"id":UPLOAD,"status":"staged","tree_digest":snapshot.tree_digest(),"manifest":snapshot.manifest(),"reserved_bytes":snapshot.total_bytes(),"expires_at":"2099-01-01T00:00:00Z"}),
    );
    upload["status"] = json!("staged");
    let mut file = envelope(
        json!({"upload_id":UPLOAD,"digest":snapshot.manifest().entries[0].sha256,"created":true}),
    );
    file["status"] = json!("persisted");
    for stage in 0..3 {
        let mut replies = vec![user(), library()];
        if stage > 0 {
            replies.push((200, upload.clone()));
        }
        if stage > 1 {
            replies.push((200, file.clone()));
        }
        replies.push((0, json!({})));
        let (ready_tx, ready_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let (url, server) = serve_with_hook(replies, move |index, request| {
            if index == stage + 2 {
                assert!(request.contains("/skills/content/"));
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        });
        let home = home(&url);
        let mut child = spawn(
            home.path(),
            &["add", root.path().to_str().unwrap(), "--yes"],
            Stdio::null(),
        );
        ready(&ready_rx, &mut child, &format!("upload/{stage}"));
        interrupt(&child);
        stopped(&mut child);
        let result = json_output(&child.wait_with_output().unwrap(), 130);
        assert_eq!(result["committed"], false);
        assert!(result["errors"][0]["message"]
            .as_str()
            .unwrap()
            .contains("uploads may remain"));
        assert_eq!(count(home.path()), 0);
        release_tx.send(()).unwrap();
        assert!(!server
            .join()
            .unwrap()
            .iter()
            .any(|r| r.starts_with("POST /api/v1/skills/installations ")));
    }
}

fn ready(receive: &mpsc::Receiver<()>, child: &mut Child, context: &str) {
    if let Err(error) = receive.recv_timeout(Duration::from_secs(10)) {
        let _ = child.kill();
        child.wait().unwrap();
        let mut output = String::new();
        child
            .stdout
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut output)
            .unwrap();
        panic!("{context}: {error}: {output}");
    }
}

#[test]
fn interrupted_configuration_post_keeps_original_pending_key_and_unknown_commitment() {
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_with_hook(
        vec![
            user(),
            library(),
            (200, envelope(installation())),
            (0, json!({})),
        ],
        move |index, request| {
            if index == 3 {
                assert!(request.starts_with("POST /api/v1/skills/rules "));
                ready_tx.send(()).unwrap();
                release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
            }
        },
    );
    let home = home(&url);
    let mut child = spawn(home.path(), &["enable", "sample", "--yes"], Stdio::null());
    ready(&ready_rx, &mut child, "submission");
    interrupt(&child);
    stopped(&mut child);
    let output = json_output(&child.wait_with_output().unwrap(), 130);
    assert_eq!(output["errors"][0]["details"]["commit_state"], "unknown");
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    let (key, state): (String, String) = db
        .query_row(
            "SELECT idempotency_key,state FROM skill_commands",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(state, "pending");
    assert_eq!(output["errors"][0]["details"]["idempotency_key"], key);
    release_tx.send(()).unwrap();
    let calls = server.join().unwrap();
    let request: Value = serde_json::from_str(calls[3].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(request["idempotency_key"], key);
}

#[test]
fn cancellation_survives_the_journal_boundary_and_never_posts_after_lock_release() {
    let (url, server) = serve(vec![user(), library(), (200, envelope(installation()))]);
    let home = home(&url);
    let (mut master, slave) = terminal();
    let mut child = spawn(home.path(), &["enable", "sample"], Stdio::from(slave));
    let reader = prompt(&mut child, b"[y/N] ");
    let db = Connection::open(home.path().join("state.sqlite3")).unwrap();
    db.execute_batch("BEGIN EXCLUSIVE").unwrap();
    master.write_all(b"yes\n").unwrap();
    // The command can finish preparation, but its journal transaction cannot pass this lock.
    std::thread::sleep(Duration::from_millis(250));
    interrupt(&child);
    std::thread::sleep(Duration::from_millis(50));
    db.execute_batch("ROLLBACK").unwrap();
    stopped(&mut child);
    let result = json_output(&child.wait_with_output().unwrap(), 130);
    assert_eq!(result["errors"][0]["code"], "SKILL_INTERRUPTED");
    assert_eq!(result["errors"][0]["details"]["commit_state"], "unknown");
    assert_eq!(count(home.path()), 1);
    reader.join().unwrap();
    assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
}

#[test]
fn excessive_terminal_confirmation_is_rejected_before_submission() {
    let (url, server) = serve(vec![user(), library(), (200, envelope(installation()))]);
    let home = home(&url);
    let (mut master, slave) = terminal();
    use std::os::fd::AsRawFd;
    let mut settings = std::mem::MaybeUninit::<libc::termios>::uninit();
    assert_eq!(
        unsafe { libc::tcgetattr(slave.as_raw_fd(), settings.as_mut_ptr()) },
        0
    );
    let mut settings = unsafe { settings.assume_init() };
    settings.c_lflag &= !(libc::ICANON | libc::ECHO);
    assert_eq!(
        unsafe { libc::tcsetattr(slave.as_raw_fd(), libc::TCSANOW, &settings) },
        0
    );
    let mut child = spawn(home.path(), &["enable", "sample"], Stdio::from(slave));
    let reader = prompt(&mut child, b"[y/N] ");
    master
        .write_all(format!("yes{}\n", " ".repeat(4096)).as_bytes())
        .unwrap();
    stopped(&mut child);
    json_output(&child.wait_with_output().unwrap(), 1);
    assert_eq!(count(home.path()), 0);
    reader.join().unwrap();
    assert!(server.join().unwrap().iter().all(|r| r.starts_with("GET ")));
}

#[test]
fn blocked_source_warning_output_cannot_prevent_cancellation_or_authorize_upload() {
    use std::os::fd::AsRawFd;
    let root = source();
    fs::create_dir(root.path().join("valid")).unwrap();
    fs::rename(
        root.path().join("SKILL.md"),
        root.path().join("valid/SKILL.md"),
    )
    .unwrap();
    for index in 0..1500 {
        let dir = root.path().join(format!("invalid-{index}"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("SKILL.md"), "---\ninvalid: [\n").unwrap();
    }
    let (url, server) = serve(vec![user()]);
    let home = home(&url);
    let mut child = spawn(
        home.path(),
        &["add", root.path().to_str().unwrap(), "--yes"],
        Stdio::null(),
    );
    let mut descriptor = libc::pollfd {
        fd: child.stderr.as_ref().unwrap().as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 10000) }, 1);
    // Leave stderr unread; the complete warning stream exceeds the pipe capacity.
    interrupt(&child);
    stopped(&mut child);
    json_output(&child.wait_with_output().unwrap(), 130);
    assert_eq!(count(home.path()), 0);
    assert_eq!(server.join().unwrap().len(), 1);
}

#[test]
fn blocked_source_catalog_output_exits_without_an_extra_json_envelope() {
    use std::os::fd::AsRawFd;
    let root = tempfile::tempdir().unwrap();
    for index in 0..1200 {
        let dir = root.path().join(format!("skill-{index}"));
        fs::create_dir(&dir).unwrap();
        fs::write(dir.join("SKILL.md"),"---\ndescription: A source catalog entry with enough text to require reading the output pipe.\n---\nInstructions\n").unwrap();
    }
    for json_mode in [true, false] {
        let home = tempfile::tempdir().unwrap();
        let mut child = spawn_mode(
            home.path(),
            &["add", root.path().to_str().unwrap(), "--list"],
            Stdio::null(),
            json_mode,
        );
        let fd = child.stdout.as_ref().unwrap().as_raw_fd();
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 10000) }, 1);
        interrupt(&child);
        stopped(&mut child);
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(130));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE_INTERRUPTED"));
        assert!(!home.path().join("state.sqlite3").exists());
    }
}

#[path = "skill_configuration_interruption/output.rs"]
mod output;
