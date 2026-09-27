use super::*;
use output_support as out;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

// Fill the inherited pipe before launching: even a short final receipt must remain cancellable.
fn full_pipe() -> (std::fs::File, std::fs::File, usize) {
    let mut descriptors = [-1; 2];
    assert_eq!(unsafe { libc::pipe(descriptors.as_mut_ptr()) }, 0);
    for fd in descriptors {
        assert_eq!(
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) },
            0
        );
    }
    let reader = unsafe { std::fs::File::from_raw_fd(descriptors[0]) };
    let mut writer = unsafe { std::fs::File::from_raw_fd(descriptors[1]) };
    let flags = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let mut count = 0;
    loop {
        match writer.write(&[b'x'; 4096]) {
            Ok(size) => count += size,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) => panic!("fill pipe: {error}"),
        }
    }
    assert_eq!(
        unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, flags) },
        0
    );
    (reader, writer, count)
}

fn spawn(
    home: &std::path::Path,
    args: &[&str],
    json: bool,
    writer: std::fs::File,
    stderr: bool,
) -> Child {
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
        .stdin(Stdio::null());
    if stderr {
        command.stdout(Stdio::piped()).stderr(Stdio::from(writer));
    } else {
        command.stdout(Stdio::from(writer)).stderr(Stdio::piped());
    }
    command.spawn().unwrap()
}

fn stopped(child: Child, mut reader: std::fs::File, count: usize) {
    let output = out::stopped(child);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).unwrap();
    assert!(bytes.len() >= count);
    assert!(bytes[..count].iter().all(|b| *b == b'x'));
    assert!(!String::from_utf8_lossy(&bytes[count..]).contains("SKILL_INTERRUPTED"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("SKILL_QUERY_FAILED"));
}

#[test]
fn state_query_success_and_failure_output_do_not_block_interruption() {
    for json in [false, true] {
        for failed in [false, true] {
            let reply = if failed {
                json!({"invalid":"response"})
            } else {
                envelope(diff())
            };
            let (url, server) = serve(vec![(200, reply)]);
            let home = home(&url);
            let (reader, writer, count) = full_pipe();
            let child = spawn(
                home.path(),
                &["diff", "--checkpoint", OP],
                json,
                writer,
                failed && !json,
            );
            assert_eq!(server.join().unwrap().len(), 1);
            std::thread::sleep(Duration::from_millis(150));
            out::signal(&child);
            stopped(child, reader, count);
            assert!(!home.path().join("state.sqlite3").exists());
        }
    }
}

#[test]
fn completed_export_survives_interruption_of_its_output() {
    for json in [true, false] {
        let bytes = b"retained checkpoint bytes";
        let entry = file("sample/memory", bytes);
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
                    bytes: bytes.to_vec(),
                    digest: entry.sha256.clone(),
                    length: bytes.len(),
                },
            ],
            |_| {},
        );
        let home = home(&url);
        let destination = home.path().join("export");
        let (reader, writer, count) = full_pipe();
        let mut child = spawn(
            home.path(),
            &[
                "export",
                SKILL,
                "--checkpoint",
                OP,
                "--output",
                destination.to_str().unwrap(),
            ],
            json,
            writer,
            false,
        );
        assert_eq!(server.join().unwrap().len(), 3);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !destination.join("checkpoint.json").exists() {
            if Instant::now() >= deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("verified export was not published");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        std::thread::sleep(Duration::from_millis(150));
        out::signal(&child);
        stopped(child, reader, count);
        let saved: Manifest =
            serde_json::from_slice(&fs::read(destination.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(saved, manifest);
        assert_eq!(
            fs::read(destination.join("objects").join(entry.sha256)).unwrap(),
            bytes
        );
        assert!(fs::read_dir(home.path()).unwrap().all(|item| !item
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".skill-export-")));
        assert!(!home.path().join("state.sqlite3").exists());
    }
}

#[test]
fn interrupted_query_cannot_block_on_its_json_error_envelope() {
    use std::sync::mpsc;
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (url, server) = serve_raw(vec![Response::Disconnect], move |_| {
        ready_tx.send(()).unwrap();
        release_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    });
    let home = home(&url);
    let (reader, writer, count) = full_pipe();
    let child = spawn(home.path(), &["info", OP], true, writer, false);
    ready_rx.recv_timeout(Duration::from_secs(10)).unwrap();
    out::signal(&child);
    stopped(child, reader, count);
    release_tx.send(()).unwrap();
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(!home.path().join("state.sqlite3").exists());
}
