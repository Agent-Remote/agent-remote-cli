use super::{file_contains, inspect_command};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

fn fake(dir: &Path, name: &str, script: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    path
}

#[test]
fn security_missing_is_distinct_from_denied_locked_or_signaled() {
    let dir = tempfile::tempdir().unwrap();
    for (script, expected) in [
        ("printf fixture-secret; exit 0", Some(true)),
        ("printf 'item not found' >&2; exit 44", Some(false)),
        ("exit 36", None),
        ("printf private-diagnostic >&2; exit 1", None),
        ("kill -TERM $$", None),
    ] {
        let path = fake(dir.path(), "security", script);
        let result = inspect_command(
            path.to_str().unwrap(),
            &[],
            44,
            false,
            &AtomicBool::new(false),
        );
        assert_eq!(result.ok(), expected);
    }
}

#[test]
fn secret_tool_errors_are_not_missing_and_raw_stderr_is_never_returned() {
    let dir = tempfile::tempdir().unwrap();
    for (script, expected) in [
        ("printf fixture-secret; exit 0", Some(true)),
        ("exit 1", Some(false)),
        ("printf private-diagnostic >&2; exit 1", None),
        ("exit 2", None),
        ("printf ambiguous-output; exit 1", None),
    ] {
        let path = fake(dir.path(), "secret-tool", script);
        let result = inspect_command(
            path.to_str().unwrap(),
            &[],
            1,
            true,
            &AtomicBool::new(false),
        );
        if let Err(error) = &result {
            assert!(!error.to_string().contains("private-diagnostic"));
        }
        assert_eq!(result.ok(), expected);
    }
}

#[test]
fn credential_tool_output_is_bounded_on_both_streams() {
    let dir = tempfile::tempdir().unwrap();
    for script in [
        "while :; do printf '0123456789012345678901234567890123456789'; done",
        "while :; do printf '0123456789012345678901234567890123456789' >&2; done",
    ] {
        let path = fake(dir.path(), "security", script);
        let start = std::time::Instant::now();
        let error = inspect_command(
            path.to_str().unwrap(),
            &[],
            44,
            false,
            &AtomicBool::new(false),
        )
        .unwrap_err();
        assert!(error.to_string().contains("output exceeded"));
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }
}

#[test]
fn credential_tool_timeout_kills_its_children() {
    let dir = tempfile::tempdir().unwrap();
    let pid_path = dir.path().join("child.pid");
    let path = fake(
        dir.path(),
        "security",
        &format!(
            "/bin/sleep 30 &\nprintf '%s' $! > '{}'\nwait",
            pid_path.display()
        ),
    );
    let start = std::time::Instant::now();
    let error = inspect_command(
        path.to_str().unwrap(),
        &[],
        44,
        false,
        &AtomicBool::new(false),
    )
    .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(start.elapsed() < std::time::Duration::from_secs(5));
    let pid: i32 = std::fs::read_to_string(pid_path).unwrap().parse().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
    while std::time::Instant::now() < deadline && unsafe { libc::kill(pid, 0) } == 0 {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let present = unsafe { libc::kill(pid, 0) } == 0;
    if present {
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    assert!(!present, "credential tool child survived bounded read");
}

#[test]
fn fallback_read_is_bounded_and_rejects_special_files() {
    use std::os::unix::ffi::OsStrExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("credential");
    assert!(!file_contains(&path).unwrap());
    std::fs::write(&path, "credential").unwrap();
    assert!(file_contains(&path).unwrap());
    std::fs::write(&path, vec![b'x'; 64 * 1024 + 1]).unwrap();
    assert!(file_contains(&path).is_err());
    std::fs::write(&path, [0xff]).unwrap();
    assert!(file_contains(&path).is_err());
    std::fs::remove_file(&path).unwrap();
    let cpath = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(cpath.as_ptr(), 0o600) }, 0);
    let start = std::time::Instant::now();
    assert!(file_contains(&path).is_err());
    assert!(start.elapsed() < std::time::Duration::from_secs(1));
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(file_contains(&path).is_err());
}
