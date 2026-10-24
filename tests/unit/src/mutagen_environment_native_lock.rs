use super::*;
use std::fs;

#[test]
fn probe_never_creates_and_acquire_requires_explicit_creation() {
    let temp = tempfile::tempdir().unwrap();
    let data = temp.path().join("data");
    assert!(matches!(probe(&data).unwrap(), Probe::Missing));
    assert!(!data.exists());
    assert_eq!(
        acquire(&data, false).err().unwrap().code(),
        "sync_mutagen_daemon_lock_missing"
    );
    let guard = acquire(&data, true).unwrap();
    guard.validate().unwrap();
    drop(guard);
    assert!(matches!(probe(&data).unwrap(), Probe::Stopped(_)));
    assert!(fs::read(data.join("daemon/daemon.lock"))
        .unwrap()
        .is_empty());
}

#[cfg(unix)]
#[test]
fn rejects_links_and_detects_directory_replacement() {
    use std::os::unix::fs::symlink;
    let temp = tempfile::tempdir().unwrap();
    let guard = acquire(temp.path(), true).unwrap();
    fs::rename(temp.path().join("daemon"), temp.path().join("old")).unwrap();
    fs::create_dir(temp.path().join("daemon")).unwrap();
    fs::write(temp.path().join("daemon/daemon.lock"), []).unwrap();
    assert!(guard.validate().is_err());
    drop(guard);
    fs::remove_file(temp.path().join("daemon/daemon.lock")).unwrap();
    symlink(
        temp.path().join("old/daemon.lock"),
        temp.path().join("daemon/daemon.lock"),
    )
    .unwrap();
    assert!(probe(temp.path()).is_err());
}

#[cfg(unix)]
fn child(data: &Path, expected_busy: bool) {
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "mutagen::desktop::environment::native_lock::tests::fcntl_child_probe",
            "--nocapture",
        ])
        .env("AGENT_REMOTE_TEST_MUTAGEN_FCNTL", data)
        .env(
            "AGENT_REMOTE_TEST_MUTAGEN_EXPECT_BUSY",
            if expected_busy { "1" } else { "0" },
        )
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("running 1 test"));
}

#[cfg(unix)]
#[test]
fn fcntl_child_probe() {
    use std::os::fd::AsRawFd;
    let Some(data) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN_FCNTL") else {
        return;
    };
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(Path::new(&data).join("daemon/daemon.lock"))
        .unwrap();
    // Deliberately independent native call: flock would incorrectly coexist.
    let mut spec: libc::flock = unsafe { std::mem::zeroed() };
    spec.l_type = libc::F_WRLCK as _;
    spec.l_whence = libc::SEEK_SET as _;
    let acquired = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &spec) } == 0;
    let expected_busy = std::env::var("AGENT_REMOTE_TEST_MUTAGEN_EXPECT_BUSY").unwrap() == "1";
    assert_eq!(!acquired, expected_busy);
    if let Some(hold) = std::env::var_os("AGENT_REMOTE_TEST_MUTAGEN_HOLD") {
        let hold = Path::new(&hold);
        fs::write(hold.join("ready"), []).unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !hold.join("stop").exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(hold.join("stop").exists());
    }
}

#[cfg(unix)]
#[test]
fn guard_excludes_official_fcntl_writer_and_validate_preserves_lock() {
    let temp = tempfile::tempdir().unwrap();
    let guard = acquire(temp.path(), true).unwrap();
    child(temp.path(), true);
    guard.validate().unwrap();
    child(temp.path(), true);
    drop(guard);
    child(temp.path(), false);
    let Probe::Stopped(guard) = probe(temp.path()).unwrap() else {
        panic!("expected read lock")
    };
    child(temp.path(), true);
    guard.validate().unwrap();
    child(temp.path(), true);
    drop(guard);
    child(temp.path(), false);
}

#[cfg(unix)]
#[test]
fn probe_identifies_busy_official_writer_without_changing_it() {
    let temp = tempfile::tempdir().unwrap();
    drop(acquire(temp.path(), true).unwrap());
    let hold = tempfile::tempdir().unwrap();
    let mut process = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "mutagen::desktop::environment::native_lock::tests::fcntl_child_probe",
            "--nocapture",
        ])
        .env("AGENT_REMOTE_TEST_MUTAGEN_FCNTL", temp.path())
        .env("AGENT_REMOTE_TEST_MUTAGEN_EXPECT_BUSY", "0")
        .env("AGENT_REMOTE_TEST_MUTAGEN_HOLD", hold.path())
        .spawn()
        .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    while !hold.path().join("ready").exists() && std::time::Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(hold.path().join("ready").exists());
    assert!(matches!(probe(temp.path()).unwrap(), Probe::Busy));
    assert_eq!(
        acquire(temp.path(), false).err().unwrap().code(),
        "sync_mutagen_daemon_busy"
    );
    fs::write(hold.path().join("stop"), []).unwrap();
    assert!(process.wait().unwrap().success());
}
