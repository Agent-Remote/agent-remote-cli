use super::*;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

fn fixture(body: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wg");
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    (dir, path)
}

#[tokio::test]
async fn invokes_exact_dump_arguments_and_captures_only_stdout() {
    let (_dir,path) = fixture("[ \"$#\" = 3 ] && [ \"$1\" = show ] && [ \"$2\" = all ] && [ \"$3\" = dump ] || exit 99\nprintf 'snapshot\\n'\nprintf 'discard stderr' >&2");
    let output = run(&path, &AtomicBool::new(false)).await.unwrap();
    assert_eq!(output.0, b"snapshot\n");
}

#[tokio::test]
async fn failed_exit_returns_content_free_error() {
    let (_dir, path) = fixture("printf 'private-key'; printf 'preshared-key' >&2; exit 1");
    assert!(matches!(
        run(&path, &AtomicBool::new(false)).await,
        Err(ProbeError::Failed)
    ));
}

#[tokio::test]
async fn both_streams_have_hard_output_limits() {
    for body in ["head -c 1048577 /dev/zero", "head -c 16385 /dev/zero >&2"] {
        let (_dir, path) = fixture(body);
        assert!(matches!(
            run(&path, &AtomicBool::new(false)).await,
            Err(ProbeError::OutputTooLarge)
        ));
    }
}

async fn wait_for_pid(path: &Path) -> i32 {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if let Ok(text) = std::fs::read_to_string(path) {
                if let Ok(pid) = text.trim().parse() {
                    return pid;
                }
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("fixture descendant must start")
}

async fn assert_stopped(pid: i32) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let output = std::process::Command::new("ps")
                .args(["-o", "stat=", "-p", &pid.to_string()])
                .output()
                .unwrap();
            let state = String::from_utf8(output.stdout).unwrap();
            if state.trim().is_empty() || state.trim().starts_with('Z') {
                return;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("probe must terminate its descendant");
}

fn descendant_fixture(
    parent_exits: bool,
) -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let (dir, path) = fixture("");
    let pid = dir.path().join("descendant.pid");
    let ending = if parent_exits { "exit 0" } else { "wait" };
    std::fs::write(
        &path,
        format!(
            "#!/bin/sh\nsleep 60 &\nprintf '%s\\n' \"$!\" > '{}'\n{ending}\n",
            pid.display()
        ),
    )
    .unwrap();
    (dir, path, pid)
}

#[tokio::test]
async fn timeout_kills_descendants_even_after_the_leader_exits() {
    let (_dir, path, pid_path) = descendant_fixture(true);
    let task = tokio::spawn(async move {
        run_with_budget(&path, &AtomicBool::new(false), Duration::from_secs(1)).await
    });
    let pid = wait_for_pid(&pid_path).await;
    assert!(matches!(task.await.unwrap(), Err(ProbeError::TimedOut)));
    assert_stopped(pid).await;
}

#[tokio::test]
async fn cancellation_and_future_drop_clean_the_process_group() {
    for drop_future in [false, true] {
        let (_dir, path, pid_path) = descendant_fixture(false);
        let cancel = Arc::new(AtomicBool::new(false));
        let flag = cancel.clone();
        let task = tokio::spawn(async move { run(&path, &flag).await });
        let pid = wait_for_pid(&pid_path).await;
        if drop_future {
            task.abort();
            assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        } else {
            cancel.store(true, Ordering::Release);
            assert!(matches!(task.await.unwrap(), Err(ProbeError::Canceled)));
        }
        assert_stopped(pid).await;
    }
}

#[tokio::test]
async fn already_canceled_probe_does_not_spawn() {
    let (_dir, path) = fixture("exit 99");
    assert!(matches!(
        run(&path, &AtomicBool::new(true)).await,
        Err(ProbeError::Canceled)
    ));
}
