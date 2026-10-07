// Tests for src/skills/git_process.rs.

use super::*;
#[tokio::test]
async fn output_bound_and_timeout_kill_descendant_processes() {
    let root = tempfile::tempdir().unwrap();
    for excess in [true, false] {
        let marker = root.path().join(if excess {
            "output-child"
        } else {
            "timeout-child"
        });
        let mut command = Command::new("sh");
        command
            .args([
                "-c",
                if excess {
                    "(sleep 0.5; touch \"$1\") & printf too-much-output; wait"
                } else {
                    "(sleep 0.5; touch \"$1\") & wait"
                },
                "fixture",
            ])
            .arg(&marker)
            .process_group(0);
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let error = run(command, b"", 3, Duration::from_millis(100), None)
            .await
            .err()
            .unwrap();
        assert!(error.to_string().contains(if excess {
            "QUOTA_EXCEEDED"
        } else {
            "SOURCE_TIMEOUT"
        }));
        tokio::time::sleep(Duration::from_millis(650)).await;
        assert!(!marker.exists());
    }
}
#[tokio::test]
async fn disk_guard_checks_fast_completion_and_sparse_file_sizes() {
    let root = tempfile::tempdir().unwrap();
    std::fs::File::create(root.path().join("pack"))
        .unwrap()
        .set_len(512 * 1024 * 1024 + 1)
        .unwrap();
    let mut command = Command::new("sh");
    command
        .args(["-c", "true"])
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let error = run(
        command,
        b"",
        1024,
        Duration::from_secs(10),
        Some(root.path()),
    )
    .await
    .err()
    .unwrap();
    assert!(error.to_string().contains("QUOTA_EXCEEDED"));
}
#[tokio::test]
async fn cancellation_drops_the_whole_process_group() {
    let root = tempfile::tempdir().unwrap();
    let ready = root.path().join("ready");
    let marker = root.path().join("child");
    let mut command = Command::new("sh");
    command
        .args([
            "-c",
            "touch \"$1\"; (sleep 0.5; touch \"$2\") & wait",
            "fixture",
        ])
        .arg(&ready)
        .arg(&marker)
        .process_group(0)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let task =
        tokio::spawn(async move { run(command, b"", 1024, Duration::from_secs(10), None).await });
    tokio::time::timeout(Duration::from_secs(5), async {
        while !ready.exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    task.abort();
    let _ = task.await;
    tokio::time::sleep(Duration::from_millis(650)).await;
    assert!(!marker.exists());
}
