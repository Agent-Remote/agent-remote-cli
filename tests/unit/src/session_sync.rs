// Tests for src/session_sync.rs.

#[cfg(unix)]
#[tokio::test]
async fn launch_flush_requires_success_and_bounds_the_wait() {
    use std::time::Duration;
    let mut success = tokio::process::Command::new("/bin/sh");
    success.args(["-c", "exit 0"]);
    assert!(super::wait_for_flush(success, Duration::from_secs(1))
        .await
        .is_ok());
    let mut failed = tokio::process::Command::new("/bin/sh");
    failed.args(["-c", "exit 3"]);
    let error = super::wait_for_flush(failed, Duration::from_secs(1))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("Claude was not started"));
    let mut blocked = tokio::process::Command::new("/bin/sh");
    blocked.args(["-c", "exec sleep 30"]);
    let started = std::time::Instant::now();
    let error = super::wait_for_flush(blocked, Duration::from_millis(50))
        .await
        .unwrap_err();
    assert!(error.to_string().contains("timed out"));
    assert!(started.elapsed() < Duration::from_secs(2));
}
