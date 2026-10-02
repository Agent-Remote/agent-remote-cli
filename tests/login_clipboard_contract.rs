#[cfg(unix)]
#[test]
fn packaged_proxy_copies_binding_and_relogin_links_without_changing_tty_or_exit_status() {
    let status = std::process::Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/login_clipboard_pty.py"
        ))
        .arg(env!("CARGO_BIN_EXE_agent-remote-ssh"))
        .status()
        .expect("python3 is required for the PTY regression test");
    assert!(status.success());
}

#[cfg(unix)]
#[test]
fn redirected_managed_ssh_output_is_unchanged() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let fake = root.path().join("ssh");
    std::fs::write(&fake, "#!/bin/sh\nprintf 'unchanged\\033[0m\\n'\nexit 23\n").unwrap();
    std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_agent-remote-ssh"))
        .args([
            "-tt",
            "fixture@host",
            "agent-remote-attach",
            "--binding",
            "fixture",
        ])
        .env("AGENT_REMOTE_HOME", root.path().join("home"))
        .env("AGENT_REMOTE_SYSTEM_SSH", fake)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"unchanged\x1b[0m\n");
    assert!(output.stderr.is_empty());
}
