//! Exercises the real Linux helper selection in an isolated child environment.
#![cfg(target_os = "linux")]
use agent_remote_cli::attachments::{read_clipboard_payload, ClipboardPayload};
use std::{os::unix::fs::PermissionsExt, process::Command};

#[tokio::test]
async fn wsl_without_windows_interop_uses_wayland_clipboard() {
    if std::env::var_os("AGENT_REMOTE_CAPTURE_PROBE").is_some() {
        assert_eq!(
            read_clipboard_payload().await,
            Some(ClipboardPayload::Image {
                bytes: b"\x89PNG\r\n\x1a\n".to_vec(),
                extension: "png"
            })
        );
        return;
    }
    let root = tempfile::tempdir().unwrap();
    let png = root.path().join("fixture.png");
    std::fs::write(&png, b"\x89PNG\r\n\x1a\n").unwrap();
    let helper = root.path().join("wl-paste");
    std::fs::write(&helper, "#!/bin/sh\nif [ \"$1\" = --list-types ]; then printf 'image/png\\n'; else /bin/cat \"$TEST_PNG\"; fi\n").unwrap();
    std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "wsl_without_windows_interop_uses_wayland_clipboard",
            "--nocapture",
        ])
        .env("AGENT_REMOTE_CAPTURE_PROBE", "1")
        .env("PATH", root.path())
        .env("TEST_PNG", png)
        .env("WSL_DISTRO_NAME", "fixture")
        .env("WAYLAND_DISPLAY", "fixture")
        .env_remove("SSH_CONNECTION")
        .env_remove("SSH_TTY")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
