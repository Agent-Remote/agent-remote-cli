use super::*;

#[test]
fn selects_native_backends_independently_of_terminal_brand() {
    assert_eq!(
        clipboard_commands("macos", false, false, false, false)[0].program,
        "/usr/bin/pbcopy"
    );
    assert_eq!(
        clipboard_commands("windows", false, false, false, false)[0].program,
        "powershell.exe"
    );
    assert_eq!(
        clipboard_commands("linux", false, true, true, false)
            .iter()
            .map(|c| c.program)
            .collect::<Vec<_>>(),
        ["wl-copy", "xclip", "xsel"]
    );
    assert_eq!(
        clipboard_commands("linux", false, false, false, true)[0].program,
        "powershell.exe"
    );
    for platform in ["macos", "windows", "linux"] {
        assert!(clipboard_commands(platform, true, true, true, true).is_empty());
    }
    assert!(clipboard_commands("linux", false, false, false, false).is_empty());
}

#[test]
fn osc52_supports_plain_tmux_and_screen_terminals() {
    assert_eq!(osc52("hello", false, false), "\x1b]52;c;aGVsbG8=\x07");
    assert_eq!(
        osc52("hello", true, true),
        "\x1bPtmux;\x1b\x1b]52;c;aGVsbG8=\x07\x1b\\"
    );
    assert_eq!(
        osc52("hello", false, true),
        "\x1bP\x1b]52;c;aGVsbG8=\x07\x1b\\"
    );
    let long = "selected text".repeat(100);
    let wrapped = osc52(&long, false, true);
    assert!(wrapped.matches("\x1bP").count() > 1);
    assert_eq!(
        wrapped.replace("\x1bP", "").replace("\x1b\\", ""),
        osc52(&long, false, false)
    );
}

#[cfg(unix)]
#[tokio::test]
async fn clipboard_helpers_receive_data_only_on_stdin_and_fail_without_hanging() {
    let command = ClipboardCommand {
        program: "/bin/sh",
        args: vec!["-c", "test \"$(cat)\" = 'https://example.test/?a=1&b=2'"],
        base64_input: false,
    };
    assert!(write_clipboard(&command, "https://example.test/?a=1&b=2").await);
    let missing = ClipboardCommand {
        program: "/no-such-agent-remote-clipboard-command",
        ..command.clone()
    };
    assert!(!write_clipboard(&missing, "test").await);
    let failed = ClipboardCommand {
        args: vec!["-c", "exit 1"],
        ..command.clone()
    };
    assert!(!write_clipboard(&failed, "test").await);
    let blocked = ClipboardCommand {
        args: vec!["-c", "exec sleep 30"],
        ..command
    };
    let started = std::time::Instant::now();
    assert!(!write_clipboard(&blocked, "test").await);
    assert!(started.elapsed() < Duration::from_secs(5));
}
