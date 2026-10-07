//! Local clipboard writers shared by login and explicit terminal selections.

use base64::{engine::general_purpose::STANDARD, Engine};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Clone, Debug, PartialEq, Eq)]
struct ClipboardCommand {
    program: &'static str,
    args: Vec<&'static str>,
    base64_input: bool,
}

fn clipboard_commands(
    platform: &str,
    remote: bool,
    wayland: bool,
    x11: bool,
    wsl: bool,
) -> Vec<ClipboardCommand> {
    // A desktop clipboard on an SSH jump host is not the user's clipboard.
    if remote {
        return Vec::new();
    }
    let command = |program, args| ClipboardCommand {
        program,
        args,
        base64_input: false,
    };
    let powershell = || {
        ClipboardCommand {
        program: "powershell.exe",
        args: vec!["-NoLogo", "-NoProfile", "-NonInteractive", "-Command",
            "$ErrorActionPreference='Stop'; Set-Clipboard -Value ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String([Console]::In.ReadToEnd())))"],
        base64_input: true,
    }
    };
    match platform {
        "macos" => vec![command("/usr/bin/pbcopy", vec![])],
        "windows" => vec![powershell()],
        "linux" => {
            let mut commands = Vec::new();
            if wsl {
                commands.push(powershell());
            }
            if wayland {
                commands.push(command(
                    "wl-copy",
                    vec!["--type", "text/plain;charset=utf-8"],
                ));
            }
            if x11 {
                commands.push(command("xclip", vec!["-selection", "clipboard", "-in"]));
                commands.push(command("xsel", vec!["--clipboard", "--input"]));
            }
            commands
        }
        _ => Vec::new(),
    }
}

pub(super) enum CopyResult {
    Native,
    Terminal(String),
}

pub(super) async fn copy(value: &str) -> CopyResult {
    let env_set = |name| std::env::var_os(name).is_some_and(|v| !v.is_empty());
    let commands = clipboard_commands(
        std::env::consts::OS,
        env_set("SSH_CONNECTION") || env_set("SSH_TTY"),
        env_set("WAYLAND_DISPLAY"),
        env_set("DISPLAY"),
        env_set("WSL_DISTRO_NAME") || env_set("WSL_INTEROP"),
    );
    for command in commands {
        if write_clipboard(&command, value).await {
            return CopyResult::Native;
        }
    }
    CopyResult::Terminal(osc52(
        value,
        env_set("TMUX"),
        std::env::var("TERM")
            .unwrap_or_default()
            .starts_with("screen"),
    ))
}

async fn write_clipboard(command: &ClipboardCommand, value: &str) -> bool {
    let Ok(mut child) = Command::new(command.program)
        .args(&command.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
    else {
        return false;
    };
    let payload = if command.base64_input {
        STANDARD.encode(value)
    } else {
        value.to_owned()
    };
    let operation = async {
        let Some(mut input) = child.stdin.take() else {
            return false;
        };
        if input.write_all(payload.as_bytes()).await.is_err() {
            return false;
        }
        drop(input);
        child.wait().await.is_ok_and(|status| status.success())
    };
    tokio::time::timeout(Duration::from_secs(2), operation)
        .await
        .unwrap_or(false)
}

fn osc52(value: &str, tmux: bool, screen: bool) -> String {
    let sequence = format!("\x1b]52;c;{}\x07", STANDARD.encode(value));
    if tmux {
        format!("\x1bPtmux;{}\x1b\\", sequence.replace('\x1b', "\x1b\x1b"))
    } else if screen {
        // GNU screen limits each DCS passthrough payload. Split the ASCII
        // sequence; the outer terminal receives the original OSC contiguously.
        sequence
            .as_bytes()
            .chunks(256)
            .map(|chunk| format!("\x1bP{}\x1b\\", String::from_utf8_lossy(chunk)))
            .collect()
    } else {
        sequence
    }
}
#[cfg(test)]
#[path = "../../tests/unit/src/ssh/clipboard/tests.rs"]
mod tests;
