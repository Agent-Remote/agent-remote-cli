use std::process::Command;

mod clipboard;
mod clipboard_stream;
mod interactive;
mod login_clipboard;
mod pty;
mod stdin;

use anyhow::{bail, Context, Result};
use stdin::StdinReader;
use tokio::io::AsyncWriteExt;

use crate::api::AttachSessionData;
use crate::attachments::{self, AttachmentContext, InputDecoder, InputEvent};
use crate::config::AppPaths;

pub fn check_ssh_available() -> Result<String> {
    let ssh = crate::platform::ssh_binary();
    let output = Command::new(&ssh)
        .arg("-V")
        .output()
        .with_context(|| format!("failed to execute {}", ssh.display()))?;
    let version = if output.stderr.is_empty() {
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    } else {
        String::from_utf8_lossy(&output.stderr).trim().to_string()
    };
    if !output.status.success() {
        bail!("ssh exited with {}", output.status);
    }
    Ok(version)
}

pub async fn execute_attach(paths: &AppPaths, attach: &AttachSessionData) -> Result<()> {
    execute_attach_with_context(paths, attach, None).await
}

pub async fn execute_attach_with_context(
    paths: &AppPaths,
    attach: &AttachSessionData,
    attachment: Option<AttachmentContext>,
) -> Result<()> {
    paths.ensure_base_dirs()?;
    let known_hosts = paths.ssh_dir().join("known_hosts");
    let remote_command = if attach.command_args.is_empty() {
        vec![
            "agent-remote-attach".to_string(),
            "--session".to_string(),
            attach.session_id.clone(),
        ]
    } else {
        attach.command_args.clone()
    };
    let managed = is_managed_attach(&remote_command.iter().map(Into::into).collect::<Vec<_>>());
    let ssh = crate::platform::ssh_binary();
    let mut command = tokio::process::Command::new(&ssh);
    command.args(attach_args(attach, remote_command, &known_hosts));
    let status = if managed {
        execute_interactive_with_attachments(&mut command, attachment, Some(paths)).await
    } else {
        command.status().await.map_err(Into::into)
    }
    .with_context(|| format!("failed to execute SSH attach with {}", ssh.display()))?;
    if !status.success() {
        bail!("ssh attach exited with {status}");
    }
    Ok(())
}

/// Runs managed SSH attachment with local login-link copying and unchanged terminal bytes.
#[allow(dead_code)]
pub async fn execute_interactive(
    command: &mut tokio::process::Command,
) -> Result<std::process::ExitStatus> {
    execute_interactive_with_attachments(command, None, None).await
}

async fn execute_interactive_with_attachments(
    command: &mut tokio::process::Command,
    attachment: Option<AttachmentContext>,
    app_paths: Option<&AppPaths>,
) -> Result<std::process::ExitStatus> {
    use std::io::IsTerminal;

    let login_copy = std::env::var_os("AGENT_REMOTE_LOGIN_CLIPBOARD").is_none_or(|v| v != "0");
    let selection_copy = std::env::var_os("AGENT_REMOTE_CLIPBOARD").is_none_or(|v| v != "0");
    let attachment = attachment
        .filter(|_| std::env::var_os("AGENT_REMOTE_ATTACHMENTS").is_none_or(|value| value != "0"));
    let attachment_requested = attachment.is_some();
    if !std::io::stdin().is_terminal()
        || !std::io::stdout().is_terminal()
        || std::env::var_os("AGENT_REMOTE_LOGIN_CLIPBOARD_ACTIVE").is_some()
        || !(login_copy || selection_copy || attachment_requested)
    {
        return command.status().await.context("failed to run SSH");
    }
    command.env("AGENT_REMOTE_LOGIN_CLIPBOARD_ACTIVE", "1");
    if login_copy {
        crate::terminal::note("Claude login links copy automatically. Terminal clipboard permission may be required when no desktop clipboard is available.");
    }
    if selection_copy {
        crate::terminal::note("Drag to select remote text; release to copy (requires an updated Node). Selections are limited to 64 KiB; a bell signals rejected text. Your terminal may support Shift/Option-drag for native selection.");
    }
    let attachment = attachment
        .map(|attachment| {
            let paths = app_paths.cloned().map(Ok).unwrap_or_else(|| AppPaths::new(None))?;
            crate::terminal::note(
                "Clipboard images and file drops are bridged into the synchronized Claude workspace.",
            );
            Ok::<_, anyhow::Error>((paths, attachment))
        })
        .transpose()?;
    // Fall back to OpenSSH's own terminal handling if raw input is unavailable.
    let Ok(raw_mode) = RawModeGuard::enable() else {
        return command.status().await.context("failed to run SSH");
    };
    let raw_mode = std::sync::Arc::new(raw_mode);
    let input = StdinReader::spawn(raw_mode.clone())?;
    let session = pty::Session::spawn(command, pty::command_size())?;
    let (mut output, writer, resize_handle, pty_child) = session.parts();
    let resize_task_handle = resize_handle.clone();
    // JoinSet also aborts both relays if the attach future is dropped.
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let mut previous = pty::command_size();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            let current = pty::command_size();
            if current != previous {
                if resize_task_handle.resize(current).is_err() {
                    break;
                }
                previous = current;
            }
        }
        Ok(())
    });
    tasks.spawn(async move {
        if let Some((paths, attachment)) = attachment {
            relay_input(writer, resize_handle, input, paths, attachment).await
        } else {
            relay_passthrough(writer, resize_handle, input).await
        }
    });
    let size = || match terminal_size::terminal_size() {
        Some((terminal_size::Width(cols), terminal_size::Height(rows))) => (rows, cols),
        None => (48, 160),
    };
    let mut stdout = std::io::stdout();
    let observer = interactive::observe(
        &mut output,
        &mut stdout,
        login_copy,
        selection_copy,
        size,
        |text| async move { clipboard::copy(&text).await },
    );
    tokio::pin!(observer);
    // ConPTY keeps its output pipe open until the PTY master is closed.
    // Reap SSH independently, then stop the relays that own the master while
    // continuing to drain final output and clipboard requests.
    let killer = pty_child.killer();
    let wait = pty_child.wait();
    tokio::pin!(wait);
    let (observe_result, status_result) = tokio::select! {
        status = &mut wait => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            (observer.await, status)
        }
        observed = &mut observer => {
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
            if observed.is_err() {
                let mut killer = killer;
                let _ = killer.kill();
            }
            (observed, wait.await)
        }
    };

    // Closing the receiver cancels and joins the native reader before local
    // terminal modes are restored. No reader survives to steal shell input.
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    drop(raw_mode);
    let feedback = observe_result?;
    let status = pty::exit_status(status_result?);
    // Feedback outside the TUI avoids moving its cursor, scrolling its screen,
    // or overwriting Claude's code-entry prompt while SSH owns raw mode.
    if feedback.incomplete {
        crate::terminal::note("Some clipboard requests were rejected or timed out. Select at most 64 KiB of text and try again, or use native terminal selection.");
    }
    match feedback.native_copy {
        Some(true) => crate::terminal::note("Remote text copied to your clipboard."),
        Some(false) => crate::terminal::note("Copy sent to terminal clipboard (OSC 52). If paste failed, enable terminal clipboard access or use native terminal selection."),
        None => {}
    }
    Ok(status)
}

async fn relay_input<W>(
    mut remote: W,
    resize_handle: pty::ResizeHandle,
    mut input: StdinReader,
    paths: AppPaths,
    attachment: AttachmentContext,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut decoder = InputDecoder::default();
    let mut buffer = [0u8; 8192];
    let mut previous_size = pty::command_size();
    loop {
        let bytes = input.recv().await?.unwrap_or_default();
        let count = bytes.len();
        buffer[..count].copy_from_slice(&bytes);
        if count == 0 {
            for event in decoder.finish() {
                if let InputEvent::Bytes(bytes) = event {
                    remote.write_all(&bytes).await?;
                }
            }
            remote.flush().await?;
            break;
        }
        resize_if_needed(&resize_handle, &mut previous_size);
        for event in decoder.feed(&buffer[..count]) {
            match event {
                InputEvent::Bytes(bytes) => remote.write_all(&bytes).await?,
                InputEvent::ClipboardPaste => {
                    let payload = tokio::task::spawn_blocking(attachments::read_clipboard_payload)
                        .await
                        .ok()
                        .flatten();
                    if let Some(payload) = payload {
                        let attachment = attachment.clone();
                        let paths_clone = paths.clone();
                        let staged = tokio::task::spawn_blocking(move || {
                            attachment.stage_payload(&paths_clone, payload)
                        })
                        .await
                        .ok()
                        .and_then(Result::ok);
                        if let Some(staged) = staged {
                            remote
                                .write_all(&bracketed_attachment_text(&staged))
                                .await?;
                        } else {
                            remote.write_all(b"\x07\x16").await?;
                        }
                    } else {
                        remote.write_all(&[0x16]).await?;
                    }
                }
                InputEvent::BracketedPaste(value) => {
                    if let Some(local_paths) = attachments::parse_dropped_paths(
                        std::str::from_utf8(&value).unwrap_or_default(),
                    ) {
                        let attachment = attachment.clone();
                        let paths_clone = paths.clone();
                        let staged = tokio::task::spawn_blocking(move || {
                            attachment.stage_payload(
                                &paths_clone,
                                attachments::ClipboardPayload::Files(local_paths),
                            )
                        })
                        .await
                        .ok()
                        .and_then(Result::ok);
                        if let Some(staged) = staged {
                            remote
                                .write_all(&bracketed_attachment_text(&staged))
                                .await?;
                        } else {
                            remote.write_all(b"\x07\x1b[200~").await?;
                            remote.write_all(&value).await?;
                            remote.write_all(b"\x1b[201~").await?;
                        }
                    } else {
                        remote.write_all(b"\x1b[200~").await?;
                        remote.write_all(&value).await?;
                        remote.write_all(b"\x1b[201~").await?;
                    }
                }
            }
        }
        remote.flush().await?;
    }
    Ok(())
}

async fn relay_passthrough<W>(
    mut remote: W,
    resize_handle: pty::ResizeHandle,
    mut input: StdinReader,
) -> Result<()>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; 8192];
    let mut previous_size = pty::command_size();
    loop {
        let bytes = input.recv().await?.unwrap_or_default();
        let count = bytes.len();
        buffer[..count].copy_from_slice(&bytes);
        if count == 0 {
            remote.shutdown().await?;
            break;
        }
        resize_if_needed(&resize_handle, &mut previous_size);
        remote.write_all(&buffer[..count]).await?;
        remote.flush().await?;
    }
    Ok(())
}

fn resize_if_needed(handle: &pty::ResizeHandle, previous: &mut portable_pty::PtySize) {
    let current = pty::command_size();
    if current != *previous {
        let _ = handle.resize(current);
        *previous = current;
    }
}

fn bracketed_attachment_text(paths: &[String]) -> Vec<u8> {
    let value = paths
        .iter()
        .map(|path| shell_escape_path(path))
        .collect::<Vec<_>>()
        .join(" ");
    let mut output = b"\x1b[200~".to_vec();
    output.extend(value.as_bytes());
    output.extend_from_slice(b"\x1b[201~");
    output
}

fn shell_escape_path(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-._/:\\".contains(&byte))
    {
        return value.to_string();
    }
    format!("'{}'", value.replace('\'', "'\\''"))
}

struct RawModeGuard {
    #[cfg(windows)]
    input_mode: u32,
}

impl RawModeGuard {
    fn enable() -> Result<Self> {
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT,
                ENABLE_EXTENDED_FLAGS, ENABLE_LINE_INPUT, ENABLE_PROCESSED_INPUT,
                ENABLE_QUICK_EDIT_MODE, ENABLE_VIRTUAL_TERMINAL_INPUT, STD_INPUT_HANDLE,
            };
            let mut input_mode = 0;
            // SAFETY: process-owned console handle and initialized mode storage.
            unsafe {
                let handle = GetStdHandle(STD_INPUT_HANDLE);
                if GetConsoleMode(handle, &mut input_mode) == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
                let raw = (input_mode | ENABLE_VIRTUAL_TERMINAL_INPUT | ENABLE_EXTENDED_FLAGS)
                    & !(ENABLE_LINE_INPUT
                        | ENABLE_ECHO_INPUT
                        | ENABLE_PROCESSED_INPUT
                        | ENABLE_QUICK_EDIT_MODE);
                if SetConsoleMode(handle, raw) == 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            Ok(Self { input_mode })
        }
        #[cfg(not(windows))]
        {
            crossterm::terminal::enable_raw_mode().context("failed to enable terminal raw mode")?;
            Ok(Self {})
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        // A disconnected SSH client may not forward tmux's final mode reset.
        // Stop generating mouse/focus reports before handing input to the shell.
        use std::io::Write;
        let mut stdout = std::io::stdout();
        let _ = stdout.write_all(b"\x1b[?1000l\x1b[?1002l\x1b[?1003l\x1b[?1005l\x1b[?1006l\x1b[?1015l\x1b[?1004l\x1b[?2004l");
        let _ = stdout.flush();
        crate::terminal::flush_input();
        #[cfg(windows)]
        {
            use windows_sys::Win32::System::Console::{
                GetStdHandle, SetConsoleMode, STD_INPUT_HANDLE,
            };
            // SAFETY: restore the exact input mode saved before this attach.
            unsafe { SetConsoleMode(GetStdHandle(STD_INPUT_HANDLE), self.input_mode) };
        }
        #[cfg(not(windows))]
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Limits clipboard observation in the packaged SSH proxy to managed attach commands.
pub fn is_managed_attach(arguments: &[std::ffi::OsString]) -> bool {
    let words: Vec<_> = arguments
        .iter()
        .filter_map(|value| value.to_str())
        .flat_map(str::split_whitespace)
        .collect();
    words.len() >= 3
        && words[words.len() - 3] == "agent-remote-attach"
        && matches!(words[words.len() - 2], "--binding" | "--session")
        && words[words.len() - 1].len() <= 128
        && words[words.len() - 1]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_:".contains(&b))
}

fn attach_args(
    attach: &AttachSessionData,
    remote_command: Vec<String>,
    known_hosts: &std::path::Path,
) -> Vec<String> {
    let mut args = Vec::with_capacity(remote_command.len() + 19);
    if attach.forward_ssh_agent {
        args.push("-A".to_string());
    }
    args.extend([
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", known_hosts.to_string_lossy()),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=10".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=2".to_string(),
        "-tt".to_string(),
        "-p".to_string(),
        attach.ssh_port.to_string(),
        format!("{}@{}", attach.ssh_user, attach.ssh_host),
    ]);
    args.extend(remote_command);
    args
}

pub fn tunnel_args(
    ssh_host: &str,
    ssh_port: u16,
    ssh_user: &str,
    forward_id: &str,
    known_hosts: &std::path::Path,
) -> Vec<String> {
    vec![
        "-T".to_string(),
        "-o".to_string(),
        "StrictHostKeyChecking=accept-new".to_string(),
        "-o".to_string(),
        format!("UserKnownHostsFile={}", known_hosts.to_string_lossy()),
        "-o".to_string(),
        "BatchMode=yes".to_string(),
        "-o".to_string(),
        "ConnectTimeout=10".to_string(),
        "-o".to_string(),
        "ServerAliveInterval=10".to_string(),
        "-o".to_string(),
        "ServerAliveCountMax=2".to_string(),
        "-o".to_string(),
        "ClearAllForwardings=yes".to_string(),
        "-o".to_string(),
        "PermitLocalCommand=no".to_string(),
        "-p".to_string(),
        ssh_port.to_string(),
        format!("{ssh_user}@{ssh_host}"),
        "agent-remote-tunnel".to_string(),
        "--forward".to_string(),
        forward_id.to_string(),
        "--protocol".to_string(),
        "1".to_string(),
    ]
}

/// Fixed frozen export command; no server text can enable SSH configuration execution.
pub fn skill_export_args(
    host: &str,
    port: u16,
    user: &str,
    snapshot: &str,
    known_hosts: &std::path::Path,
) -> Vec<String> {
    vec![
        "-F".into(),
        "none".into(),
        "-T".into(),
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ForwardX11=no".into(),
        "-o".into(),
        "ClearAllForwardings=yes".into(),
        "-o".into(),
        "PermitLocalCommand=no".into(),
        "-o".into(),
        "ConnectTimeout=10".into(),
        "-o".into(),
        "ServerAliveInterval=10".into(),
        "-o".into(),
        "ServerAliveCountMax=2".into(),
        "-o".into(),
        "StrictHostKeyChecking=accept-new".into(),
        "-o".into(),
        format!("UserKnownHostsFile={}", known_hosts.to_string_lossy()),
        "-p".into(),
        port.to_string(),
        format!("{user}@{host}"),
        "agent-remote-skill-export".into(),
        "--snapshot".into(),
        snapshot.into(),
        "--protocol".into(),
        "1".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_proxy_only_observes_managed_session_and_binding_attach() {
        for target in ["--session", "--binding"] {
            let args = [
                "-tt",
                "user@host",
                "agent-remote-attach",
                target,
                "account-123",
            ]
            .map(Into::into);
            assert!(is_managed_attach(&args));
            assert!(is_managed_attach(&[format!(
                "agent-remote-attach {target} account-123"
            )
            .into()]));
        }
        for args in [
            vec!["user@host", "mutagen-agent", "synchronizer"],
            vec!["user@host", "agent-remote-tunnel", "--forward", "id"],
            vec!["user@host", "agent-remote-attach", "--session", "id;sh"],
            vec![
                "user@host",
                "agent-remote-attach",
                "--session",
                "id",
                "extra",
            ],
            vec!["-V"],
        ] {
            assert!(!is_managed_attach(
                &args.into_iter().map(Into::into).collect::<Vec<_>>()
            ));
        }
    }

    fn attach(forward_ssh_agent: bool) -> AttachSessionData {
        AttachSessionData {
            session_id: "session_1".to_string(),
            node_id: "node_1".to_string(),
            node_wireguard_ip: "10.77.0.1".to_string(),
            ssh_host: "10.77.0.1".to_string(),
            ssh_port: 22,
            ssh_user: "agent-remote".to_string(),
            tmux_session_name: "claude-test".to_string(),
            command_args: Vec::new(),
            ssh_command: String::new(),
            forward_ssh_agent,
            authorization_task_id: "task_1".to_string(),
            authorization_task_status: "succeeded".to_string(),
            expires_in: 300,
        }
    }

    #[test]
    fn attach_args_forward_agent_only_when_authorized() {
        let remote_command = vec!["agent-remote-attach".to_string()];
        let known_hosts = std::path::Path::new("/tmp/agent-remote/ssh/known_hosts");
        let forwarded = attach_args(&attach(true), remote_command.clone(), known_hosts);
        assert_eq!(forwarded.first().map(String::as_str), Some("-A"));

        let restricted = attach_args(&attach(false), remote_command, known_hosts);
        assert!(!restricted.iter().any(|argument| argument == "-A"));
        for option in [
            "BatchMode=yes",
            "ConnectTimeout=10",
            "ServerAliveInterval=10",
            "ServerAliveCountMax=2",
            "StrictHostKeyChecking=accept-new",
            "UserKnownHostsFile=/tmp/agent-remote/ssh/known_hosts",
        ] {
            assert!(restricted.iter().any(|argument| argument == option));
        }
    }

    #[test]
    fn tunnel_args_disable_standard_forwarding_and_use_fixed_command() {
        let args = tunnel_args(
            "10.77.0.2",
            2222,
            "agent-remote",
            "forward-1",
            std::path::Path::new("/tmp/known_hosts"),
        );
        for expected in [
            "-T",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
            "agent-remote-tunnel",
            "--forward",
            "forward-1",
            "--protocol",
            "1",
        ] {
            assert!(args.iter().any(|argument| argument == expected));
        }
        for forbidden in ["-L", "-R", "-D", "-W", "StrictHostKeyChecking=no"] {
            assert!(!args.iter().any(|argument| argument == forbidden));
        }
    }
}
