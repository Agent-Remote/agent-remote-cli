use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::api::AttachSessionData;

pub fn check_ssh_available() -> Result<String> {
    let output = Command::new("ssh")
        .arg("-V")
        .output()
        .context("failed to execute ssh")?;
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

pub fn execute_attach(attach: &AttachSessionData) -> Result<()> {
    let remote_command = if attach.command_args.is_empty() {
        vec![
            "agent-remote-attach".to_string(),
            "--session".to_string(),
            attach.session_id.clone(),
        ]
    } else {
        attach.command_args.clone()
    };
    let status = Command::new("ssh")
        .args(attach_args(attach, remote_command))
        .status()
        .context("failed to execute ssh attach")?;
    if !status.success() {
        bail!("ssh attach exited with {status}");
    }
    Ok(())
}

fn attach_args(attach: &AttachSessionData, remote_command: Vec<String>) -> Vec<String> {
    let mut args = Vec::with_capacity(remote_command.len() + 5);
    if attach.forward_ssh_agent {
        args.push("-A".to_string());
    }
    args.extend([
        "-tt".to_string(),
        "-p".to_string(),
        attach.ssh_port.to_string(),
        format!("{}@{}", attach.ssh_user, attach.ssh_host),
    ]);
    args.extend(remote_command);
    args
}

#[cfg(test)]
mod tests {
    use super::*;

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
            expires_in: 300,
        }
    }

    #[test]
    fn attach_args_forward_agent_only_when_authorized() {
        let remote_command = vec!["agent-remote-attach".to_string()];
        let forwarded = attach_args(&attach(true), remote_command.clone());
        assert_eq!(forwarded.first().map(String::as_str), Some("-A"));

        let restricted = attach_args(&attach(false), remote_command);
        assert!(!restricted.iter().any(|argument| argument == "-A"));
    }
}
