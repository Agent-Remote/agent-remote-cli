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
        .arg("-tt")
        .arg("-p")
        .arg(attach.ssh_port.to_string())
        .arg(format!("{}@{}", attach.ssh_user, attach.ssh_host))
        .args(remote_command)
        .status()
        .context("failed to execute ssh attach")?;
    if !status.success() {
        bail!("ssh attach exited with {status}");
    }
    Ok(())
}
