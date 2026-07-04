use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Result};

pub fn current_platform() -> Result<String> {
    if cfg!(target_os = "macos") {
        Ok("macos".to_string())
    } else if cfg!(target_os = "linux") {
        Ok("linux".to_string())
    } else {
        bail!("agent-remote-cli currently supports macOS and Linux")
    }
}

pub fn default_device_name() -> String {
    env::var("HOSTNAME")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .or_else(|| command_output("hostname"))
        .unwrap_or_else(|| "local-device".to_string())
}

pub fn default_ssh_public_key_path() -> Option<PathBuf> {
    let home = env::var_os("HOME").map(PathBuf::from)?;
    ["id_ed25519.pub", "id_rsa.pub"]
        .into_iter()
        .map(|name| home.join(".ssh").join(name))
        .find(|path| path.exists())
}

fn command_output(command: &str) -> Option<String> {
    let output = Command::new(command).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if value.is_empty() {
        None
    } else {
        Some(value)
    }
}
