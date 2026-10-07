use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process;
use tokio::process::Command;

use agent_remote_cli::config::AppPaths;
use anyhow::{bail, Context, Result};

#[tokio::main]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("agent-remote ssh proxy: {error:#}");
        process::exit(1);
    }
}

async fn run() -> Result<()> {
    let ssh =
        system_ssh().context("OpenSSH ssh was not found; install the system OpenSSH client")?;
    let paths = AppPaths::new(None)?;
    paths.ensure_base_dirs()?;
    let known_hosts = paths.home().join("ssh").join("known_hosts");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        std::fs::set_permissions(paths.ssh_dir(), std::fs::Permissions::from_mode(0o700))?;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&known_hosts)?;
        std::fs::set_permissions(&known_hosts, std::fs::Permissions::from_mode(0o600))?;
    }
    let arguments = proxy_args(&known_hosts, env::args_os().skip(1));
    let mut command = Command::new(&ssh);
    command.args(&arguments);
    let status = if agent_remote_cli::ssh::is_managed_attach(&arguments) {
        agent_remote_cli::ssh::execute_interactive(&mut command).await
    } else {
        command.status().await.map_err(Into::into)
    }
    .with_context(|| format!("failed to execute {}", ssh.display()))?;
    match status.code() {
        Some(code) => process::exit(code),
        None => bail!("system ssh terminated without an exit code"),
    }
}

fn proxy_args(known_hosts: &Path, arguments: impl IntoIterator<Item = OsString>) -> Vec<OsString> {
    let mut result = vec![
        OsString::from("-o"),
        OsString::from("StrictHostKeyChecking=accept-new"),
        OsString::from("-o"),
        OsString::from(format!(
            "UserKnownHostsFile={}",
            known_hosts.to_string_lossy()
        )),
    ];
    result.extend(arguments);
    result
}

fn system_ssh() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_SYSTEM_SSH") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    #[cfg(unix)]
    if Path::new("/usr/bin/ssh").is_file() {
        return Some(PathBuf::from("/usr/bin/ssh"));
    }
    #[cfg(windows)]
    if let Some(windows) = env::var_os("WINDIR") {
        let path = PathBuf::from(windows)
            .join("System32")
            .join("OpenSSH")
            .join("ssh.exe");
        if path.is_file() {
            return Some(path);
        }
    }
    let current = env::current_exe().ok();
    for directory in env::split_paths(&env::var_os("PATH")?) {
        let candidate = directory.join(if cfg!(windows) { "ssh.exe" } else { "ssh" });
        if candidate.is_file() && !same_file_path(current.as_deref(), &candidate) {
            return Some(candidate);
        }
    }
    None
}

fn same_file_path(left: Option<&Path>, right: &Path) -> bool {
    left.and_then(|path| path.canonicalize().ok()) == right.canonicalize().ok()
}

#[cfg(test)]
#[path = "../../tests/unit/src/bin/agent-remote-ssh.rs"]
mod tests;
