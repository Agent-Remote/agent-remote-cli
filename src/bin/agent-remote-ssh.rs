use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use agent_remote_cli::config::AppPaths;
use anyhow::{bail, Context, Result};

fn main() {
    if let Err(error) = run() {
        eprintln!("agent-remote ssh proxy: {error:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let ssh = system_ssh().context(
        "OpenSSH ssh was not found; install the Windows OpenSSH Client optional feature",
    )?;
    let paths = AppPaths::new(None)?;
    paths.ensure_base_dirs()?;
    let known_hosts = paths.home().join("ssh").join("known_hosts");
    let status = Command::new(&ssh)
        .args(proxy_args(&known_hosts, env::args_os().skip(1)))
        .status()
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
mod tests {
    use std::ffi::{OsStr, OsString};
    use std::path::Path;

    use super::proxy_args;

    #[test]
    fn proxy_uses_managed_known_hosts_and_accepts_only_new_keys() {
        let arguments = proxy_args(
            Path::new("C:/Agent Remote/ssh/known_hosts"),
            [OsString::from("example.test")],
        );
        let expected = [
            "-o",
            "StrictHostKeyChecking=accept-new",
            "-o",
            "UserKnownHostsFile=C:/Agent Remote/ssh/known_hosts",
            "example.test",
        ];
        assert_eq!(
            arguments
                .iter()
                .map(OsString::as_os_str)
                .collect::<Vec<_>>(),
            expected.iter().map(OsStr::new).collect::<Vec<_>>()
        );
    }
}
