use std::env;
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use anyhow::{bail, Context, Result};

fn main() {
    if let Err(error) = run() {
        eprintln!("agent-remote scp proxy: {error:#}");
        process::exit(1);
    }
}

fn run() -> Result<()> {
    let scp = system_scp().context(
        "OpenSSH scp was not found; install the Windows OpenSSH Client optional feature",
    )?;
    let status = Command::new(&scp)
        .arg("-O")
        .args(env::args_os().skip(1))
        .status()
        .with_context(|| format!("failed to execute {}", scp.display()))?;
    match status.code() {
        Some(code) => process::exit(code),
        None => bail!("system scp terminated without an exit code"),
    }
}

fn system_scp() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_SYSTEM_SCP") {
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
            .join("scp.exe");
        if path.is_file() {
            return Some(path);
        }
    }
    let current = env::current_exe().ok();
    for directory in env::split_paths(&env::var_os("PATH")?) {
        let candidate = directory.join(if cfg!(windows) { "scp.exe" } else { "scp" });
        if candidate.is_file() && !same_file_path(current.as_deref(), &candidate) {
            return Some(candidate);
        }
    }
    None
}

fn same_file_path(left: Option<&Path>, right: &Path) -> bool {
    left.and_then(|path| path.canonicalize().ok()) == right.canonicalize().ok()
}
