use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    let action = args.next().unwrap_or_else(|| "help".to_string());
    if action == "help" || action == "--help" || action == "-h" {
        print_usage();
        return Ok(());
    }
    let mut config: Option<PathBuf> = None;
    let mut dry_run = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config = args.next().map(PathBuf::from),
            "--dry-run" => dry_run = true,
            value => bail!("unknown argument {value}"),
        }
    }
    let config = config.context("--config is required")?;
    if !config.exists() {
        bail!("WireGuard config does not exist: {}", config.display());
    }
    match action.as_str() {
        "check" => {
            println!("config ok: {}", config.display());
            if let Some(path) = find_wg_quick() {
                println!("wg-quick: {}", path.display());
                Ok(())
            } else {
                bail!("wg-quick is missing; {}", install_hint());
            }
        }
        "up" | "down" => run_wg_quick(&action, &config, dry_run),
        value => bail!("unknown action {value}"),
    }
}

fn run_wg_quick(action: &str, config: &PathBuf, dry_run: bool) -> Result<()> {
    let wg_quick = if dry_run {
        find_wg_quick().unwrap_or_else(|| PathBuf::from("wg-quick"))
    } else {
        find_wg_quick().context("wg-quick is missing from this release or PATH")?
    };
    if dry_run {
        println!("{} {} {}", wg_quick.display(), action, config.display());
        return Ok(());
    }
    let managed_bin = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()));
    let mut command = Command::new(wg_quick);
    if let Some(managed_bin) = managed_bin {
        let mut paths = vec![managed_bin];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        command.env(
            "PATH",
            env::join_paths(paths).context("failed to build managed PATH")?,
        );
    }
    let status = command
        .arg(action)
        .arg(config)
        .status()
        .context("failed to execute wg-quick")?;
    if !status.success() {
        bail!("wg-quick exited with {status}");
    }
    Ok(())
}

fn find_wg_quick() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_WG_QUICK") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join("wg-quick");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    for candidate in [
        PathBuf::from("/opt/homebrew/bin/wg-quick"),
        PathBuf::from("/usr/local/bin/wg-quick"),
        PathBuf::from("/usr/bin/wg-quick"),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let path_value = env::var_os("PATH")?;
    for dir in env::split_paths(&path_value) {
        let candidate = dir.join("wg-quick");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "reinstall agent-remote to restore the managed WireGuard tools"
    } else {
        "install the wireguard-tools package for this system"
    }
}

fn print_usage() {
    println!("agent-remote-wireguard <check|up|down> --config <path> [--dry-run]");
}
