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
            } else {
                println!("wg-quick: missing");
            }
            Ok(())
        }
        "up" | "down" => run_wg_quick(&action, &config, dry_run),
        value => bail!("unknown action {value}"),
    }
}

fn run_wg_quick(action: &str, config: &PathBuf, dry_run: bool) -> Result<()> {
    let wg_quick = find_wg_quick().context("wg-quick is missing from this release or PATH")?;
    if dry_run {
        println!("{} {} {}", wg_quick.display(), action, config.display());
        return Ok(());
    }
    let status = Command::new(wg_quick)
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
    let path_value = env::var_os("PATH")?;
    for dir in env::split_paths(&path_value) {
        let candidate = dir.join("wg-quick");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn print_usage() {
    println!("agent-remote-wireguard <check|up|down> --config <path> [--dry-run]");
}
