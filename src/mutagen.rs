use std::env;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::api::SyncSessionData;
use crate::config::AppPaths;
use crate::workspace::{ensure_git_ready, DEFAULT_EXCLUDES};

pub mod desktop;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutagenStatus {
    pub installed: bool,
    pub session_exists: bool,
    pub session_missing: bool,
    pub has_conflicts: bool,
    pub output: String,
}

pub fn binary_path(paths: &AppPaths) -> PathBuf {
    let managed = crate::platform::managed_binary(&paths.bin_dir(), "mutagen");
    if managed.exists() {
        return managed;
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = crate::platform::managed_binary(parent, "mutagen");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    managed
}

pub fn create(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    create_with_mode(paths, sync, dry_run, "two-way-safe")
}

fn create_with_mode(
    paths: &AppPaths,
    sync: &SyncSessionData,
    dry_run: bool,
    sync_mode: &str,
) -> Result<()> {
    if sync.sync_git {
        ensure_git_ready(Path::new(&sync.local_path))?;
    }
    let remote = sync
        .remote_endpoint
        .as_deref()
        .context("sync session has no remote endpoint")?;
    let name = session_name(sync)?;
    let args = create_args(sync, remote, name, sync_mode);
    run(paths, &args, dry_run)?;
    run(
        paths,
        &["sync".to_string(), "flush".to_string(), name.to_string()],
        dry_run,
    )?;
    Ok(())
}

fn create_args(sync: &SyncSessionData, remote: &str, name: &str, sync_mode: &str) -> Vec<String> {
    let mut args = vec![
        "sync".to_string(),
        "create".to_string(),
        "--sync-mode".to_string(),
        sync_mode.to_string(),
        "--name".to_string(),
        name.to_string(),
        "--default-file-mode".to_string(),
        "0660".to_string(),
        "--default-directory-mode".to_string(),
        "0770".to_string(),
    ];
    for exclude in DEFAULT_EXCLUDES {
        args.push("--ignore".to_string());
        args.push((*exclude).to_string());
    }
    args.push(sync.local_path.clone());
    args.push(remote.to_string());
    args
}

pub fn status(paths: &AppPaths, sync: &SyncSessionData) -> Result<MutagenStatus> {
    let binary = binary_path(paths);
    if !binary.exists() {
        return Ok(MutagenStatus {
            installed: false,
            session_exists: false,
            session_missing: false,
            has_conflicts: false,
            output: format!("mutagen binary missing at {}", binary.display()),
        });
    }
    let name = session_name(sync)?;
    let output = mutagen_command(paths, &binary)?
        .args(["sync", "list", name])
        .output()
        .context("failed to execute mutagen sync list")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = combine_output(stdout, stderr);
    let lowered = combined.to_lowercase();
    let session_exists = output.status.success();
    let session_missing = !session_exists && is_missing_session_output(&lowered);
    let has_conflicts = lowered.contains("conflict") && !lowered.contains("0 conflicts");
    Ok(MutagenStatus {
        installed: true,
        session_exists,
        session_missing,
        has_conflicts,
        output: combined,
    })
}

pub fn ensure(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<bool> {
    let _guard = mutation_guard(paths, dry_run)?;
    ensure_prepared(paths, sync, dry_run)
}

fn ensure_prepared(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<bool> {
    let status = status(paths, sync)?;
    if !status.installed {
        bail!("Mutagen is missing; install the packaged CLI dependencies");
    }
    if status.session_exists {
        return Ok(false);
    }
    if !status.session_missing {
        bail!("unable to inspect the managed Mutagen session");
    }
    create_with_mode(paths, sync, dry_run, "two-way-safe")?;
    Ok(true)
}

pub fn pause(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    let status = status(paths, sync)?;
    if !status.installed {
        bail!("Mutagen is missing; install the packaged CLI dependencies");
    }
    if status.session_missing {
        return Ok(());
    }
    if !status.session_exists {
        bail!("unable to inspect the managed Mutagen session");
    }
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "pause".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn resume(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    if ensure_prepared(paths, sync, dry_run)? {
        return Ok(());
    }
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "resume".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn resolve(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "flush".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn reset(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    let name = session_name(sync)?;
    let _ = run(
        paths,
        &[
            "sync".to_string(),
            "terminate".to_string(),
            name.to_string(),
        ],
        dry_run,
    );
    if dry_run {
        create_with_mode(paths, sync, true, "two-way-safe")?;
        return Ok(());
    }
    create_with_mode(paths, sync, false, "two-way-safe")
}

pub fn terminate_session(paths: &AppPaths, name: &str, dry_run: bool) -> Result<()> {
    let _guard = mutation_guard(paths, dry_run)?;
    run(
        paths,
        &[
            "sync".to_string(),
            "terminate".to_string(),
            name.to_string(),
        ],
        dry_run,
    )
    .map(|_| ())
}

pub(crate) fn session_name(sync: &SyncSessionData) -> Result<&str> {
    sync.mutagen_session_id
        .as_deref()
        .context("sync session has no Mutagen session name")
}

fn run(paths: &AppPaths, args: &[String], dry_run: bool) -> Result<String> {
    let binary = binary_path(paths);
    if dry_run {
        println!("{} {}", binary.display(), args.join(" "));
        return Ok(String::new());
    }
    if !binary.exists() {
        bail!(
            "Mutagen binary is missing at {}; install the packaged CLI dependencies",
            binary.display()
        );
    }
    run_binary(paths, &binary, args)
}

fn run_binary(paths: &AppPaths, binary: &Path, args: &[String]) -> Result<String> {
    let output = mutagen_command(paths, binary)?
        .args(args)
        .output()
        .context("failed to execute Mutagen")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !output.status.success() {
        bail!("Mutagen exited with {}: {}", output.status, stderr);
    }
    if stdout.is_empty() {
        Ok(stderr)
    } else {
        Ok(stdout)
    }
}

/// One guard spans every command in the public mutation, including create+flush
/// and status+resume. Nested helpers never acquire it again.
fn mutation_guard(
    paths: &AppPaths,
    dry_run: bool,
) -> Result<Option<desktop::environment::NamespaceGuard>> {
    if dry_run {
        return Ok(None);
    }
    desktop::environment::legacy_guard(paths).map(Some)
        .context("Mutagen environment requires review; run agent-remote deps mutagen-environment, then agent-remote deps mutagen-environment --repair if needed")
}

/// Legacy status and guarded mutation commands do not change daemon lifecycle.
fn mutagen_command(paths: &AppPaths, binary: &Path) -> Result<Command> {
    let directory = binary
        .parent()
        .context("Mutagen binary has no parent directory")?;
    let mut command = configured_mutagen_command(paths, binary, directory)?;
    command.env("MUTAGEN_DISABLE_AUTOSTART", "1");
    Ok(command)
}

pub(crate) fn configured_mutagen_command(
    paths: &AppPaths,
    binary: &Path,
    ssh_directory: &Path,
) -> Result<Command> {
    let mut command = Command::new(binary);
    command
        .env("PATH", mutagen_path(paths)?)
        .env("AGENT_REMOTE_HOME", paths.home())
        .env("MUTAGEN_SSH_PATH", ssh_directory)
        .env("MUTAGEN_DATA_DIRECTORY", desktop::data_directory()?);
    Ok(command)
}

fn is_missing_session_output(output: &str) -> bool {
    output.contains("unable to locate requested sessions")
        || output.contains("did not match any sessions")
}

fn combine_output(stdout: String, stderr: String) -> String {
    match (stdout.is_empty(), stderr.is_empty()) {
        (true, _) => stderr,
        (_, true) => stdout,
        (false, false) => format!("{stdout}\n{stderr}"),
    }
}

fn mutagen_path(paths: &AppPaths) -> Result<OsString> {
    let mut entries = vec![paths.bin_dir()];
    if let Some(openssh_bin) = crate::platform::openssh_bin_dir() {
        entries.push(openssh_bin);
    }
    if let Some(current) = env::var_os("PATH") {
        entries.extend(env::split_paths(&current));
    }
    env::join_paths(entries).context("failed to construct Mutagen PATH")
}

#[cfg(test)]
#[path = "../tests/unit/src/mutagen.rs"]
mod tests;
