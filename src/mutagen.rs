use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::api::SyncSessionData;
use crate::config::AppPaths;
use crate::workspace::DEFAULT_EXCLUDES;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MutagenStatus {
    pub installed: bool,
    pub has_conflicts: bool,
    pub output: String,
}

pub fn binary_path(paths: &AppPaths) -> PathBuf {
    let managed = paths.bin_dir().join("mutagen");
    if managed.exists() {
        return managed;
    }
    if let Ok(current_exe) = std::env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let sibling = parent.join("mutagen");
            if sibling.exists() {
                return sibling;
            }
        }
    }
    managed
}

pub fn create(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let remote = sync
        .remote_endpoint
        .as_deref()
        .context("sync session has no remote endpoint")?;
    let name = session_name(sync)?;
    let mut args = vec![
        "sync".to_string(),
        "create".to_string(),
        "--name".to_string(),
        name.to_string(),
    ];
    for exclude in DEFAULT_EXCLUDES {
        args.push("--ignore".to_string());
        args.push((*exclude).to_string());
    }
    args.push(sync.local_path.clone());
    args.push(remote.to_string());
    run(paths, &args, dry_run).map(|_| ())
}

pub fn status(paths: &AppPaths, sync: &SyncSessionData) -> Result<MutagenStatus> {
    let binary = binary_path(paths);
    if !binary.exists() {
        return Ok(MutagenStatus {
            installed: false,
            has_conflicts: false,
            output: format!("mutagen binary missing at {}", binary.display()),
        });
    }
    let name = session_name(sync)?;
    let output = Command::new(binary)
        .args(["sync", "list", name])
        .output()
        .context("failed to execute mutagen sync list")?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let combined = if stdout.is_empty() { stderr } else { stdout };
    let lowered = combined.to_lowercase();
    let has_conflicts = lowered.contains("conflict") && !lowered.contains("0 conflicts");
    Ok(MutagenStatus {
        installed: true,
        has_conflicts,
        output: combined,
    })
}

pub fn pause(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "pause".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn resume(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "resume".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn resolve(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
    let name = session_name(sync)?;
    run(
        paths,
        &["sync".to_string(), "flush".to_string(), name.to_string()],
        dry_run,
    )
    .map(|_| ())
}

pub fn reset(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
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
        create(paths, sync, true)?;
        return Ok(());
    }
    create(paths, sync, false)
}

fn session_name(sync: &SyncSessionData) -> Result<&str> {
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
    run_binary(&binary, args)
}

fn run_binary(binary: &Path, args: &[String]) -> Result<String> {
    let output = Command::new(binary)
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

#[cfg(test)]
mod tests {
    use crate::api::SyncSessionData;

    use super::session_name;

    #[test]
    fn uses_control_plane_session_name() {
        let sync = SyncSessionData {
            id: "sync_1".to_string(),
            user_id: "user_1".to_string(),
            workspace_id: "workspace_1".to_string(),
            node_id: Some("node_1".to_string()),
            local_path: "/tmp/project".to_string(),
            remote_path: "/var/lib/agent-remote/users/u/workspaces/w/files".to_string(),
            status: "starting".to_string(),
            conflict_status: "none".to_string(),
            sync_mode: "two_way".to_string(),
            mutagen_session_id: Some("agent-remote-sync".to_string()),
            remote_endpoint: Some(
                "ssh://agent-remote@10.42.0.10:22/var/lib/agent-remote/users/u/workspaces/w/files"
                    .to_string(),
            ),
            prepare_task_id: Some("prepare_workspace:sync_1".to_string()),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
        };
        assert_eq!(session_name(&sync).unwrap(), "agent-remote-sync");
    }
}
