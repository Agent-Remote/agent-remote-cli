use std::env;
use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::{bail, Context, Result};

use crate::api::SyncSessionData;
use crate::config::AppPaths;
use crate::workspace::{ensure_git_ready, DEFAULT_EXCLUDES};

const MANAGED_SSH_ENVIRONMENT_VERSION: &str = "1";

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
    if sync.sync_git {
        ensure_git_ready(Path::new(&sync.local_path))?;
    }
    let remote = sync
        .remote_endpoint
        .as_deref()
        .context("sync session has no remote endpoint")?;
    let name = session_name(sync)?;
    let args = create_args(sync, remote, name);
    run(paths, &args, dry_run)?;
    run(
        paths,
        &["sync".to_string(), "flush".to_string(), name.to_string()],
        dry_run,
    )?;
    Ok(())
}

fn create_args(sync: &SyncSessionData, remote: &str, name: &str) -> Vec<String> {
    let mut args = vec![
        "sync".to_string(),
        "create".to_string(),
        "--sync-mode".to_string(),
        "two-way-safe".to_string(),
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
    create(paths, sync, dry_run)?;
    Ok(true)
}

pub fn pause(paths: &AppPaths, sync: &SyncSessionData, dry_run: bool) -> Result<()> {
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
    if ensure(paths, sync, dry_run)? {
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

pub fn terminate_session(paths: &AppPaths, name: &str, dry_run: bool) -> Result<()> {
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

fn mutagen_command(paths: &AppPaths, binary: &Path) -> Result<Command> {
    paths.ensure_base_dirs()?;
    let ssh_directory = prepare_managed_ssh_environment(paths, binary)?;
    configured_mutagen_command(paths, binary, &ssh_directory)
}

fn configured_mutagen_command(
    paths: &AppPaths,
    binary: &Path,
    ssh_directory: &Path,
) -> Result<Command> {
    let mut command = Command::new(binary);
    command
        .env("PATH", mutagen_path(paths)?)
        .env("AGENT_REMOTE_HOME", paths.home())
        .env("MUTAGEN_SSH_PATH", ssh_directory);
    Ok(command)
}

fn prepare_managed_ssh_environment(paths: &AppPaths, binary: &Path) -> Result<PathBuf> {
    let ssh_directory = binary
        .parent()
        .context("Mutagen binary has no parent directory")?;
    for command in ["ssh", "scp"] {
        let proxy = crate::platform::managed_binary(ssh_directory, command);
        if !proxy.is_file() {
            bail!(
                "managed Mutagen {} proxy is missing at {}; reinstall the packaged CLI dependencies",
                command.to_uppercase(),
                proxy.display()
            );
        }
    }

    let marker = paths.ssh_dir().join("mutagen-environment");
    let desired_marker = format!(
        "{MANAGED_SSH_ENVIRONMENT_VERSION}\n{}\n",
        ssh_directory.to_string_lossy()
    );
    if fs::read_to_string(&marker).ok().as_deref() == Some(desired_marker.as_str()) {
        return Ok(ssh_directory.to_path_buf());
    }

    let output = configured_mutagen_command(paths, binary, ssh_directory)?
        .args(["daemon", "stop"])
        .output()
        .context("failed to restart Mutagen for managed SSH configuration")?;
    let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
    if !output.status.success() && !daemon_was_not_running(&stderr) {
        bail!(
            "unable to restart Mutagen for managed SSH configuration: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    if output.status.success() {
        std::thread::sleep(Duration::from_millis(250));
    }
    fs::write(&marker, desired_marker)
        .with_context(|| format!("failed to write {}", marker.display()))?;
    Ok(ssh_directory.to_path_buf())
}

fn daemon_was_not_running(output: &str) -> bool {
    output.contains("connection timed out (is the daemon running?)")
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
mod tests {
    use std::env;
    use std::path::Path;

    use crate::api::SyncSessionData;
    use crate::config::AppPaths;

    use super::{
        combine_output, configured_mutagen_command, create_args, daemon_was_not_running,
        is_missing_session_output, mutagen_path, session_name,
    };

    fn sync_session() -> SyncSessionData {
        SyncSessionData {
            id: "sync_1".to_string(),
            user_id: "user_1".to_string(),
            workspace_id: "workspace_1".to_string(),
            node_id: Some("node_1".to_string()),
            local_path: "/tmp/project".to_string(),
            remote_path: "/var/lib/agent-remote/users/u/workspaces/w/files".to_string(),
            status: "starting".to_string(),
            conflict_status: "none".to_string(),
            sync_mode: "two_way".to_string(),
            sync_git: true,
            exclude: Vec::new(),
            mutagen_session_id: Some("agent-remote-sync".to_string()),
            remote_endpoint: Some(
                "agent-remote@10.42.0.10:22:/var/lib/agent-remote/users/u/workspaces/w/files"
                    .to_string(),
            ),
            prepare_task_id: Some("prepare_workspace:sync_1".to_string()),
            created_at: "2026-07-04T00:00:00Z".to_string(),
            updated_at: "2026-07-04T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn uses_control_plane_session_name() {
        let sync = sync_session();
        assert_eq!(session_name(&sync).unwrap(), "agent-remote-sync");
    }

    #[test]
    fn isolates_git_index_from_two_way_sync() {
        let sync = sync_session();
        let args = create_args(
            &sync,
            sync.remote_endpoint.as_deref().unwrap(),
            sync.mutagen_session_id.as_deref().unwrap(),
        );
        assert!(args
            .windows(2)
            .any(|values| values == ["--ignore", ".git/index"]));
    }

    #[test]
    fn prepends_managed_bin_to_mutagen_path() {
        let paths = AppPaths::from_home("/tmp/agent-remote-test".into());
        let path = mutagen_path(&paths).unwrap();
        let entries: Vec<_> = env::split_paths(&path).collect();
        assert_eq!(entries.first(), Some(&paths.bin_dir()));
    }

    #[test]
    fn recognizes_missing_session_errors() {
        assert!(is_missing_session_output(
            "error: unable to locate requested sessions: specification did not match any sessions"
        ));
        assert!(!is_missing_session_output(
            "error: unable to connect to daemon"
        ));
    }

    #[test]
    fn preserves_stdout_and_stderr_for_status_diagnostics() {
        assert_eq!(
            combine_output(
                "Started Mutagen daemon".to_string(),
                "unable to locate requested sessions".to_string()
            ),
            "Started Mutagen daemon\nunable to locate requested sessions"
        );
    }

    #[test]
    fn configures_mutagen_to_use_managed_ssh_commands() {
        let paths = AppPaths::from_home("/tmp/agent-remote-test".into());
        let command = configured_mutagen_command(
            &paths,
            Path::new("/opt/agent-remote/bin/mutagen"),
            Path::new("/opt/agent-remote/bin"),
        )
        .unwrap();
        let environment: std::collections::HashMap<_, _> = command
            .get_envs()
            .filter_map(|(key, value)| value.map(|value| (key, value)))
            .collect();
        assert_eq!(
            environment.get(std::ffi::OsStr::new("MUTAGEN_SSH_PATH")),
            Some(&std::ffi::OsStr::new("/opt/agent-remote/bin"))
        );
    }

    #[test]
    fn recognizes_an_absent_daemon_during_environment_migration() {
        assert!(daemon_was_not_running(
            "error: unable to connect to daemon: connection timed out (is the daemon running?)"
        ));
        assert!(!daemon_was_not_running("error: access denied"));
    }
}
