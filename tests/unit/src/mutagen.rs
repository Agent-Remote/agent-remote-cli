// Tests for src/mutagen.rs.

use std::env;
use std::path::Path;

use crate::api::SyncSessionData;
use crate::config::AppPaths;

use super::{
    combine_output, configured_mutagen_command, create_args, is_missing_session_output,
    mutagen_path, session_name,
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
        "two-way-safe",
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
    assert_eq!(
        environment.get(std::ffi::OsStr::new("MUTAGEN_DATA_DIRECTORY")),
        Some(&super::desktop::data_directory().unwrap().as_os_str())
    );
}

#[test]
fn legacy_stopped_namespace_probe() {
    let Some(home) = std::env::var_os("AGENT_REMOTE_TEST_LEGACY_ENVIRONMENT") else {
        return;
    };
    let paths = AppPaths::from_home(home.into());
    let error = super::mutation_guard(&paths, false).err().unwrap();
    assert!(error
        .to_string()
        .contains("agent-remote deps mutagen-environment --repair"));
    assert!(format!("{error:#}").contains("sync_mutagen_environment_mismatch"));
}

#[cfg(unix)]
#[test]
fn legacy_commands_never_restart_an_existing_stopped_namespace_or_rewrite_old_marker() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let home = root.path().join("home");
    let paths = AppPaths::from_home(home.clone());
    std::fs::create_dir_all(paths.bin_dir()).unwrap();
    std::fs::create_dir_all(paths.ssh_dir()).unwrap();
    let marker = paths.ssh_dir().join("mutagen-environment");
    std::fs::write(&marker, "1\nold-installation\n").unwrap();
    for name in ["mutagen", "ssh", "scp"] {
        let binary = paths.bin_dir().join(name);
        std::fs::write(&binary,"#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$AGENT_REMOTE_HOME/unexpected-execution\"\nexit 91\n").unwrap();
        std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let data = root.path().join("data");
    std::fs::create_dir_all(data.join("daemon")).unwrap();
    std::fs::write(data.join("daemon/daemon.lock"), "").unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "mutagen::tests::legacy_stopped_namespace_probe"])
        .env("AGENT_REMOTE_TEST_LEGACY_ENVIRONMENT", &home)
        .env("MUTAGEN_DATA_DIRECTORY", &data)
        .env("HOME", root.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!home.join("unexpected-execution").exists());
    assert_eq!(
        std::fs::read_to_string(marker).unwrap(),
        "1\nold-installation\n"
    );
    assert!(!data.join("agent-remote-environment.json").exists());
}

#[cfg(unix)]
#[test]
fn legacy_status_is_read_only_and_never_autostarts_or_migrates_daemon() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("home"));
    std::fs::create_dir_all(paths.bin_dir()).unwrap();
    let binary = paths.bin_dir().join("mutagen");
    std::fs::write(&binary,"#!/bin/sh\n[ \"$MUTAGEN_DISABLE_AUTOSTART\" = 1 ] || exit 92\n[ \"$1 $2\" = 'sync list' ] || exit 93\nprintf '%s\\n' 'connection refused' >&2\nexit 1\n").unwrap();
    std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700)).unwrap();
    let result = super::status(&paths, &sync_session()).unwrap();
    assert!(result.installed);
    assert!(!result.session_exists);
    assert!(!result.session_missing);
    assert_eq!(result.output, "connection refused");
    assert!(!paths.ssh_dir().exists());
    assert!(!paths.state_db_path().exists());
    assert!(!paths.home().join("config-write.lock").exists());
}

#[test]
fn legacy_dry_run_does_not_acquire_or_prepare_namespace() {
    let root = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(root.path().join("absent-home"));
    assert!(super::mutation_guard(&paths, true).unwrap().is_none());
    assert!(!paths.home().exists());
}
