// Tests for src/bin/agent-remote-wireguard.rs.

#[cfg(unix)]
use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::sync::Mutex;

use clap::{Command, CommandFactory};

use super::Cli;
#[cfg(unix)]
use super::{find_executable, run, wg_requires_elevation, WireGuardCommand};

#[cfg(unix)]
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn assert_documented(command: &Command, path: &str) {
    assert!(
        command.get_about().is_some() || command.get_long_about().is_some(),
        "{path} is missing command help"
    );
    for argument in command.get_arguments() {
        if matches!(argument.get_id().as_str(), "help" | "version") {
            continue;
        }
        assert!(
            argument.get_help().is_some() || argument.get_long_help().is_some(),
            "{path} argument {} is missing help",
            argument.get_id()
        );
    }
    for child in command.get_subcommands() {
        assert_documented(child, &format!("{path} {}", child.get_name()));
    }
}

#[test]
fn every_wireguard_command_and_argument_has_help() {
    let command = Cli::command();
    command.clone().debug_assert();
    assert_documented(&command, "agent-remote-wireguard");
}

#[cfg(unix)]
#[test]
fn status_uses_the_configured_wg_and_propagates_failures() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let wg = dir.path().join("wg");
    fs::write(&wg, "#!/bin/sh\n[ \"$1\" = show ]\n").unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
    env::set_var("AGENT_REMOTE_WG", &wg);
    run(WireGuardCommand::Status).unwrap();

    let sudo = dir.path().join("sudo");
    fs::write(
        &wg,
        "#!/bin/sh\nif [ \"$AGENT_REMOTE_TEST_ELEVATED\" = 1 ]; then echo 'interface: elevated'; exit 0; fi\necho 'Unable to access interface: Permission denied' >&2\nexit 1\n",
    )
    .unwrap();
    fs::write(
        &sudo,
        "#!/bin/sh\n[ \"$1\" = -- ] || exit 64\nshift\nAGENT_REMOTE_TEST_ELEVATED=1 exec \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
    env::set_var("AGENT_REMOTE_SUDO", &sudo);
    run(WireGuardCommand::Status).unwrap();

    fs::write(&sudo, "#!/bin/sh\nexit 7\n").unwrap();
    let error = run(WireGuardCommand::Status).unwrap_err().to_string();
    assert!(error.contains("elevated wg show exited"));

    fs::write(&wg, "#!/bin/sh\nexit 9\n").unwrap();
    let error = run(WireGuardCommand::Status).unwrap_err().to_string();
    assert!(error.contains("wg show exited"));
    env::remove_var("AGENT_REMOTE_WG");
    env::remove_var("AGENT_REMOTE_SUDO");
}

#[cfg(unix)]
#[test]
fn status_recognizes_platform_permission_errors() {
    assert!(wg_requires_elevation(b"Permission denied"));
    assert!(wg_requires_elevation(b"Operation not permitted"));
    assert!(wg_requires_elevation(b"Access is denied."));
    assert!(!wg_requires_elevation(b"Invalid interface"));
}

#[cfg(unix)]
#[test]
fn executable_lookup_supports_environment_fixed_and_path_locations() {
    let _guard = ENV_LOCK.lock().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let tool = dir.path().join("test-wg");
    fs::write(&tool, "#!/bin/sh\n").unwrap();

    env::set_var("TEST_AGENT_REMOTE_WG", &tool);
    assert_eq!(
        find_executable("TEST_AGENT_REMOTE_WG", "missing", &[]),
        Some(tool.clone())
    );
    env::remove_var("TEST_AGENT_REMOTE_WG");

    assert_eq!(
        find_executable(
            "TEST_AGENT_REMOTE_WG",
            "test-wg",
            &[dir.path().to_str().unwrap()]
        ),
        Some(tool.clone())
    );

    let previous_path = env::var_os("PATH");
    env::set_var("PATH", dir.path());
    assert_eq!(
        find_executable("TEST_AGENT_REMOTE_WG", "test-wg", &[]),
        Some(tool)
    );
    if let Some(path) = previous_path {
        env::set_var("PATH", path);
    } else {
        env::remove_var("PATH");
    }
}
