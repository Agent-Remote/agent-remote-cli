use std::path::Path;
use std::process::{Command, Output};

const AGENT_REMOTE: &str = env!("CARGO_BIN_EXE_agent-remote");
const FCLAUDE: &str = env!("CARGO_BIN_EXE_fclaude");
const WIREGUARD: &str = env!("CARGO_BIN_EXE_agent-remote-wireguard");

fn run(binary: &str, args: &[&str]) -> Output {
    Command::new(binary)
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("failed to run {binary} {args:?}: {error}"))
}

fn assert_help(binary: &str, command_path: &[&str]) {
    let mut args = command_path.to_vec();
    args.push("--help");
    let output = run(binary, &args);
    assert!(
        output.status.success(),
        "help failed for {binary} {command_path:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("Usage:"),
        "help lacks usage for {binary} {command_path:?}"
    );
}

#[test]
fn every_command_path_executes_help_successfully() {
    for path in [
        &[][..],
        &["init"],
        &["login"],
        &["logout"],
        &["status"],
        &["doctor"],
        &["deps"],
        &["deps", "status"],
        &["wireguard"],
        &["wireguard", "config"],
        &["wireguard", "check"],
        &["wireguard", "status"],
        &["wireguard", "up"],
        &["wireguard", "down"],
        &["ssh"],
        &["ssh", "check"],
        &["sync"],
        &["sync", "ensure"],
        &["sync", "status"],
        &["sync", "pause"],
        &["sync", "resume"],
        &["sync", "resolve"],
        &["sync", "reset"],
        &["account"],
        &["account", "list"],
        &["account", "create"],
        &["account", "bind"],
        &["account", "import-config"],
        &["account", "verify"],
        &["account", "status"],
        &["account", "disable"],
        &["account", "default"],
        &["account", "default", "set"],
        &["account", "default", "get"],
        &["account", "default", "clear"],
        &["credentials"],
        &["credentials", "list"],
        &["credentials", "create"],
        &["credentials", "bind"],
        &["credentials", "unbind"],
        &["device"],
        &["device", "install"],
        &["device", "uninstall"],
        &["device", "status"],
        &["device", "launch"],
        &["device", "diagnose"],
        &["device", "revoke"],
        &["device", "rotate-token"],
        &["attach"],
        &["forward"],
        &["forward", "list"],
        &["forward", "stop"],
    ] {
        assert_help(AGENT_REMOTE, path);
    }

    for path in [
        &[][..],
        &["run"],
        &["new"],
        &["list"],
        &["attach"],
        &["stop"],
        &["delete"],
        &["forward"],
        &["forward", "list"],
        &["forward", "stop"],
    ] {
        assert_help(FCLAUDE, path);
    }

    for path in [&[][..], &["check"], &["status"], &["up"], &["down"]] {
        assert_help(WIREGUARD, path);
    }
}

#[test]
fn fclaude_delete_help_includes_failed_sessions() {
    let output = run(FCLAUDE, &["delete", "--help"]);
    assert!(
        output.status.success(),
        "delete help failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("stopped, interrupted, or failed"),
        "delete help does not document failed sessions"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn device_uninstall_removes_fixed_residue_and_preserves_unrelated_data() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let tools = temp.path().join("tools");
    fs::create_dir(&tools).unwrap();
    for (name, body) in [
        ("pgrep", "#!/bin/sh\nexit 1\n"),
        ("tccutil", "#!/bin/sh\nexit 0\n"),
        ("plutil", "#!/bin/sh\nprintf 'dev.agentremote.device\\n'\n"),
    ] {
        let path = tools.join(name);
        fs::write(&path, body).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    let app = temp
        .path()
        .join("Applications/Agent Remote Device.app/Contents");
    fs::create_dir_all(&app).unwrap();
    fs::write(app.join("Info.plist"), b"test plist").unwrap();
    let device_container = temp
        .path()
        .join("Library/Containers/dev.agentremote.device/Data");
    fs::create_dir_all(&device_container).unwrap();
    let unrelated = temp
        .path()
        .join("Library/Containers/com.example.unrelated/Data");
    fs::create_dir_all(&unrelated).unwrap();

    let output = Command::new(AGENT_REMOTE)
        .args(["--color", "never", "device", "uninstall", "--yes"])
        .env("HOME", temp.path())
        .env("AGENT_REMOTE_HOME", temp.path().join("agent-remote-state"))
        .env("PATH", &tools)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!app.parent().unwrap().exists());
    assert!(!device_container.parent().unwrap().exists());
    assert!(unrelated.exists());
    assert!(String::from_utf8_lossy(&output.stdout).contains("was not revoked"));
}

fn assert_color_contract(binary: &str, args: &[&str], home: &Path) {
    let home = home.to_str().expect("temporary path must be UTF-8");

    let mut always_args = vec!["--color", "always"];
    always_args.extend_from_slice(args);
    let always = Command::new(binary)
        .args(&always_args)
        .env("AGENT_REMOTE_HOME", home)
        .output()
        .unwrap();
    assert!(
        always.stdout.contains(&0x1b) || always.stderr.contains(&0x1b),
        "--color always emitted no ANSI for {binary}"
    );

    let mut never_args = vec!["--color", "never"];
    never_args.extend_from_slice(args);
    let never = Command::new(binary)
        .args(&never_args)
        .env("AGENT_REMOTE_HOME", home)
        .output()
        .unwrap();
    assert!(
        !never.stdout.contains(&0x1b) && !never.stderr.contains(&0x1b),
        "--color never emitted ANSI for {binary}"
    );
}

#[test]
fn every_binary_honors_explicit_color_modes() {
    let temp = tempfile::tempdir().unwrap();
    assert_color_contract(AGENT_REMOTE, &["status"], temp.path());
    assert_color_contract(FCLAUDE, &["list"], temp.path());

    let missing_config = temp.path().join("missing.conf");
    assert_color_contract(
        WIREGUARD,
        &[
            "check",
            "--config",
            missing_config
                .to_str()
                .expect("temporary path must be UTF-8"),
        ],
        temp.path(),
    );
}

#[test]
fn auto_color_honors_no_color() {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(AGENT_REMOTE)
        .args(["--color", "auto", "status"])
        .env("AGENT_REMOTE_HOME", temp.path())
        .env("NO_COLOR", "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(!output.stdout.contains(&0x1b));
    assert!(!output.stderr.contains(&0x1b));
}

#[cfg(unix)]
#[test]
fn wireguard_status_runs_wg_show_and_preserves_output() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let wg = temp.path().join("wg");
    fs::write(
        &wg,
        "#!/bin/sh\n[ \"$1\" = show ] || exit 64\nprintf 'interface: agent-remote\\n  latest handshake: 8 seconds ago\\n'\n",
    )
    .unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(AGENT_REMOTE)
        .args(["--color", "never", "wireguard", "status"])
        .env("AGENT_REMOTE_HOME", temp.path())
        .env("AGENT_REMOTE_WG", &wg)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("interface: agent-remote"));
    assert!(stdout.contains("latest handshake: 8 seconds ago"));
}

#[cfg(unix)]
#[test]
fn wireguard_status_retries_with_sudo_after_permission_denied() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().unwrap();
    let wg = temp.path().join("wg");
    let sudo = temp.path().join("sudo");
    fs::write(
        &wg,
        "#!/bin/sh\nif [ \"$AGENT_REMOTE_TEST_ELEVATED\" = 1 ]; then printf 'interface: elevated-agent-remote\\n'; exit 0; fi\nprintf 'Unable to access interface: Permission denied\\n' >&2\nexit 1\n",
    )
    .unwrap();
    fs::write(
        &sudo,
        "#!/bin/sh\n[ \"$1\" = -- ] || exit 64\nshift\nAGENT_REMOTE_TEST_ELEVATED=1 exec \"$@\"\n",
    )
    .unwrap();
    fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
    fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(AGENT_REMOTE)
        .args(["--color", "never", "wireguard", "status"])
        .env("AGENT_REMOTE_HOME", temp.path())
        .env("AGENT_REMOTE_WG", &wg)
        .env("AGENT_REMOTE_SUDO", &sudo)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("interface: elevated-agent-remote"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("Permission denied"));
}
