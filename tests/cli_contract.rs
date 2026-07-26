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
        &["attach"],
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
    ] {
        assert_help(FCLAUDE, path);
    }

    for path in [&[][..], &["check"], &["up"], &["down"]] {
        assert_help(WIREGUARD, path);
    }
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
