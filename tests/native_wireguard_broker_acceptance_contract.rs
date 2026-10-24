use std::fs;
use std::path::Path;

fn read_script(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join(name);
    fs::read_to_string(path).expect("acceptance script must be present")
}

#[test]
fn shell_acceptance_is_host_only_and_fail_closed() {
    let script = read_script("native-wireguard-broker-acceptance.sh");
    for marker in [
        "GOOS/GOARCH are set",
        "cross_compilation",
        "status-only",
        "AGENT_REMOTE_CLI_BINARY",
        "AGENT_REMOTE_WIREGUARD_BROKER_BINARY",
        "requests.log",
        "restart",
        "wireguard.bridge.status",
        "up_receipt",
        "down_receipt",
    ] {
        assert!(
            script.contains(marker),
            "shell script missing marker: {marker}"
        );
    }
    assert!(
        !script.contains("sudo "),
        "acceptance must not hide elevation"
    );
    assert!(
        !script.contains("runas"),
        "acceptance must not use runas fallback"
    );
}

#[test]
fn powershell_acceptance_refuses_cross_build_and_reports_windows_handshake_gap() {
    let script = read_script("native-wireguard-broker-acceptance.ps1");
    for marker in [
        "GOOS/GOARCH selectors are not allowed",
        "cross_compilation = $false",
        "wireguard.bridge.status",
        "AgentRemoteWireGuardBroker",
        "status-only",
        "up_receipt",
        "down_receipt",
    ] {
        assert!(
            script.contains(marker),
            "PowerShell script missing marker: {marker}"
        );
    }
}

#[test]
fn macos_installer_is_root_only_and_uses_fixed_launchd_paths() {
    let script = read_script("install-macos-wireguard-broker.sh");
    for marker in [
        "must run on macOS",
        "must run as root",
        "/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker",
        "/Library/LaunchDaemons/dev.agentremote.wireguard.broker.plist",
        "refusing to replace symlink",
        "launchctl bootstrap system",
        "community self-signing",
    ] {
        assert!(
            script.contains(marker),
            "macOS installer missing marker: {marker}"
        );
    }
    assert!(
        !script.contains("sudo "),
        "installer must not hide privilege requirements"
    );
}

#[test]
fn windows_broker_rechecks_target_scope_before_mutation() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let service = fs::read_to_string(root.join("src/bin/agent-remote-wireguard-broker.rs"))
        .expect("Windows broker service source must be present");
    for marker in [
        "scope_digest_for_broker",
        "wireguard_windows_broker_scope_mismatch",
        "wireguard_windows_broker_target_precondition",
        "config_identity",
        "wireguard_windows_broker_config_mismatch",
        "WorkerAction::Up",
    ] {
        assert!(
            service.contains(marker),
            "Windows broker missing marker: {marker}"
        );
    }
    let handle = service
        .find("fn handle_request(")
        .expect("Windows broker request handler must remain explicit");
    let execution = &service[handle..];
    let fence = execution
        .find("scope_digest_for_broker")
        .expect("scope must be re-observed before execution");
    let command = execution
        .find("Command::new(&wireguard)")
        .expect("fixed WireGuard command must remain present");
    assert!(
        fence < command,
        "target fence must precede WireGuard invocation"
    );
}
