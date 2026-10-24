use std::fs;
use std::path::Path;

#[test]
fn linux_broker_installation_material_is_fixed_and_fail_closed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let unit =
        fs::read_to_string(root.join("packaging/linux/agent-remote-wireguard-broker.service"))
            .unwrap();
    assert!(unit.contains("ExecStart=/usr/libexec/agent-remote-wireguard-broker"));
    assert!(unit.contains("User=root"));
    assert!(unit.contains("ProtectSystem=strict"));
    assert!(unit.contains("CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW"));

    let policy =
        fs::read_to_string(root.join("packaging/linux/dev.agentremote.wireguard.manage.policy"))
            .unwrap();
    assert!(policy.contains("id=\"dev.agentremote.wireguard.manage\""));
    assert!(policy.contains("<allow_active>auth_admin</allow_active>"));
    assert!(!policy.contains("<allow_any>yes</allow_any>"));

    let dbus =
        fs::read_to_string(root.join("packaging/linux/dev.agentremote.WireGuardBroker.service"))
            .unwrap();
    assert!(dbus.contains("Name=dev.agentremote.WireGuardBroker"));
    assert!(dbus.contains("User=root"));

    let install =
        fs::read_to_string(root.join("scripts/install-linux-wireguard-broker.sh")).unwrap();
    assert!(install.contains("must run as root"));
    assert!(install.contains("refusing to replace symlink"));
    assert!(install.contains("[ ! -L \"$binary\" ]"));
    assert!(install.contains("install -o root -g root -m 0755"));
    assert!(!install.contains("sudo"));
}

#[test]
fn linux_broker_checks_root_owned_runtime_dependencies_before_execution() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let source = fs::read_to_string(root.join("src/wireguard/linux_broker.rs")).unwrap();
    let execution = source
        .find("fn run_fixed_wg_quick(")
        .expect("fixed executor must remain present");
    let body = &source[execution..];
    assert!(body.contains("trusted_tool(\"wg-quick\")"));
    assert!(body.contains("trusted_tool(\"bash\")"));
    assert!(body.contains("trusted_tool(\"wg\")"));
    assert!(body.contains("trusted_tool(\"ip\")"));
    assert!(body.contains("metadata.uid() != 0"));
    assert!(body.contains("metadata.nlink() != 1"));
    assert!(body.contains("metadata.mode() & 0o022 != 0"));

    let status = source
        .find("async fn status(")
        .expect("status must bind to a caller");
    let status_body = &source[status..];
    assert!(status_body.contains("observe_peer(connection, &sender)"));
    assert!(status_body.contains("check_polkit(connection, &peer)"));
    assert!(status_body.contains("caller_not_authorized"));
}
