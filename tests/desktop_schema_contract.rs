use std::process::Command;

fn schema(binary: &str) -> serde_json::Value {
    let temp = tempfile::tempdir().unwrap();
    let state = temp.path().join("must-not-be-created");
    let output = Command::new(binary)
        .arg("--desktop-schema")
        .env("AGENT_REMOTE_HOME", &state)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!state.exists(), "schema discovery initialized client state");
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["schema_version"], 1);
    value
}

#[test]
fn discovery_includes_nested_commands_and_typed_flags_without_state_access() {
    let value = schema(env!("CARGO_BIN_EXE_agent-remote"));
    let commands = value["commands"].as_array().unwrap();
    for path in [
        vec!["skill", "state", "migrate"],
        vec!["ego-browser", "delete-binding"],
        vec!["account", "default", "set"],
        vec!["node", "install"],
        vec!["forward", "stop"],
    ] {
        assert!(
            commands
                .iter()
                .any(|c| c["path"] == serde_json::json!(path)),
            "missing {path:?}"
        );
    }
    let login = commands
        .iter()
        .find(|c| c["path"] == serde_json::json!(["login"]))
        .unwrap();
    assert!(login["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["long"] == "home" && a["global"] == true));
    assert!(!commands.iter().any(|c| c["path"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("help"))));
}

#[test]
fn launcher_discovery_includes_stop_recovery_and_passthrough() {
    let value = schema(env!("CARGO_BIN_EXE_fclaude"));
    let commands = value["commands"].as_array().unwrap();
    assert!(commands
        .iter()
        .any(|c| c["path"] == serde_json::json!(["stop-status"])));
    let new = commands
        .iter()
        .find(|c| c["path"] == serde_json::json!(["new"]))
        .unwrap();
    assert!(new["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == "claude_args" && a["action"] == "Append"));
    assert!(
        commands
            .iter()
            .all(|command| command.get("platforms").is_none()),
        "platform declarations from another executable must not leak into fclaude"
    );
}

#[test]
fn platform_declarations_use_exact_host_command_paths_without_parent_inheritance() {
    let value = schema(env!("CARGO_BIN_EXE_agent-remote"));
    let commands = value["commands"].as_array().unwrap();
    let find = |path: &[&str]| {
        commands
            .iter()
            .find(|command| command["path"] == serde_json::json!(path))
            .unwrap()
    };
    for action in ["install", "uninstall", "status", "launch", "diagnose"] {
        assert_eq!(
            find(&["device", action])["platforms"],
            serde_json::json!(["macos"])
        );
    }
    assert_eq!(
        find(&["ego-browser", "upgrade"])["platforms"],
        serde_json::json!(["macos"])
    );
    for action in ["config", "check", "status", "up", "down"] {
        assert_eq!(
            find(&["wireguard", action])["platforms"],
            serde_json::json!(["linux", "macos", "windows"])
        );
    }
    for path in [
        vec![],
        vec!["device"],
        vec!["ego-browser"],
        vec!["wireguard"],
        vec!["node"],
        vec!["device", "revoke"],
        vec!["device", "rotate-token"],
        vec!["node", "install"],
        vec!["ego-browser", "setup"],
        vec!["ego-browser", "repair"],
        vec!["ego-browser", "status"],
        vec!["ego-browser", "list"],
        vec!["ego-browser", "requests"],
        vec!["ego-browser", "cancel-request"],
        vec!["ego-browser", "delete-device"],
        vec!["ego-browser", "delete-binding"],
    ] {
        assert!(
            find(&path).get("platforms").is_none(),
            "unexpected platform claim for {path:?}"
        );
    }
    for platforms in commands
        .iter()
        .filter_map(|command| command.get("platforms"))
    {
        let platforms = platforms.as_array().unwrap();
        assert!(!platforms.is_empty());
        assert!(platforms
            .iter()
            .all(|platform| matches!(platform.as_str(), Some("linux" | "macos" | "windows"))));
    }
}
