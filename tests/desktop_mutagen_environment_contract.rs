use serde_json::{json, Value};
use std::{
    io::Write,
    path::Path,
    process::{Command, Stdio},
};
fn command(home: &Path, data: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
    command
        .env("AGENT_REMOTE_HOME", home)
        .env("MUTAGEN_DATA_DIRECTORY", data)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file");
    command
}
fn invoke(home: &Path, data: &Path, method: &str, params: Value) -> (bool, Value) {
    let mut child = command(home, data)
        .arg("--desktop-control")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let request = json!({"protocol_version":1,"request_id":"environment-review","method":method,"params":params});
    child
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout.iter().filter(|b| **b == b'\n').count(), 1);
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}
#[test]
fn environment_discovery_has_no_authentication_or_state_initialization() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let data = temp.path().join("absent-mutagen");
    let (ok, response) = invoke(&home, &data, "capabilities", json!({}));
    assert!(ok);
    for (method, effect) in [
        ("mutagen.environment.preview", "read"),
        ("mutagen.environment.apply", "write"),
    ] {
        let operation = response["result"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["method"] == method)
            .unwrap();
        assert_eq!(operation["credential"], "none");
        assert_eq!(operation["effect"], effect);
        if effect == "write" {
            assert_eq!(operation["confirmation"], "exact_request");
        }
    }
    assert!(!home.exists());
    assert!(!data.exists());
}
#[test]
fn environment_confirmation_home_and_fingerprint_are_validated_before_state_or_tools() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let data = temp.path().join("absent-mutagen");
    let digest = format!("sha256:{}", "a".repeat(64));
    for (method, params, code) in [
        (
            "mutagen.environment.preview",
            json!({"expected_home":"relative"}),
            "invalid_params",
        ),
        (
            "mutagen.environment.preview",
            json!({"expected_home":temp.path()}),
            "configuration_changed",
        ),
        (
            "mutagen.environment.preview",
            json!({"expected_home":home,"server_url":"https://unused.example"}),
            "invalid_params",
        ),
        (
            "mutagen.environment.apply",
            json!({"confirmed":false,"expected_home":home,"expected_fingerprint":digest}),
            "confirmation_required",
        ),
        (
            "mutagen.environment.apply",
            json!({"confirmed":true,"expected_home":temp.path(),"expected_fingerprint":digest}),
            "configuration_changed",
        ),
        (
            "mutagen.environment.apply",
            json!({"confirmed":true,"expected_home":home,"expected_fingerprint":"sha256:short"}),
            "invalid_params",
        ),
        (
            "mutagen.environment.apply",
            json!({"confirmed":true,"expected_home":home}),
            "invalid_params",
        ),
    ] {
        let (ok, response) = invoke(&home, &data, method, params);
        assert!(!ok, "{response}");
        assert_eq!(response["error"]["code"], code);
        assert_eq!(response["error"]["retryable"], false);
        assert!(!home.exists());
        assert!(!data.exists());
    }
}
#[test]
fn human_environment_help_and_schema_expose_explicit_repair_without_yes() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let data = temp.path().join("absent-mutagen");
    let output = command(&home, &data)
        .args(["deps", "mutagen-environment", "--help"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("--repair"));
    assert!(!help.contains("--yes"));
    let output = command(&home, &data)
        .arg("--desktop-schema")
        .output()
        .unwrap();
    let schema: Value = serde_json::from_slice(&output.stdout).unwrap();
    let node = schema["commands"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["path"] == json!(["deps", "mutagen-environment"]))
        .unwrap();
    assert_eq!(node["platforms"], json!(["linux", "macos", "windows"]));
    assert!(node["arguments"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["long"] == "repair"));
    assert!(!home.exists());
    assert!(!data.exists());
}

fn tools_fixture(home: &Path) {
    std::fs::create_dir_all(home.join("bin")).unwrap();
    for name in ["mutagen", "ssh", "scp"] {
        let binary = agent_remote_cli::platform::managed_binary(&home.join("bin"), name);
        std::fs::write(
            &binary,
            b"test tool bytes; this preview must not execute me",
        )
        .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(binary, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
    }
}
#[test]
fn environment_preview_needs_no_configuration_credentials_database_or_project() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("absent-mutagen");
    tools_fixture(&home);
    let (ok, response) = invoke(
        &home,
        &data,
        "mutagen.environment.preview",
        json!({"expected_home":home}),
    );
    assert!(ok, "{response}");
    let plan = &response["result"];
    assert_eq!(plan["home"], home.to_str().unwrap());
    assert_eq!(plan["daemon_state"], "stopped");
    assert_eq!(plan["sessions"], json!([]));
    assert_eq!(plan["tools"].as_array().unwrap().len(), 3);
    assert!(plan["fingerprint"].as_str().unwrap().starts_with("sha256:"));
    for name in [
        "config.toml",
        "config-write.lock",
        "state.sqlite3",
        "secrets",
        "ssh",
        "dependencies",
        "wireguard",
    ] {
        assert!(!home.join(name).exists(), "preview created {name}");
    }
    assert!(!data.exists());
}
#[test]
fn environment_stale_or_tool_changed_confirmation_never_initializes_namespace_or_config_lock() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("absent-mutagen");
    tools_fixture(&home);
    let (_, response) = invoke(
        &home,
        &data,
        "mutagen.environment.preview",
        json!({"expected_home":home}),
    );
    let plan = &response["result"];
    let fingerprints = [
        json!(format!("sha256:{}", "0".repeat(64))),
        plan["fingerprint"].clone(),
    ];
    std::fs::write(
        agent_remote_cli::platform::managed_binary(&home.join("bin"), "ssh"),
        b"changed tool bytes",
    )
    .unwrap();
    for fingerprint in fingerprints {
        let (ok, response) = invoke(
            &home,
            &data,
            "mutagen.environment.apply",
            json!({"confirmed":true,"expected_home":home,"expected_fingerprint":fingerprint}),
        );
        assert!(!ok, "{response}");
        assert_eq!(
            response["error"]["code"],
            "sync_mutagen_environment_changed"
        );
        assert!(!data.exists());
        assert!(!home.join("config-write.lock").exists());
    }
}
#[test]
fn human_environment_json_has_its_own_versioned_schema_and_rejects_noninteractive_repair() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("absent-mutagen");
    tools_fixture(&home);
    let output = command(&home, &data)
        .args(["--json", "deps", "mutagen-environment"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let preview: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(preview["schema_version"], 1);
    assert_eq!(preview["kind"], "mutagen_environment_preview");
    let output = command(&home, &data)
        .args(["--json", "deps", "mutagen-environment", "--repair"])
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!output.status.success());
    let error: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(error["schema_version"], 1);
    assert_eq!(error["kind"], "mutagen_environment_error");
    assert!(matches!(
        error["error_code"].as_str(),
        Some("interactive_confirmation_required" | "sync_mutagen_environment_blocked")
    ));
    assert!(error.get("admission").is_none());
    assert!(!data.exists());
    assert!(!home.join("config-write.lock").exists());
}

#[cfg(unix)]
#[test]
fn environment_spawn_failure_retains_review_and_completed_stop_stage() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("new-mutagen");
    tools_fixture(&home);
    // Missing execute permission fails before spawning a daemon. Merely using
    // invalid image bytes can invoke the platform shell fallback instead.
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(
        home.join("bin/mutagen"),
        std::fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (_, response) = invoke(
        &home,
        &data,
        "mutagen.environment.preview",
        json!({"expected_home":home}),
    );
    let plan = &response["result"];
    let (ok, response) = invoke(
        &home,
        &data,
        "mutagen.environment.apply",
        json!({
            "confirmed":true, "expected_home":home, "expected_fingerprint":plan["fingerprint"]
        }),
    );
    assert!(ok, "{response}");
    let receipt = &response["result"];
    assert_eq!(&receipt["plan"], plan);
    assert_eq!(receipt["outcome"], "partial");
    assert_eq!(
        receipt["stages"],
        json!([
            {"name":"stop","state":"skipped"},
            {"name":"start","state":"failed"}
        ])
    );
    assert_eq!(receipt["environment"], Value::Null);
    assert_eq!(receipt["error_code"], "sync_mutagen_unavailable");
    assert!(!data.join("agent-remote-environment.json").exists());
    for path in [
        "config.toml",
        "state.sqlite3",
        "secrets",
        "ssh",
        "wireguard",
    ] {
        assert!(!home.join(path).exists());
    }
}

#[test]
fn environment_preview_rejects_malformed_recorded_binding_without_rewriting_it() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("data");
    tools_fixture(&home);
    std::fs::create_dir(&data).unwrap();
    let digest = format!("sha256:{}", "a".repeat(64));
    let valid = json!({"version":2,"binding":{"home":home,"ssh_directory":home.join("bin"),"fingerprint":digest},"namespace_fingerprint":digest,"running_fingerprint":digest});
    for (pointer, value) in [
        ("/binding/home", json!("/bad\nforged review")),
        ("/binding/ssh_directory", json!("relative")),
        ("/binding/fingerprint", json!("invalid")),
        ("/namespace_fingerprint", json!("invalid")),
        ("/running_fingerprint", json!("invalid")),
    ] {
        let mut marker = valid.clone();
        *marker.pointer_mut(pointer).unwrap() = value;
        let bytes = serde_json::to_vec(&marker).unwrap();
        let path = data.join("agent-remote-environment.json");
        std::fs::write(&path, &bytes).unwrap();
        let (ok, response) = invoke(
            &home,
            &data,
            "mutagen.environment.preview",
            json!({"expected_home":home}),
        );
        assert!(!ok, "{pointer}: {response}");
        assert_eq!(
            response["error"]["code"],
            "sync_mutagen_environment_invalid"
        );
        assert_eq!(std::fs::read(path).unwrap(), bytes);
        assert!(!data.join("daemon").exists());
        assert!(!home.join("config-write.lock").exists());
    }
}

#[cfg(unix)]
#[test]
fn environment_binding_preserves_non_unicode_environment_identity() {
    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("home");
    let data = temp.path().join("data");
    tools_fixture(&home);
    let mut fingerprints = Vec::new();
    for last_byte in [0xfe, 0xff] {
        let output = command(&home, &data)
            .env(
                "SSH_AUTH_SOCK",
                std::ffi::OsString::from_vec(vec![b'/', b'a', last_byte]),
            )
            .args(["--json", "deps", "mutagen-environment"])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        fingerprints.push(value["plan"]["desired"]["fingerprint"].clone());
    }
    assert_ne!(fingerprints[0], fingerprints[1]);
    assert!(!data.exists());
}
