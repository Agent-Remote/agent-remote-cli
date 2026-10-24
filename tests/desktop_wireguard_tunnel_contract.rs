use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
#[cfg(target_os = "linux")]
use std::sync::Mutex;

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

struct Fixture {
    temp: tempfile::TempDir,
    home: PathBuf,
    config: PathBuf,
    tool: PathBuf,
}
#[cfg(target_os = "linux")]
static BRIDGE_ENV_LOCK: Mutex<()> = Mutex::new(());
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("absent-home");
        // Invalid logical name makes target observation independent of host tunnels.
        let config = temp.path().join("!invalid.conf");
        let tool = temp
            .path()
            .join(if cfg!(windows) { "tool.exe" } else { "tool" });
        fs::write(&tool, b"#!/bin/sh\ntouch \"$UNEXPECTED_INVOCATION\"\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self {
            temp,
            home,
            config,
            tool,
        }
    }
    fn write(&self, text: &str) {
        fs::write(&self.config, text).unwrap();
        let file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.config)
            .unwrap();
        agent_remote_cli::platform::set_private_wireguard_file_permissions(&file).unwrap();
    }
    fn call(&self, params: Value) -> (bool, Value) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
            .arg("--desktop-control")
            .env("AGENT_REMOTE_HOME", &self.home)
            .env("AGENT_REMOTE_WG", &self.tool)
            .env("AGENT_REMOTE_WG_QUICK", &self.tool)
            .env("AGENT_REMOTE_WIREGUARD", &self.tool)
            .env("UNEXPECTED_INVOCATION", self.temp.path().join("invoked"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child.stdin.take().unwrap().write_all(json!({"protocol_version":1,"request_id":"tunnel-plan","method":"wireguard.tunnel.plan","params":params}).to_string().as_bytes()).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains(&STANDARD.encode([7; 32])));
        assert!(!text.contains("SECRET_HOOK"));
        assert!(!self.home.exists());
        assert!(!self.temp.path().join("invoked").exists());
        (
            output.status.success(),
            serde_json::from_str(&text).unwrap(),
        )
    }
    fn plan(&self) -> Value {
        let (ok, response) =
            self.call(json!({"expected_home":self.home,"action":"up","config":self.config}));
        assert!(ok, "{response}");
        response["result"].clone()
    }

    fn apply(&self, params: Value) -> (bool, Value) {
        let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
            .arg("--desktop-control")
            .env("AGENT_REMOTE_HOME", &self.home)
            .env("AGENT_REMOTE_WG", &self.tool)
            .env("AGENT_REMOTE_WG_QUICK", &self.tool)
            .env("AGENT_REMOTE_WIREGUARD", &self.tool)
            .env("UNEXPECTED_INVOCATION", self.temp.path().join("invoked"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(
                &json!({
                    "protocol_version": 1,
                    "request_id": "tunnel-apply",
                    "method": "wireguard.tunnel.apply",
                    "params": params
                })
                .to_string()
                .into_bytes(),
            )
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(output.stderr.is_empty());
        let text = String::from_utf8(output.stdout).unwrap();
        (
            output.status.success(),
            serde_json::from_str(&text).unwrap(),
        )
    }
}

#[cfg(target_os = "linux")]
#[test]
fn apply_invokes_the_reviewed_helper_but_never_fakes_observed_state() {
    let _guard = BRIDGE_ENV_LOCK.lock().unwrap();
    let fixture = Fixture::new();
    let config_path = fixture.temp.path().join("agent-remote.conf");
    fixture.write(&config());
    fs::rename(&fixture.config, &config_path).unwrap();
    let (ok, response) = fixture.call(json!({
        "expected_home": fixture.home,
        "action": "up",
        "config": config_path
    }));
    assert!(ok, "{response}");
    let plan = response["result"].clone();
    if !plan["issues"].as_array().unwrap().is_empty() {
        return;
    }
    std::env::set_var("AGENT_REMOTE_WIREGUARD_HELPER", &fixture.tool);
    let (ok, response) = fixture.apply(json!({
        "confirmed": true,
        "expected_home": fixture.home,
        "action": "up",
        "config": config_path,
        "expected_plan": plan
    }));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "wireguard_outcome_unknown");
    assert!(fixture.temp.path().join("invoked").exists());
    std::env::remove_var("AGENT_REMOTE_WIREGUARD_HELPER");
}
fn config() -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = 10.77.0.2/24\n",
        STANDARD.encode([7; 32])
    )
}
fn hash(text: &[u8]) -> String {
    format!("{:x}", Sha256::digest(text))
}

#[test]
fn plan_binds_exact_config_and_tool_bytes_without_exposing_secrets_or_authorizing_execution() {
    let fixture = Fixture::new();
    let original = config();
    fixture.write(&original);
    let first = fixture.plan();
    assert_eq!(first.as_object().unwrap().len(), 9);
    assert_eq!(first["version"], 1);
    assert_eq!(first["action"], "up");
    assert_eq!(first["config"]["state"], "ready");
    assert_eq!(first["config"].as_object().unwrap().len(), 7);
    assert_eq!(
        first["binding"]["content_sha256"],
        hash(original.as_bytes())
    );
    assert_eq!(
        first["binding"]["public_key"],
        agent_remote_cli::wireguard::public_key_from_private(&STANDARD.encode([7; 32])).unwrap()
    );
    let identity = first["binding"]["file_identity"].as_str().unwrap();
    assert_eq!(identity.len(), 64);
    assert!(identity
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    for tool in first["tools"].as_array().unwrap() {
        assert_eq!(tool.as_object().unwrap().len(), 5);
        assert_eq!(tool["state"], "available");
        assert_eq!(tool["identity"].as_str().unwrap().len(), 64);
        assert_eq!(tool["sha256"], hash(&fs::read(&fixture.tool).unwrap()));
    }
    assert_eq!(first["target"]["state"], "unknown");
    assert_eq!(first["target"]["reason"], "invalid_name");
    assert_eq!(
        first["issues"],
        json!(["target_unknown", "execution_bridge_required"])
    );
    let changed = format!("{original}# changed bytes\n");
    fixture.write(&changed);
    let second = fixture.plan();
    assert_ne!(
        first["binding"]["file_identity"],
        second["binding"]["file_identity"]
    );
    assert_eq!(
        second["binding"]["content_sha256"],
        hash(changed.as_bytes())
    );
    assert_eq!(
        first["binding"]["public_key"],
        second["binding"]["public_key"]
    );
    assert_eq!(fs::read_to_string(&fixture.config).unwrap(), changed);
}

#[test]
fn missing_invalid_and_unsupported_configurations_keep_explicit_null_bindings_and_fixed_issues() {
    let fixture = Fixture::new();
    let missing = fixture.plan();
    assert_eq!(missing["config"]["state"], "missing");
    assert!(missing["binding"].is_null());
    assert_eq!(
        missing["issues"],
        json!([
            "config_not_ready",
            "target_unknown",
            "execution_bridge_required"
        ])
    );
    fixture.write("PrivateKey = SECRET_HOOK");
    let invalid = fixture.plan();
    assert_eq!(invalid["config"]["state"], "invalid");
    assert!(invalid["binding"].is_null());
    fixture.write(&format!("{}PostUp = SECRET_HOOK\n", config()));
    let unsupported = fixture.plan();
    assert_eq!(unsupported["config"]["state"], "unsupported");
    assert!(unsupported["binding"].is_object());
    assert_eq!(
        unsupported["issues"],
        json!([
            "config_unsupported",
            "target_unknown",
            "execution_bridge_required"
        ])
    );
    fs::remove_file(&fixture.tool).unwrap();
    let no_tools = fixture.plan();
    for tool in no_tools["tools"].as_array().unwrap() {
        assert_eq!(tool["state"], "missing");
        assert!(tool["identity"].is_null() && tool["sha256"].is_null());
    }
    assert_eq!(
        no_tools["issues"],
        json!([
            "config_unsupported",
            "tool_unavailable",
            "target_unknown",
            "execution_bridge_required"
        ])
    );
}

#[test]
fn oversize_tool_remains_inventory_but_never_has_an_execution_snapshot() {
    let fixture = Fixture::new();
    fixture.write(&config());
    fs::OpenOptions::new()
        .write(true)
        .open(&fixture.tool)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();
    let result = fixture.plan();
    for tool in result["tools"].as_array().unwrap() {
        assert_eq!(tool["state"], "available");
        assert!(tool["identity"].is_null() && tool["sha256"].is_null());
    }
    assert_eq!(
        result["issues"],
        json!([
            "tool_snapshot_unavailable",
            "target_unknown",
            "execution_bridge_required"
        ])
    );
}

#[test]
fn request_requires_exact_home_known_action_and_present_nullable_absolute_config() {
    let fixture = Fixture::new();
    for params in [
        json!({"expected_home":fixture.home,"action":"up"}),
        json!({"expected_home":fixture.home,"action":"restart","config":null}),
        json!({"expected_home":fixture.home,"action":"up","config":"relative.conf"}),
        json!({"expected_home":fixture.home,"action":"up","config":format!("{}/child/./client.conf", fixture.temp.path().display())}),
        json!({"expected_home":fixture.home,"action":"up","config":format!("{}//client.conf", fixture.temp.path().display())}),
        json!({"expected_home":fixture.home,"action":"up","config":fixture.temp.path().join("child/../client.conf")}),
        json!({"expected_home":fixture.home,"action":"up","config":null,"confirmed":true}),
    ] {
        let (ok, value) = fixture.call(params);
        assert!(!ok);
        assert_eq!(value["error"]["code"], "invalid_params");
    }
    let (ok, value) =
        fixture.call(json!({"expected_home":fixture.temp.path(),"action":"up","config":null}));
    assert!(!ok);
    assert_eq!(value["error"]["code"], "configuration_changed");
}

#[test]
fn apply_requires_an_exact_read_only_plan_and_rejects_unready_targets() {
    let fixture = Fixture::new();
    fixture.write(&config());
    let plan = fixture.plan();
    let params = json!({
        "confirmed": true,
        "expected_home": fixture.home,
        "action": "up",
        "config": fixture.config,
        "expected_plan": plan
    });
    let (ok, response) = fixture.apply(params.clone());
    assert!(!ok);
    assert_eq!(response["error"]["code"], "wireguard_precondition_failed");
    assert!(response["result"].is_null());

    let (ok, response) = fixture.call(json!({
        "expected_home": fixture.home,
        "action": "up",
        "config": null
    }));
    assert!(ok, "{response}");
    let default_plan = response["result"].clone();
    let (ok, response) = fixture.apply(json!({
        "confirmed": true,
        "expected_home": fixture.home,
        "action": "up",
        "config": null,
        "expected_plan": default_plan
    }));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "wireguard_precondition_failed");

    let mut stale = params;
    stale["expected_plan"]["action"] = json!("down");
    let (ok, response) = fixture.apply(stale);
    assert!(!ok);
    assert_eq!(response["error"]["code"], "wireguard_plan_stale");

    let mut unconfirmed = json!({
        "confirmed": false,
        "expected_home": fixture.home,
        "action": "up",
        "config": fixture.config,
        "expected_plan": plan
    });
    let (ok, response) = fixture.apply(unconfirmed.take());
    assert!(!ok);
    assert_eq!(response["error"]["code"], "confirmation_required");

    let mut unknown = json!({
        "confirmed": true,
        "expected_home": fixture.home,
        "action": "up",
        "config": fixture.config,
        "expected_plan": plan,
        "elevate": true
    });
    let (ok, response) = fixture.apply(unknown.take());
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");

    let mut secret = json!({
        "confirmed": true,
        "expected_home": fixture.home,
        "action": "up",
        "config": fixture.config,
        "expected_plan": plan
    });
    secret["expected_plan"]["private_key"] = json!("must-not-be-read");
    let (ok, response) = fixture.apply(secret);
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
}
