use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::{Command, Stdio};

use serde_json::{json, Value};

#[path = "desktop_control/account_defaults.rs"]
mod account_defaults;

#[path = "desktop_control/device.rs"]
mod device;
#[path = "desktop_control/device_code.rs"]
mod device_code;
#[path = "desktop_control/device_local_plan.rs"]
mod device_local_plan;
#[path = "desktop_control/device_local_status.rs"]
mod device_local_status;
#[path = "desktop_control/ego_browser_delete.rs"]
mod ego_browser_delete;
#[path = "desktop_control/ego_browser_status.rs"]
mod ego_browser_status;
#[path = "desktop_control/login.rs"]
mod login;
#[path = "desktop_control/logout.rs"]
mod logout;
#[path = "desktop_control/port_forward.rs"]
mod port_forward;
#[path = "desktop_control/session_delete.rs"]
mod session_delete;
#[path = "desktop_control/session_stop.rs"]
mod session_stop;
#[path = "desktop_control/skills.rs"]
mod skills;

fn invoke(home: &Path, request: &[u8]) -> (bool, Value) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let write = child.stdin.take().unwrap().write_all(request);
    let output = child.wait_with_output().unwrap();
    assert!(write.is_ok() || request.len() > 64 * 1024);
    assert!(
        output.stderr.is_empty(),
        "machine operation wrote raw diagnostics"
    );
    assert_eq!(
        output.stdout.iter().filter(|&&byte| byte == b'\n').count(),
        1
    );
    (
        output.status.success(),
        serde_json::from_slice(&output.stdout).unwrap(),
    )
}

fn request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"protocol_version": 1, "request_id": "query-123", "method": method, "params": params})).unwrap()
}

fn streaming_request(method: &str, params: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "protocol_version": 1,
        "request_id": "query-123",
        "method": method,
        "stream_events": true,
        "params": params
    }))
    .unwrap()
}

fn invoke_stream(home: &Path, request: &[u8]) -> (bool, Vec<Value>) {
    let mut child = Command::new(env!("CARGO_BIN_EXE_agent-remote"))
        .arg("--desktop-control")
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(request).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.stderr.is_empty(),
        "machine operation wrote raw diagnostics"
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.ends_with('\n'));
    let events = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    (output.status.success(), events)
}

#[test]
fn opt_in_stream_emits_bounded_started_event_before_terminal_result() {
    let temp = tempfile::tempdir().unwrap();
    let (ok, events) = invoke_stream(
        &temp.path().join("absent"),
        &streaming_request("context", json!({})),
    );
    assert!(ok, "{events:?}");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["protocol_version"], 1);
    assert_eq!(events[0]["request_id"], "query-123");
    assert_eq!(events[0]["type"], "progress");
    assert_eq!(events[0]["phase"], "started");
    assert_eq!(events[0]["progress"]["operation"], "context");
    assert_eq!(events[0]["progress"]["stage"], "started");
    assert_eq!(events[1]["type"], "result");
    assert_eq!(events[1]["phase"], "completed");
    assert_eq!(events[1]["request_id"], "query-123");
}

#[test]
fn discovery_and_context_do_not_initialize_state_or_claim_authentication() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = invoke(&home, &request("capabilities", json!({})));
    assert!(ok);
    assert_eq!(value["request_id"], "query-123");
    assert_eq!(value["phase"], "completed");
    assert_eq!(value["result"]["attachment_transfer"]["supported"], true);
    assert_eq!(
        value["result"]["attachment_transfer"]["protocol_version"],
        1
    );
    assert_eq!(
        value["result"]["attachment_transfer"]["max_bytes"],
        268435456_i64
    );
    assert_eq!(value["result"]["attachment_transfer"]["max_entries"], 32);
    let operations = value["result"]["operations"].as_array().unwrap();
    assert_eq!(operations.len(), 95);
    for (method, effect, credential, confirmation) in [
        ("skills.retry.plan", "read", "user", ""),
        ("skills.retry.control", "write", "user", "exact_request"),
    ] {
        assert!(operations.iter().any(|operation| {
            operation["method"] == method
                && operation["effect"] == effect
                && operation["credential"] == credential
                && operation["confirmation"] == confirmation
        }));
    }
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "credentials.list"
            && operation["effect"] == "read"
            && operation["credential"] == "device"));
    for method in [
        "credentials.create",
        "credentials.bind",
        "credentials.unbind",
    ] {
        assert!(operations
            .iter()
            .any(|operation| operation["method"] == method
                && operation["effect"] == "write"
                && operation["credential"] == "device"
                && operation["confirmation"] == "exact_request"));
    }
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "port_forwards.list"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "port_forwards.create"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "port_forwards.stop"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "port_forwards.reconnect"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "wireguard.bridge.status"
            && operation["effect"] == "read"
            && operation["credential"] == "none"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.stop"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.stop.request"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.stop.status"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.delete"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.delete.request"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "sessions.delete.status"));
    assert!(operations.iter().any(
        |operation| operation["method"] == "ego_browser.binding.plan"
            && operation["effect"] == "read"
            && operation["credential"] == "user"
    ));
    assert!(operations.iter().any(|operation| operation["method"]
        == "ego_browser.binding.control"
        && operation["effect"] == "write"
        && operation["credential"] == "user"
        && operation["confirmation"] == "exact_request"));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "ego_browser.delete.plan"
            && operation["effect"] == "read"
            && operation["credential"] == "user"));
    assert!(operations.iter().any(
        |operation| operation["method"] == "ego_browser.delete.control"
            && operation["effect"] == "write"
            && operation["credential"] == "user"
            && operation["confirmation"] == "exact_request"
    ));
    assert!(operations
        .iter()
        .any(|operation| operation["method"] == "skills.info"
            && operation["effect"] == "read"
            && operation["credential"] == "user"));
    assert!(operations.iter().any(|operation| {
        operation["method"] == "skills.state.info"
            && operation["effect"] == "read"
            && operation["credential"] == "user"
            && operation.get("confirmation").is_none()
    }));
    assert!(operations.iter().any(|operation| {
        operation["method"] == "skills.state.diff"
            && operation["effect"] == "read"
            && operation["credential"] == "user"
            && operation.get("confirmation").is_none()
    }));
    let terminal_operations = value["result"]["terminal_operations"]
        .as_array()
        .expect("terminal operations");
    for method in [
        "accounts.binding.attach",
        "sessions.attach",
        "fclaude run",
        "fclaude new",
        "fclaude list",
        "agent-remote doctor",
        "agent-remote ssh check",
        "agent-remote node install",
        "agent-remote device install",
        "agent-remote device uninstall",
        "agent-remote device status",
        "agent-remote device launch",
        "agent-remote device diagnose",
        "agent-remote skill state prune",
        "agent-remote skill state reset",
        "agent-remote skill state migrate",
        "agent-remote skill state resolve",
        "agent-remote skill state restore",
        "agent-remote skill state list",
        "agent-remote skill state conflicts",
        "agent-remote skill state info",
        "agent-remote skill state diff",
        "agent-remote skill state export",
        "agent-remote skill add",
        "agent-remote skill update",
        "agent-remote skill enable",
        "agent-remote skill disable",
        "agent-remote skill pin",
        "agent-remote skill unpin",
        "agent-remote skill inherit",
        "agent-remote skill remove",
        "agent-remote skill rollback",
        "agent-remote skill check",
        "agent-remote skill info",
        "agent-remote skill status",
        "agent-remote skill list",
        "agent-remote skill retry",
        "agent-remote ego-browser setup",
        "agent-remote ego-browser connect",
        "agent-remote ego-browser repair",
        "agent-remote ego-browser upgrade",
        "agent-remote ego-browser remove",
        "agent-remote ego-browser forget-this-mac",
        "agent-remote ego-browser forget",
        "agent-remote ego-browser re-enroll",
        "agent-remote ego-browser device-rotate",
        "agent-remote ego-browser switch-server",
        "agent-remote ego-browser register",
        "agent-remote ego-browser status",
        "agent-remote ego-browser list",
        "agent-remote ego-browser requests",
        "agent-remote ego-browser cancel-request",
        "agent-remote ego-browser claim",
        "agent-remote ego-browser pause",
        "agent-remote ego-browser resume",
        "agent-remote ego-browser stop",
        "agent-remote ego-browser revoke",
        "agent-remote ego-browser delete-device",
        "agent-remote ego-browser device-delete",
        "agent-remote ego-browser delete-binding",
        "agent-remote ego-browser binding-delete",
    ] {
        assert!(
            terminal_operations.iter().any(
                |operation| operation["method"] == method && operation["protocol_version"] == 1
            ),
            "missing terminal operation {method}"
        );
    }
    for (method, workflow, effect) in [
        (
            "agent-remote skill state migrate",
            "skill_state_migrate",
            "write",
        ),
        (
            "agent-remote skill state resolve",
            "skill_state_resolve",
            "write",
        ),
        (
            "agent-remote skill state restore",
            "skill_state_restore",
            "write",
        ),
        (
            "agent-remote skill state conflicts",
            "skill_state_conflicts",
            "read",
        ),
    ] {
        let capability = terminal_operations
            .iter()
            .find(|operation| operation["method"] == method)
            .expect("skill state terminal capability");
        assert_eq!(capability["workflow"], workflow);
        assert_eq!(capability["effect"], effect);
        if effect == "write" {
            assert_eq!(capability["confirmation"], "exact_request");
        }
    }
    assert!(operations
        .iter()
        .all(|op| op["method"] != "accounts.binding.attach"));
    assert!(operations.iter().all(|o| o["effect"] == "read"
        || ((o["method"] == "login.password"
            || o["method"] == "login.device_code"
            || o["method"] == "setup.local"
            || o["method"] == "wireguard.config.apply"
            || o["method"] == "wireguard.tunnel.apply"
            || o["method"] == "accounts.default.set"
            || o["method"] == "accounts.default.clear"
            || o["method"] == "accounts.create"
            || o["method"] == "accounts.bind"
            || o["method"] == "accounts.verify"
            || o["method"] == "accounts.disable"
            || o["method"] == "credentials.create"
            || o["method"] == "credentials.bind"
            || o["method"] == "credentials.unbind"
            || o["method"] == "skills.change"
            || o["method"] == "skills.retry.control"
            || o["method"] == "accounts.import.apply"
            || o["method"] == "accounts.import.validate"
            || o["method"] == "accounts.runtime_recovery.apply"
            || o["method"] == "accounts.runtime_recovery.forget"
            || o["method"] == "accounts.import.forget"
            || o["method"] == "sync.ensure"
            || o["method"] == "sync.pause"
            || o["method"] == "sync.resume"
            || o["method"] == "sync.resolve"
            || o["method"] == "sync.reset"
            || o["method"] == "sync.recovery.apply"
            || o["method"] == "mutagen.environment.apply"
            || o["method"] == "sessions.create"
            || o["method"] == "sessions.stop"
            || o["method"] == "sessions.delete"
            || o["method"] == "port_forwards.create"
            || o["method"] == "port_forwards.stop"
            || o["method"] == "port_forwards.reconnect"
            || o["method"] == "device.revoke"
            || o["method"] == "device.rotate_token"
            || o["method"] == "ego_browser.request.cancel"
            || o["method"] == "ego_browser.binding.control"
            || o["method"] == "ego_browser.delete.control"
            || o["method"] == "ego_browser.claim.control"
            || o["method"] == "doctor.repair"
            || o["method"] == "deps.repair"
            || o["method"] == "logout")
            && o["effect"] == "write"
            && o["confirmation"] == "exact_request")));
    let (ok, value) = invoke(&home, &request("context", json!({})));
    assert!(ok);
    assert_eq!(value["result"]["home"], home.to_str().unwrap());
    assert!(value["result"]["server_url"].is_null());
    assert!(value["result"].get("authenticated").is_none());
    assert!(!home.exists());
}

#[test]
fn invalid_requests_and_unsupported_mutations_never_touch_state() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let cases = [
        (b"not JSON: sensitive-input".to_vec(), "invalid_request"),
        (vec![b'x'; 65 * 1024], "invalid_request"),
        (request("sessions.delete", json!({})), "invalid_params"),
        (
            request("accounts.binding.attach", json!({})),
            "unsupported_method",
        ),
        (
            request("accounts.list", json!({"password": "sensitive-input"})),
            "invalid_params",
        ),
        (
            request("sessions.list", json!({"statuses": ["\nsecret"]})),
            "invalid_params",
        ),
        (
            request(
                "ego_browser.binding.plan",
                json!({
                    "expected_context": {"home": home.clone(), "server_url": null, "active_device_id": null},
                    "binding_id": "binding-1", "binding_generation": 2, "generation": 2, "action": "delete"
                }),
            ),
            "invalid_params",
        ),
        (
            request(
                "ego_browser.binding.control",
                json!({
                    "confirmed": false,
                    "expected_context": {"home": home.clone(), "server_url": null, "active_device_id": null},
                    "binding_id": "binding-1", "binding_generation": 2, "generation": 2, "action": "pause"
                }),
            ),
            "invalid_params",
        ),
        (
            request(
                "ego_browser.delete.plan",
                json!({
                    "expected_context": {"home": home.clone(), "server_url": null, "active_device_id": null},
                    "target": "device", "id": "device-1", "generation": 2, "binding_generation": 1
                }),
            ),
            "invalid_params",
        ),
        (request("accounts.list", Value::Null), "invalid_params"),
        (
            br#"{"protocol_version":2,"request_id":"query-123","method":"context","params":{}}"#
                .to_vec(),
            "unsupported_version",
        ),
        (
            br#"{"protocol_version":1,"request_id":"secret\n","method":"context","params":{}}"#
                .to_vec(),
            "invalid_request",
        ),
        (
            [request("context", json!({})), request("context", json!({}))].concat(),
            "invalid_request",
        ),
    ];
    for (input, code) in cases {
        let (ok, response) = invoke(&home, &input);
        assert!(!ok);
        assert_eq!(response["error"]["code"], code);
        assert!(!response.to_string().contains("sensitive-input"));
        assert!(!home.exists());
    }
    let (_, response) = invoke(&home, &request("accounts.list", json!({})));
    assert_eq!(response["error"]["code"], "authentication_required");
    assert!(!home.exists());
}

#[test]
fn skill_retry_rejects_unknown_fields_and_unconfirmed_control() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let context =
        json!({"home": home, "server_url": "https://example.invalid", "active_device_id": null});
    let (ok, value) = invoke(
        &home,
        &request(
            "skills.retry.plan",
            json!({
                "expected_context": context,
                "operation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "unexpected": true
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");

    let (ok, value) = invoke(
        &home,
        &request(
            "skills.retry.control",
            json!({
                "confirmed": false,
                "expected_context": {"home": home, "server_url": "https://example.invalid", "active_device_id": null},
                "operation_id": "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
                "expected_generation": 7,
                "expected_plan_fingerprint": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
}

// Seed via the real credential and state APIs in a child so environment changes
// cannot affect parallel tests or the developer's system credential store.
#[test]
fn seed_device_credential() {
    let Ok(server) = std::env::var("DESKTOP_CONTROL_TEST_SERVER") else {
        return;
    };
    use agent_remote_cli::{
        config::{AppPaths, Config},
        local_state::LocalState,
        secrets::{device_token_key, SecretStore},
    };
    let paths = AppPaths::new(None).unwrap();
    Config {
        server_url: Some(server.clone()),
        active_device_id: Some("device-test".into()),
    }
    .save(&paths)
    .unwrap();
    SecretStore::new(paths.clone())
        .set_secret(
            &device_token_key(&server, "device-test"),
            "test-private-token",
        )
        .unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .set_kv(
            &format!("device-token-refresh-at:{server}:device-test"),
            "4102444800",
        )
        .unwrap();
}

fn fixture(home: &Path, status: u16, body: Value) -> std::thread::JoinHandle<String> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = format!("http://{}", listener.local_addr().unwrap());
    let seeded = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "seed_device_credential"])
        .env("DESKTOP_CONTROL_TEST_SERVER", server)
        .env("AGENT_REMOTE_HOME", home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(seeded.status.success());
    std::thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(error) => panic!("request did not arrive: {error}"),
            }
        };
        // Keep accept bounded without making request reads race the client's write.
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        while !bytes.windows(4).any(|w| w == b"\r\n\r\n") {
            let mut block = [0; 1024];
            let count = stream.read(&mut block).unwrap();
            assert!(count > 0 && bytes.len() < 8192);
            bytes.extend_from_slice(&block[..count]);
        }
        let body = body.to_string();
        write!(stream, "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    })
}

#[test]
fn lists_accounts_through_shared_device_credentials_and_projects_safe_fields() {
    let temp = tempfile::tempdir().unwrap();
    let server = fixture(
        temp.path(),
        200,
        json!({"data":{"items":[{
            "id":"account-1","user_id":"user-1","tool_type":"claude","display_name":"My account",
            "status":"ready","region_code":"JP","timezone":"Asia/Tokyo","locale":"ja",
            "preferred_node_tags":[],"runtime_backend":"native","created_at":"now","updated_at":"now",
            "secret_future_field":"must-not-leak"
        }]}}),
    );
    let (ok, response) = invoke(temp.path(), &request("accounts.list", json!({})));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["items"][0]["id"], "account-1");
    assert_eq!(
        response["result"]["context"]["active_device_id"],
        "device-test"
    );
    let config = agent_remote_cli::config::Config::load(
        &agent_remote_cli::config::AppPaths::new(Some(temp.path().to_owned())).unwrap(),
    )
    .unwrap();
    assert_eq!(
        response["result"]["context"]["server_url"],
        config.server_url.unwrap()
    );
    assert!(!response.to_string().contains("must-not-leak"));
    assert!(!response.to_string().contains("test-private-token"));
    let http = server.join().unwrap();
    assert!(http.starts_with("GET /api/v1/tool-accounts "));
    assert!(http.contains("Bearer test-private-token"));
}

#[test]
fn lists_developer_credentials_without_exposing_identity_or_secrets() {
    let temp = tempfile::tempdir().unwrap();
    let server = fixture(
        temp.path(),
        200,
        json!({"data":{"items":[{
            "id":"profile-1","user_id":"user-1","display_name":"Workstation",
            "status":"ready","git_identity":{"user_name":"Private Name","user_email":"private@example.invalid"},
            "github_cli_mode":"remote_login","ssh_mode":"agent_forwarding",
            "created_at":"now","updated_at":"later","secret_future_field":"must-not-leak"
        }]}}),
    );
    let (ok, response) = invoke(temp.path(), &request("credentials.list", json!({})));
    assert!(ok, "{response}");
    assert_eq!(response["result"]["items"][0]["id"], "profile-1");
    assert_eq!(
        response["result"]["items"][0]["github_cli_mode"],
        "remote_login"
    );
    assert!(response["result"]["items"][0].get("user_id").is_none());
    assert!(response["result"]["items"][0].get("git_identity").is_none());
    assert!(!response.to_string().contains("private@example.invalid"));
    assert!(!response.to_string().contains("must-not-leak"));
    let http = server.join().unwrap();
    assert!(http.starts_with("GET /api/v1/developer-credential-profiles "));
    assert!(http.contains("Bearer test-private-token"));
}

#[test]
fn credential_mutation_rejects_unknown_secret_fields_before_configuration_or_network() {
    let temp = tempfile::tempdir().unwrap();
    let params = json!({
        "confirmed": true,
        "expected_context": {
            "home": temp.path(),
            "server_url": "https://server.invalid",
            "active_device_id": "device-1"
        },
        "display_name": "Profile",
        "gh_mode": "remote_login",
        "ssh_mode": "agent_forwarding",
        "token": "must-not-enter"
    });
    let (ok, response) = invoke(temp.path(), &request("credentials.create", params));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!response.to_string().contains("must-not-enter"));
}

#[test]
fn credential_mutations_require_confirmation_and_exact_fields() {
    let temp = tempfile::tempdir().unwrap();
    let context = json!({
        "home": temp.path(),
        "server_url": "https://server.invalid",
        "active_device_id": "device-1"
    });
    for (method, mut params) in [
        (
            "credentials.bind",
            json!({"expected_context": context.clone(), "account_id": "account-1", "profile_id": "profile-1"}),
        ),
        (
            "credentials.unbind",
            json!({"confirmed": false, "expected_context": context, "account_id": "account-1"}),
        ),
    ] {
        let (ok, response) = invoke(temp.path(), &request(method, params.clone()));
        assert!(
            !ok,
            "{method} unexpectedly accepted unconfirmed/missing request"
        );
        assert_eq!(response["error"]["code"], "invalid_params");
        params["confirmed"] = json!(true);
        params["unexpected_secret"] = json!("private-token");
        let (ok, response) = invoke(temp.path(), &request(method, params));
        assert!(!ok);
        assert_eq!(response["error"]["code"], "invalid_params");
        assert!(!response.to_string().contains("private-token"));
    }
}

#[test]
fn session_filters_reach_api_and_permission_errors_are_content_free() {
    let temp = tempfile::tempdir().unwrap();
    let server = fixture(temp.path(), 200, json!({"data":{"items":[]}}));
    let (ok, response) = invoke(
        temp.path(),
        &request(
            "sessions.list",
            json!({"tool_type":"claude","statuses":["running","stopped"]}),
        ),
    );
    assert!(ok, "{response}");
    let http = server.join().unwrap();
    assert!(
        http.starts_with("GET /api/v1/sessions?tool_type=claude&status=running&status=stopped ")
    );
    let server = fixture(
        temp.path(),
        403,
        json!({"error":{"code":"FORBIDDEN","message":"sensitive-upstream-detail"}}),
    );
    let (ok, response) = invoke(temp.path(), &request("accounts.list", json!({})));
    assert!(!ok);
    assert_eq!(response["error"]["code"], "permission_denied");
    assert_eq!(response["error"]["http_status"], 403);
    assert_eq!(response["error"]["retryable"], false);
    assert!(!response.to_string().contains("sensitive-upstream-detail"));
    server.join().unwrap();
}
