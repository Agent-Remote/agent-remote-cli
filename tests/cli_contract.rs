use std::path::Path;
use std::process::{Command, Output};

#[cfg(unix)]
use sha2::{Digest, Sha256};
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::io::{Read, Write};
#[cfg(unix)]
use std::net::TcpListener;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::path::PathBuf;
#[cfg(unix)]
use std::thread::JoinHandle;

const AGENT_REMOTE: &str = env!("CARGO_BIN_EXE_agent-remote");
const FCLAUDE: &str = env!("CARGO_BIN_EXE_fclaude");
const WIREGUARD: &str = env!("CARGO_BIN_EXE_agent-remote-wireguard");

#[cfg(unix)]
fn managed_node_version() -> String {
    let manifest: serde_json::Value =
        serde_json::from_str(include_str!("../release-dependencies.json")).unwrap();
    manifest["node"]["version"].as_str().unwrap().to_owned()
}

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

#[cfg(unix)]
fn write_private_file(path: &Path, contents: impl AsRef<[u8]>) {
    fs::write(path, contents).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
fn write_user_token(state_home: &Path, server_url: &str, token: &str) {
    let sanitized: String = format!("user-token:{server_url}")
        .chars()
        .map(|character| match character {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' | '.' => character,
            _ => '_',
        })
        .collect();
    let directory = state_home.join("secrets");
    fs::create_dir_all(&directory).unwrap();
    let credential = serde_json::json!({
        "version": 1,
        "token": {"access_token": token, "expires_in": 3600, "refresh_token": "test-refresh", "refresh_expires_in": 2592000},
        "refresh_at": 4102444800_u64,
        "expires_at": 4102444800_u64,
        "session_expires_at": 4102444800_u64
    });
    write_private_file(
        &directory.join(format!("{sanitized}.secret")),
        credential.to_string(),
    );
}

#[cfg(unix)]
fn write_test_credential(store: &Path, device_id: &str, server_url: &str, revision: u64) {
    fs::create_dir_all(store).unwrap();
    fs::set_permissions(store, fs::Permissions::from_mode(0o700)).unwrap();
    let expires_at = if revision == 0 { 0 } else { 4_102_444_800_u64 };
    write_private_file(
        &store.join("ego-browser-credential.json"),
        serde_json::json!({
            "version": 1,
            "device_id": device_id,
            "server_url": server_url,
            "token": "egbc_test-device-token",
            "credential_id": format!("credential-{device_id}"),
            "release_profile": "community-local-trust",
            "credential_profile": "community_file",
            "expires_at_unix": expires_at,
            "revision": revision,
            "device_generation": 1
        })
        .to_string(),
    );
}

#[cfg(unix)]
fn ego_device_data(device_id: &str, status: &str) -> serde_json::Value {
    serde_json::json!({
        "id": device_id,
        "generation": 1,
        "device_generation": 1,
        "status": status,
        "release_profile": "community-local-trust",
        "bridge_version": "0.1.11",
        "local_ego_browser_runtime_version": "1.2.3",
        "ego_lite_runtime_version": "1.2.3",
        "skill_version": "1.2.3"
    })
}

#[cfg(unix)]
fn spawn_http_responses(responses: Vec<serde_json::Value>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut bytes = [0_u8; 16 * 1024];
            let count = stream.read(&mut bytes).unwrap();
            let request = String::from_utf8_lossy(&bytes[..count]).to_string();
            requests.push(request.lines().next().unwrap_or_default().to_owned());
            let encoded = body.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                encoded.len(),
                encoded
            )
            .unwrap();
        }
        requests
    });
    (server_url, handle)
}

#[cfg(unix)]
fn spawn_http_exchange_responses(
    responses: Vec<serde_json::Value>,
) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for body in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut expected_length = None;
            loop {
                let mut chunk = [0_u8; 4096];
                let count = stream.read(&mut chunk).unwrap();
                if count == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..count]);
                if expected_length.is_none() {
                    if let Some(header_end) =
                        request.windows(4).position(|part| part == b"\r\n\r\n")
                    {
                        let headers = String::from_utf8_lossy(&request[..header_end + 4]);
                        let content_length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().ok())
                                    .flatten()
                            })
                            .unwrap_or(0);
                        expected_length = Some(header_end + 4 + content_length);
                    }
                }
                if expected_length.is_some_and(|length| request.len() >= length) {
                    break;
                }
            }
            requests.push(String::from_utf8_lossy(&request).to_string());
            let encoded = body.to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                encoded.len(),
                encoded
            )
            .unwrap();
        }
        requests
    });
    (server_url, handle)
}

#[cfg(unix)]
fn node_item(node_id: &str) -> serde_json::Value {
    serde_json::json!({
        "id": node_id,
        "name": "managed-node",
        "status": "offline",
        "ssh_host": "127.0.0.1",
        "ssh_port": 22,
        "ssh_user": "agent-remote",
        "version": "0.2.19",
        "ego_browser_enabled": false,
        "configured_enabled": false,
        "effective_enabled": false,
        "node_execution_allowed": false,
        "enrollment_admission": true,
        "execution_admission": false
    })
}

#[cfg(unix)]
struct NodeReleaseFixture {
    archive: PathBuf,
    bin_directory: PathBuf,
    cosign_calls: PathBuf,
    sha256: String,
}

#[cfg(unix)]
fn write_node_release_fixture(root: &Path) -> NodeReleaseFixture {
    let archive_name = format!(
        "agent-remote-node-{}-linux-amd64-glibc.tar.gz",
        managed_node_version()
    );
    let archive = root.join(&archive_name);
    let payload = b"contract-test authenticated Node release";
    fs::write(&archive, payload).unwrap();
    let digest = format!("{:x}", Sha256::digest(payload));
    fs::write(
        root.join(format!("{archive_name}.sha256")),
        format!("{digest}  {archive_name}\n"),
    )
    .unwrap();
    fs::write(
        root.join(format!("{archive_name}.sigstore.json")),
        "{\"mediaType\":\"application/vnd.dev.sigstore.bundle+json;version=0.3\"}\n",
    )
    .unwrap();

    let bin_directory = root.join("release-tools");
    fs::create_dir(&bin_directory).unwrap();
    let cosign = bin_directory.join("cosign");
    fs::write(
        &cosign,
        "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$@\" > \"$TEST_NODE_COSIGN_CALLS\"\n",
    )
    .unwrap();
    fs::set_permissions(&cosign, fs::Permissions::from_mode(0o700)).unwrap();

    NodeReleaseFixture {
        archive,
        bin_directory,
        cosign_calls: root.join("cosign-calls"),
        sha256: digest,
    }
}

#[cfg(unix)]
fn run_node_install(
    state_home: &Path,
    ssh: &Path,
    node_id: &str,
    calls: &Path,
    release: &NodeReleaseFixture,
) -> Output {
    let mut search_path = vec![release.bin_directory.clone()];
    if let Some(existing) = std::env::var_os("PATH") {
        search_path.extend(std::env::split_paths(&existing));
    }
    Command::new(AGENT_REMOTE)
        .args([
            "--color", "never", "node", "install", "--node", node_id, "--yes",
        ])
        .env("AGENT_REMOTE_HOME", state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_NODE_SSH", ssh)
        .env("AGENT_REMOTE_NODE_RELEASE_ARCHIVE", &release.archive)
        .env("TEST_NODE_SSH_CALLS", calls)
        .env("TEST_NODE_COSIGN_CALLS", &release.cosign_calls)
        .env("TEST_NODE_RELEASE_SHA256", &release.sha256)
        .env("PATH", std::env::join_paths(search_path).unwrap())
        .output()
        .unwrap()
}

#[cfg(unix)]
fn request_body(request: &str) -> serde_json::Value {
    let (_, body) = request.split_once("\r\n\r\n").unwrap();
    serde_json::from_str(body).unwrap()
}

#[cfg(unix)]
fn argument_after<'a>(arguments: &'a str, name: &str) -> &'a str {
    let mut values = arguments.split_whitespace();
    while let Some(value) = values.next() {
        if value == name {
            return values.next().unwrap().trim_matches('\'');
        }
    }
    panic!("missing argument {name} in {arguments}")
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_requires_exact_profile_trust_without_running_an_installer() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let device_home = temporary.path().join("ego-browser-device");
    fs::create_dir_all(&state_home).unwrap();
    fs::create_dir_all(&device_home).unwrap();
    fs::set_permissions(&device_home, fs::Permissions::from_mode(0o700)).unwrap();
    write_private_file(
        &device_home.join("ego-browser-local-admission.json"),
        serde_json::json!({
            "version": 1,
            "state": "open",
            "device_id": "device-before-profile-change",
            "device_generation": 1,
            "binding_id": "binding-before-profile-change",
            "binding_generation": 1,
            "updated_at_unix": 1
        })
        .to_string(),
    );
    let (server_url, server) = spawn_http_exchange_responses(vec![serde_json::json!({
        "data": {
            "enabled": false,
            "enrollment_enabled": true,
            "execution_admission": false,
            "protocol": "ego-browser-bridge-v1"
        }
    })]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_setup-trust-token");
    let bootstrap_probe = temporary.path().join("bootstrap-ran");

    let output = Command::new(AGENT_REMOTE)
        .args(["--json", "ego-browser", "setup"])
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &device_home)
        .env(
            "AGENT_REMOTE_EGO_BROWSER_BOOTSTRAP",
            temporary.path().join("missing-bootstrap"),
        )
        .env("TEST_BRIDGE_BOOTSTRAP_PROBE", &bootstrap_probe)
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error_code"], "trust_confirmation_required");
    assert_eq!(value["state"]["phase"], "profile_verified");
    assert_eq!(value["next_action"], "confirm_local_trust");
    assert!(!bootstrap_probe.exists());
    assert!(!state_home.join("ego-browser-trust.json").exists());
    let admission: serde_json::Value = serde_json::from_slice(
        &fs::read(device_home.join("ego-browser-local-admission.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(admission["state"], "closed");
    assert!(admission["binding_id"].is_null());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/ego-browser/policy HTTP/1.1"));
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_rejects_legacy_admission_before_creating_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let device_home = temporary.path().join("ego-browser-device");
    fs::create_dir_all(&state_home).unwrap();
    let (server_url, server) = spawn_http_exchange_responses(vec![serde_json::json!({
        "data": {
            "enabled": false,
            "protocol": "ego-browser-bridge-v1"
        }
    })]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_setup-legacy-policy-token");

    let output = Command::new(AGENT_REMOTE)
        .args(["--json", "ego-browser", "setup", "--yes"])
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &device_home)
        .env(
            "AGENT_REMOTE_EGO_BROWSER_BOOTSTRAP",
            temporary.path().join("missing-bootstrap"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error_code"], "server_capability_unavailable");
    assert_eq!(value["next_action"], "repair");
    assert!(!device_home.exists());
    assert!(!state_home.join("ego-browser-trust.json").exists());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/ego-browser/policy HTTP/1.1"));
}

#[cfg(unix)]
#[test]
fn destructive_identity_commands_fail_closed_without_non_tty_confirmation() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let device_home = temporary.path().join("ego-browser-device");
    fs::create_dir_all(&state_home).unwrap();

    let run_command = |args: &[&str]| {
        Command::new(AGENT_REMOTE)
            .args(args)
            .env("HOME", temporary.path())
            .env("AGENT_REMOTE_HOME", &state_home)
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &device_home)
            .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", "/usr/bin/false")
            .output()
            .unwrap()
    };

    write_test_credential(
        &device_home,
        "device-confirmation",
        "https://old.example",
        1,
    );
    let forget = run_command(&["--json", "ego-browser", "forget-this-mac"]);
    assert!(!forget.status.success());
    let value: serde_json::Value = serde_json::from_slice(&forget.stdout).unwrap();
    assert_eq!(value["error_code"], "confirmation_required");
    assert_eq!(value["next_action"], "confirm_forget");
    assert!(!state_home
        .join("ego-browser-pending-revocation.json")
        .exists());
    assert!(!device_home
        .join("ego-browser-local-admission.json")
        .exists());

    let (old_server, server) = spawn_http_exchange_responses(vec![serde_json::json!({
        "data": {"items": []}
    })]);
    write_test_credential(&device_home, "device-confirmation", &old_server, 1);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{old_server}\"\n"),
    );
    write_user_token(&state_home, &old_server, "art_rotate-confirmation-token");
    let rotate = run_command(&["--json", "ego-browser", "device-rotate"]);
    assert!(!rotate.status.success());
    let value: serde_json::Value = serde_json::from_slice(&rotate.stdout).unwrap();
    assert_eq!(value["error_code"], "confirmation_required");
    assert_eq!(value["next_action"], "confirm_device_rotate");
    assert!(!state_home
        .join("ego-browser-pending-revocation.json")
        .exists());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/ego-browser/bindings HTTP/1.1"));

    let new_server = "https://new.example";
    write_user_token(&state_home, new_server, "art_switch-confirmation-token");
    let switch = run_command(&[
        "--json",
        "ego-browser",
        "switch-server",
        "--server-url",
        new_server,
    ]);
    assert!(!switch.status.success());
    let value: serde_json::Value = serde_json::from_slice(&switch.stdout).unwrap();
    assert_eq!(value["error_code"], "confirmation_required");
    assert_eq!(value["next_action"], "confirm_switch_server");
    assert!(!state_home
        .join("ego-browser-pending-revocation.json")
        .exists());
    assert_eq!(
        fs::read_to_string(state_home.join("config.toml")).unwrap(),
        format!("server_url = \"{old_server}\"\n")
    );
}

#[cfg(unix)]
#[test]
fn offline_forget_persists_revocation_and_preserves_local_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let device_home = temporary.path().join("ego-browser-device");
    fs::create_dir_all(&state_home).unwrap();
    fs::create_dir_all(&device_home).unwrap();
    fs::set_permissions(&device_home, fs::Permissions::from_mode(0o700)).unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let server_url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let device_id = "849aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_offline-forget-token");
    write_test_credential(&device_home, device_id, &server_url, 4);
    write_private_file(
        &device_home.join("ego-browser-device-key.bin"),
        "offline-forget-private-key-material",
    );
    write_private_file(
        &device_home.join("ego-browser-policy.json"),
        r#"{"version":1,"policy_revision":7,"allowlist_revision":4,"allowlist_roots":[],"allowlist_roots_digest":null,"learning_bundle_root":null}"#,
    );
    write_private_file(
        &device_home.join("ego-browser-local-admission.json"),
        serde_json::json!({
            "version": 1,
            "state": "open",
            "device_id": device_id,
            "device_generation": 3,
            "binding_id": "949aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "binding_generation": 8,
            "updated_at_unix": 1
        })
        .to_string(),
    );

    let calls = temporary.path().join("device-calls");
    let purge_marker = temporary.path().join("purge-called");
    let device = temporary.path().join("ego-browser-device-client");
    let metadata = serde_json::json!({
        "device_id": device_id,
        "device_generation": 3,
        "server_url": server_url,
        "release_profile": "community-local-trust",
        "credential_profile": "community_file",
        "credential_revision": 4,
        "credential_expires_at_unix": 4_102_444_800_u64
    });
    fs::write(
        &device,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >>\"$TEST_DEVICE_CALLS\"\ncase \"${{1:-}}\" in\n  metadata) printf '%s\\n' '{}' ;;\n  purge-local) : >\"$TEST_PURGE_MARKER\" ;;\n  *) exit 64 ;;\nesac\n",
            metadata
        ),
    )
    .unwrap();
    fs::set_permissions(&device, fs::Permissions::from_mode(0o700)).unwrap();

    let credential_path = device_home.join("ego-browser-credential.json");
    let key_path = device_home.join("ego-browser-device-key.bin");
    let policy_path = device_home.join("ego-browser-policy.json");
    let credential_before = fs::read(&credential_path).unwrap();
    let key_before = fs::read(&key_path).unwrap();
    let policy_before = fs::read(&policy_path).unwrap();

    let output = Command::new(AGENT_REMOTE)
        .args(["--json", "ego-browser", "forget-this-mac", "--yes"])
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &device_home)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device)
        .env("TEST_DEVICE_CALLS", &calls)
        .env("TEST_PURGE_MARKER", &purge_marker)
        .output()
        .unwrap();

    assert!(!output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error_code"], "pending_revocation");
    assert_eq!(value["next_action"], "retry_revocation");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("art_offline-forget-token"));
    let pending_path = state_home.join("ego-browser-pending-revocation.json");
    let pending: serde_json::Value =
        serde_json::from_slice(&fs::read(&pending_path).unwrap()).unwrap();
    assert_eq!(pending["scope"], "device");
    assert_eq!(pending["device_id"], device_id);
    assert_eq!(pending["device_generation"], 3);
    assert_eq!(pending["reason"], "forget_device");
    assert_eq!(pending["retry_count"], 1);
    assert_eq!(pending["server_url"], server_url);
    assert!(pending["operation_id"]
        .as_str()
        .is_some_and(|value| value.starts_with("op_")));
    assert_eq!(
        fs::metadata(&pending_path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let admission: serde_json::Value = serde_json::from_slice(
        &fs::read(device_home.join("ego-browser-local-admission.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(admission["state"], "closed");
    assert!(!purge_marker.exists());
    assert_eq!(fs::read_to_string(calls).unwrap(), "metadata\n");
    assert_eq!(fs::read(credential_path).unwrap(), credential_before);
    assert_eq!(fs::read(key_path).unwrap(), key_before);
    assert_eq!(fs::read(policy_path).unwrap(), policy_before);
}

#[cfg(unix)]
#[test]
fn ego_browser_routine_repair_reuses_exact_trust_without_confirmation() {
    check_retained_device_registration("repair", "active", false);
}

#[cfg(unix)]
#[test]
fn ego_browser_reenrollment_passes_explicit_mode_and_token_through_stdin() {
    check_retained_device_registration("re-enroll", "active", false);
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_pauses_before_install_and_preserves_resume_generation() {
    check_retained_device_registration("setup", "active", false);
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_preserves_paused_bindings_without_pausing_again() {
    check_retained_device_registration("setup", "paused", false);
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_with_terminal_binding_offers_connect() {
    check_retained_device_registration("setup", "stopped", false);
}

#[cfg(unix)]
#[test]
fn ego_browser_setup_stops_before_install_when_pause_fails() {
    check_retained_device_registration("setup", "active", true);
}

#[cfg(unix)]
fn check_retained_device_registration(operation: &str, binding_status: &str, pause_fails: bool) {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let mut responses = if matches!(operation, "repair" | "setup") {
        vec![serde_json::json!({"data": {"items": [{
            "id": "binding-repair", "ego_browser_device_id": "device-repair",
            "tool_session_id": "session-repair", "node_id": "node-repair", "status": binding_status,
            "relay_binding_kind": "ego_browser", "authorization_mode": "ego_browser_script_full_trust",
            "release_profile": "community-local-trust", "bridge_protocol_version": "ego-browser-bridge-v1",
            "allowlist_revision": 1, "lease_health": "healthy", "generation": 3,
            "binding_generation": 3
        }]}})]
    } else {
        vec![]
    };
    if operation == "setup" {
        responses.insert(
            0,
            serde_json::json!({"data": {
                "enabled": true, "enrollment_enabled": true, "execution_admission": true,
                "protocol": "ego-browser-bridge-v1"
            }}),
        );
    }
    let (server_url, server) = spawn_http_exchange_responses(responses);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_repair-token");
    let device_home = temporary.path().join("device-home");
    fs::create_dir_all(&device_home).unwrap();
    fs::set_permissions(&device_home, fs::Permissions::from_mode(0o700)).unwrap();
    if matches!(operation, "repair" | "setup") {
        write_private_file(
            &device_home.join("ego-browser-active-binding.json"),
            serde_json::json!({
                "version": 1, "binding_id": "binding-repair", "generation": 3,
                "device_id": "device-repair", "task_space_label": "agent-remote:session-repair",
                "authorization_mode": "ego_browser_script_full_trust", "user_confirmation": true
            })
            .to_string(),
        );
    }
    let paused_handoff = temporary.path().join("paused-handoff.json");
    write_private_file(
        &paused_handoff,
        serde_json::json!({
            "version": 1, "binding_id": "binding-repair", "generation": 4,
            "device_id": "device-repair", "task_space_label": "agent-remote:session-repair",
            "authorization_mode": "ego_browser_script_full_trust", "user_confirmation": true
        })
        .to_string(),
    );
    write_private_file(
        &state_home.join("ego-browser-trust.json"),
        serde_json::json!({
            "version": 2,
            "profile_id": "community-local-trust",
            "profile_version": "0.1.12",
            "bridge_version": "0.1.12",
            "signer_certificate_sha256": "1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5"
        })
        .to_string(),
    );

    let install_root = temporary.path().join("bridge-install");
    let release = install_root.join("releases/0.1.12");
    fs::create_dir_all(release.join("installer")).unwrap();
    fs::create_dir_all(release.join("bin")).unwrap();
    fs::write(release.join("VERSION"), "0.1.12\n").unwrap();
    fs::write(
        release.join("SIGNING-EVIDENCE.json"),
        serde_json::json!({
            "schema_version": 1,
            "version": "0.1.12",
            "profile": "community-local-trust",
            "signer_certificate_sha256": "1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5"
        })
        .to_string(),
    )
    .unwrap();
    fs::write(
        install_root.join("TRUSTED_CERTIFICATE_SHA256"),
        "1b1527d1c0ac6b3a1e95ccd7d4e6462ece9f5a42d2f4d309d09170588a4197e5\n",
    )
    .unwrap();
    for path in [
        release.join("VERSION"),
        release.join("SIGNING-EVIDENCE.json"),
        install_root.join("TRUSTED_CERTIFICATE_SHA256"),
    ] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
    }
    std::os::unix::fs::symlink(&release, install_root.join("current")).unwrap();

    let installer_log = temporary.path().join("installer.log");
    let installer = release.join("installer/install-macos.sh");
    fs::write(
        &installer,
        "#!/bin/sh\nset -eu\n\
         if [ \"$TEST_EXPECT_PAUSE\" = 1 ]; then\n\
           cmp \"$EGO_BROWSER_DEVICE_HOME/ego-browser-active-binding.json\" \"$TEST_PAUSED_HANDOFF\"\n\
         fi\n\
         printf '%s\\n' \"$*\" > \"$TEST_BRIDGE_INSTALLER_LOG\"\n",
    )
    .unwrap();
    fs::set_permissions(&installer, fs::Permissions::from_mode(0o500)).unwrap();
    let device_log = temporary.path().join("device.log");
    let device_stdin = temporary.path().join("device.stdin");
    let device = release.join("bin/ego-browser-device");
    fs::write(
        &device,
        format!(
            "#!/bin/sh\nset -eu\nprintf '%s\\n' \"$*\" >> \"$TEST_BRIDGE_DEVICE_LOG\"\n\
             if [ \"$1\" = metadata ]; then\n\
               printf '%s\\n' '{}'\n\
             elif [ \"$1\" = ensure ]; then\n\
               cat > \"$TEST_BRIDGE_DEVICE_STDIN\"\n\
             elif [ \"$1\" = pause ]; then\n\
               test \"$2\" = binding-repair && test \"$4\" = 3\n\
               test \"$TEST_PAUSE_FAILS\" = 0 || exit 43\n\
               cp \"$TEST_PAUSED_HANDOFF\" \"$EGO_BROWSER_DEVICE_HOME/ego-browser-active-binding.json\"\n\
             else\n\
               exit 64\n\
             fi\n",
            serde_json::json!({
                "device_id": "device-repair",
                "device_generation": 7,
                "server_url": server_url,
                "release_profile": "community-local-trust",
                "credential_profile": "community_file",
                "credential_revision": 3,
                "credential_expires_at_unix": 4_102_444_800_u64
            })
        ),
    )
    .unwrap();
    fs::set_permissions(&device, fs::Permissions::from_mode(0o500)).unwrap();

    let mut command = Command::new(AGENT_REMOTE);
    command.args(["--json", "--color", "never", "ego-browser", operation]);
    if operation == "re-enroll" {
        command.arg("--yes");
    }
    let output = command
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("EGO_BROWSER_INSTALL_ROOT", &install_root)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", &device_home)
        .env("EGO_BROWSER_DEVICE_HOME", &device_home)
        .env("TEST_BRIDGE_INSTALLER_LOG", &installer_log)
        .env("TEST_BRIDGE_DEVICE_LOG", &device_log)
        .env("TEST_BRIDGE_DEVICE_STDIN", &device_stdin)
        .env("TEST_PAUSED_HANDOFF", &paused_handoff)
        .env("TEST_PAUSE_FAILS", if pause_fails { "1" } else { "0" })
        .env(
            "TEST_EXPECT_PAUSE",
            if binding_status == "active" { "1" } else { "0" },
        )
        .output()
        .unwrap();
    if pause_fails {
        assert!(!output.status.success());
        assert!(!installer_log.exists());
        assert!(!device_stdin.exists());
        let admission: serde_json::Value = serde_json::from_slice(
            &fs::read(device_home.join("ego-browser-local-admission.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(admission["state"], "closed");
        assert_eq!(server.join().unwrap().len(), 2);
        return;
    }
    assert!(
        output.status.success(),
        "{operation} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    if matches!(operation, "repair" | "setup") {
        assert_eq!(
            fs::read_to_string(installer_log).unwrap(),
            format!("--{operation}\n")
        );
    } else {
        assert!(!installer_log.exists());
    }
    let device_calls = fs::read_to_string(device_log).unwrap();
    assert!(device_calls.lines().any(|line| line == "metadata"));
    let expected = format!(
        "ensure --server {server_url} --token-stdin{}{}",
        if operation == "setup" {
            ""
        } else {
            " --force-refresh"
        },
        if operation == "re-enroll" {
            " --re-enroll"
        } else {
            ""
        }
    );
    assert!(device_calls.lines().any(|line| line == expected));
    assert!(!device_calls.contains("art_repair-token"));
    assert_eq!(
        fs::read_to_string(device_stdin).unwrap(),
        "art_repair-token"
    );
    let requests = server.join().unwrap();
    if matches!(operation, "repair" | "setup") {
        assert_eq!(
            device_calls
                .lines()
                .any(|line| line == "pause binding-repair --binding-generation 3"),
            binding_status == "active"
        );
        assert_eq!(requests.len(), if operation == "setup" { 2 } else { 1 });
        assert!(requests
            .last()
            .unwrap()
            .starts_with("GET /api/v1/ego-browser/bindings HTTP/1.1"));
        if operation == "setup" {
            let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            let next = if binding_status == "stopped" {
                "connect"
            } else {
                "resume"
            };
            assert_eq!(result["next_action"], next);
            assert_eq!(
                result["next_command"],
                format!("agent-remote ego-browser {next}")
            );
            if binding_status == "active" {
                assert_eq!(
                    fs::read(device_home.join("ego-browser-active-binding.json")).unwrap(),
                    fs::read(paused_handoff).unwrap()
                );
            }
        }
    } else {
        assert!(requests.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn ego_browser_register_reports_certificate_errors_before_loading_credentials() {
    for (certificate, expected) in [
        (None, "signer_certificate_required"),
        (Some(""), "signer_certificate_invalid"),
        (Some("not-a-certificate"), "signer_certificate_invalid"),
        (Some("abc"), "signer_certificate_invalid"),
    ] {
        for json in [false, true] {
            let temporary = tempfile::tempdir().unwrap();
            let mut command = Command::new(AGENT_REMOTE);
            command.args(["ego-browser", "register"]);
            if json {
                command.arg("--json");
            }
            if let Some(certificate) = certificate {
                command.args(["--signer-certificate-sha256", certificate]);
            }
            let output = command
                .env("HOME", temporary.path())
                .env("AGENT_REMOTE_HOME", temporary.path().join("state"))
                .env(
                    "AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME",
                    temporary.path().join("device"),
                )
                .env("EGO_BROWSER_DEVICE_HOME", temporary.path().join("device"))
                .env("AGENT_REMOTE_SECRET_BACKEND", "file")
                .env_remove("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256")
                .output()
                .unwrap();
            assert!(!output.status.success());
            if json {
                let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(result["error_code"], expected);
                assert_eq!(result["next_action"], "provide_signer_certificate");
                assert_eq!(
                    result["next_command"],
                    "agent-remote ego-browser register --signer-certificate-sha256 <HEX>"
                );
            } else {
                let error = String::from_utf8_lossy(&output.stderr);
                assert!(error.contains(expected), "{error}");
                assert!(error.contains("--signer-certificate-sha256"));
                assert!(!error.contains("not-a-certificate"));
            }
        }
    }
}

#[cfg(unix)]
fn run_switch_server(
    state_home: &Path,
    store: &Path,
    device_client: &Path,
    new_server: &str,
    calls: &Path,
    ensure_count: &Path,
) -> Output {
    Command::new(AGENT_REMOTE)
        .args([
            "--color",
            "never",
            "ego-browser",
            "switch-server",
            "--server-url",
            new_server,
            "--yes",
        ])
        .env("AGENT_REMOTE_HOME", state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME", store)
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", device_client)
        .env("TEST_DEVICE_CALLS", calls)
        .env("TEST_ENSURE_COUNT", ensure_count)
        .env("TEST_NEW_SERVER", new_server)
        .output()
        .unwrap()
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
        &["node"],
        &["node", "install"],
        &["ego-browser"],
        &["ego-browser", "register"],
        &["ego-browser", "status"],
        &["ego-browser", "list"],
        &["ego-browser", "requests"],
        &["ego-browser", "cancel-request"],
        &["ego-browser", "claim"],
        &["ego-browser", "pause"],
        &["ego-browser", "resume"],
        &["ego-browser", "stop"],
        &["ego-browser", "revoke"],
        &["ego-browser", "delete-device"],
        &["ego-browser", "delete-binding"],
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

#[cfg(unix)]
#[test]
fn ego_browser_register_passes_stored_token_over_stdin() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let secrets = state_home.join("secrets");
    fs::create_dir_all(&secrets).unwrap();
    fs::write(
        state_home.join("config.toml"),
        "server_url = \"https://example.test\"\n",
    )
    .unwrap();
    let token = "art_test-user-token";
    write_user_token(&state_home, "https://example.test", token);

    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        "#!/bin/sh\nif [ \"$1\" = \"--help\" ]; then printf '%s\\n' --token-stdin; exit 0; fi\nprintf '%s\\n' \"$*\" > \"$TEST_DEVICE_ARGS\"\ncat > \"$TEST_DEVICE_STDIN\"\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let args_log = temporary.path().join("device-args");
    let stdin_log = temporary.path().join("device-stdin");
    let certificate = "a".repeat(64);

    let output = Command::new(AGENT_REMOTE)
        .args([
            "--color",
            "never",
            "ego-browser",
            "register",
            "--server-url",
            "https://example.test",
            "--signer-certificate-sha256",
            certificate.as_str(),
        ])
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device_client)
        .env("TEST_DEVICE_ARGS", &args_log)
        .env("TEST_DEVICE_STDIN", &stdin_log)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "registration delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let child_args = fs::read_to_string(args_log).unwrap();
    assert!(child_args.contains("register"));
    assert!(child_args.contains("--token-stdin"));
    assert!(child_args.contains("--signer-certificate-sha256"));
    assert!(!child_args.contains(token));
    assert_eq!(fs::read_to_string(stdin_log).unwrap(), token);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
}

#[cfg(unix)]
#[test]
fn ego_browser_register_reuses_the_standard_device_token_store() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    use agent_remote_cli::config::AppPaths;
    use agent_remote_cli::local_state::LocalState;

    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(state_home.join("secrets")).unwrap();
    fs::write(
        state_home.join("config.toml"),
        "server_url = \"https://example.test\"\nactive_device_id = \"device-1\"\n",
    )
    .unwrap();
    let token = "art_test-device-token-with-more-than-enough-entropy";
    fs::write(
        state_home.join("secrets/device-token_https___example.test_device-1.secret"),
        token,
    )
    .unwrap();

    let paths = AppPaths::new(Some(state_home.clone())).unwrap();
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .set_kv(
            "device-token-refresh-at:https://example.test:device-1",
            "4102444800",
        )
        .unwrap();

    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TEST_DEVICE_ARGS\"\ncat > \"$TEST_DEVICE_STDIN\"\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let args_log = temporary.path().join("device-args");
    let stdin_log = temporary.path().join("device-stdin");
    let certificate = "b".repeat(64);

    let output = Command::new(AGENT_REMOTE)
        .args([
            "--color",
            "never",
            "ego-browser",
            "register",
            "--signer-certificate-sha256",
            certificate.as_str(),
        ])
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device_client)
        .env("TEST_DEVICE_ARGS", &args_log)
        .env("TEST_DEVICE_STDIN", &stdin_log)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "device-token registration delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let child_args = fs::read_to_string(args_log).unwrap();
    assert!(child_args.contains("--token-stdin"));
    assert!(child_args.contains("--server https://example.test"));
    assert!(!child_args.contains(token));
    assert_eq!(fs::read_to_string(stdin_log).unwrap(), token);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(token));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(token));
}

#[cfg(unix)]
#[test]
fn node_install_persists_exchange_id_and_keeps_join_code_on_ssh_stdin() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let join_code = "jcode_contract_success_0123456789";
    let node = node_item(node_id);
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node]}}),
        serde_json::json!({"data": {
            "node_id": node_id,
            "code": join_code,
            "expires_at": "2099-01-02T03:04:05Z",
            "ego_browser_enabled": null
        }}),
        serde_json::json!({"data": {"state": "consumed"}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-install-token");

    let ssh = temporary.path().join("ssh");
    fs::write(
        &ssh,
        r#"#!/bin/sh
set -eu
count=0
if [ -f "$TEST_NODE_SSH_CALLS.count" ]; then count=$(cat "$TEST_NODE_SSH_CALLS.count"); fi
count=$((count + 1))
printf '%s' "$count" > "$TEST_NODE_SSH_CALLS.count"
command=${6-}
printf '%s\n' "$1" "$2" "$3" "$4" "$5" > "$TEST_NODE_SSH_CALLS.argv-$count"
printf '%s' "$command" > "$TEST_NODE_SSH_CALLS.command-$count"
case "$command" in
  *'uname -s'*)
    kind=probe
    printf '%s\n' linux-amd64-glibc
    ;;
  *'path, version, target = sys.argv'*)
    kind=inspect
    printf '%s\n' "$kind" >> "$TEST_NODE_SSH_CALLS"
    exit 1
    ;;
  *'.incoming.$$'*) kind=transfer ;;
  *'--no-start'*) kind=install ;;
  *'--join-code-stdin'*) kind=enroll ;;
  *'rm -rf -- "$stage"'*) kind=cleanup ;;
  *) kind=unexpected ;;
esac
printf '%s\n' "$kind" >> "$TEST_NODE_SSH_CALLS"
cat > "$TEST_NODE_SSH_CALLS.stdin-$count"
[ "$kind" != unexpected ]
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let output = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(
        output.status.success(),
        "Node install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "probe\ninspect\ntransfer\ninstall\nenroll\ncleanup\n"
    );
    let arguments = fs::read_to_string(format!("{}.command-5", calls.display())).unwrap();
    let argv: Vec<_> = fs::read_to_string(format!("{}.argv-5", calls.display()))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        &argv[..5],
        ["-T", "-p", "22", "--", "agent-remote@127.0.0.1"]
    );
    assert_eq!(argv.len(), 5);
    assert!(arguments.contains("agent-remote-node"));
    let exchange_id = argument_after(&arguments, "--exchange-id");
    assert_eq!(exchange_id.len(), 32);
    assert!(exchange_id.bytes().all(|byte| byte.is_ascii_hexdigit()));
    assert!(arguments.contains(&format!("--node-id '{node_id}'")));
    assert!(arguments.contains("--join-code-stdin"));
    assert!(!arguments.contains(join_code));
    assert_eq!(
        fs::read_to_string(format!("{}.stdin-5", calls.display())).unwrap(),
        format!("{join_code}\n")
    );
    assert!(!state_home.join("node-install-exchange.json").exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(join_code));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(join_code));
    let cosign_arguments = fs::read_to_string(&release.cosign_calls).unwrap();
    assert!(cosign_arguments.contains("verify-blob"));
    assert!(cosign_arguments.contains(&format!(
        "https://github.com/Agent-Remote/agent-remote-node/.github/workflows/release.yml@refs/tags/v{}",
        managed_node_version()
    )));

    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 4);
    assert!(requests[0].starts_with("GET /api/v1/nodes HTTP/1.1"));
    assert!(requests[1].starts_with("GET /api/v1/nodes HTTP/1.1"));
    let issue = request_body(&requests[2]);
    let revoke = request_body(&requests[3]);
    assert_eq!(issue["exchange_id"], exchange_id);
    assert_eq!(issue["ego_browser_enabled"], serde_json::Value::Null);
    assert_eq!(revoke["exchange_id"], exchange_id);
    assert!(requests.iter().all(|request| !request.contains(join_code)));
}

#[cfg(unix)]
#[test]
fn node_install_never_issues_a_code_after_release_transfer_failure() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "449aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let node = node_item(node_id);
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node]}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-transfer-failure-token");

    let ssh = temporary.path().join("ssh");
    fs::write(
        &ssh,
        r#"#!/bin/sh
set -eu
command=${6-}
case "$command" in
  *'uname -s'*)
    printf '%s\n' probe >> "$TEST_NODE_SSH_CALLS"
    printf '%s\n' linux-amd64-glibc
    ;;
  *'path, version, target = sys.argv'*)
    printf '%s\n' inspect >> "$TEST_NODE_SSH_CALLS"
    exit 1
    ;;
  *'.incoming.$$'*)
    printf '%s\n' transfer-failed >> "$TEST_NODE_SSH_CALLS"
    cat >/dev/null
    exit 255
    ;;
  *)
    printf '%s\n' unexpected >> "$TEST_NODE_SSH_CALLS"
    exit 65
    ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let output = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("state=release_pending"));
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "probe\ninspect\ntransfer-failed\n"
    );
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(state_home.join("node-install-exchange.json")).unwrap())
            .unwrap();
    assert_eq!(state["stage"], "prepared");
    assert_eq!(state["release_sha256"], serde_json::Value::Null);
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| !request.contains("/join-code HTTP/1.1")));
}

#[cfg(unix)]
#[test]
fn node_install_rejects_a_tampered_release_before_transfer_or_code_issue() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    fs::write(&release.archive, b"tampered after checksum creation").unwrap();
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "549aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let node = node_item(node_id);
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node]}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-tamper-token");

    let ssh = temporary.path().join("ssh");
    fs::write(
        &ssh,
        r#"#!/bin/sh
set -eu
command=${6-}
case "$command" in
  *'uname -s'*) printf '%s\n' linux-amd64-glibc ;;
  *'path, version, target = sys.argv'*) exit 1 ;;
  *) touch "$TEST_NODE_SSH_CALLS"; exit 65 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let output = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("error_code=release_verification_failed")
    );
    assert!(!calls.exists());
    assert!(!release.cosign_calls.exists());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| !request.contains("/join-code HTTP/1.1")));
}

#[cfg(unix)]
#[test]
fn node_install_retry_reuses_transfer_but_never_skips_failed_installation() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "649aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let join_code = "jcode_contract_install_retry_012345";
    let node = node_item(node_id);
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node]}}),
        serde_json::json!({"data": {
            "node_id": node_id,
            "code": join_code,
            "expires_at": "2099-01-02T03:04:05Z",
            "ego_browser_enabled": null
        }}),
        serde_json::json!({"data": {"state": "consumed"}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-install-retry-token");

    let ssh = temporary.path().join("ssh");
    fs::write(
        &ssh,
        r#"#!/bin/sh
set -eu
command=${6-}
case "$command" in
  *'uname -s'*)
    kind=probe
    printf '%s\n' linux-amd64-glibc
    ;;
  *'path, version, target = sys.argv'*)
    if [ -f "$TEST_NODE_SSH_CALLS.staged" ]; then
      kind=inspect-staged
      printf '%s\n' "$TEST_NODE_RELEASE_SHA256"
    else
      printf '%s\n' inspect-missing >> "$TEST_NODE_SSH_CALLS"
      exit 1
    fi
    ;;
  *'.incoming.$$'*)
    kind=transfer
    cat >/dev/null
    : > "$TEST_NODE_SSH_CALLS.staged"
    ;;
  *'--no-start'*)
    if [ ! -f "$TEST_NODE_SSH_CALLS.install-failed" ]; then
      printf '%s\n' install-failed >> "$TEST_NODE_SSH_CALLS"
      : > "$TEST_NODE_SSH_CALLS.install-failed"
      exit 1
    fi
    kind=install-ok
    ;;
  *'--join-code-stdin'*)
    kind=enroll
    cat > "$TEST_NODE_SSH_CALLS.join-code-stdin"
    ;;
  *'rm -rf -- "$stage"'*) kind=cleanup ;;
  *) kind=unexpected ;;
esac
printf '%s\n' "$kind" >> "$TEST_NODE_SSH_CALLS"
[ "$kind" != unexpected ]
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let first = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(!first.status.success());
    assert!(String::from_utf8_lossy(&first.stderr).contains("state=release_pending"));
    let pending: serde_json::Value =
        serde_json::from_slice(&fs::read(state_home.join("node-install-exchange.json")).unwrap())
            .unwrap();
    assert_eq!(pending["stage"], "prepared");

    let second = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(
        second.status.success(),
        "Node retry failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert_eq!(
        fs::read_to_string(&calls).unwrap(),
        "probe\ninspect-missing\ntransfer\ninstall-failed\nprobe\ninspect-staged\ninstall-ok\nenroll\ncleanup\n"
    );
    assert_eq!(
        fs::read_to_string(format!("{}.join-code-stdin", calls.display())).unwrap(),
        format!("{join_code}\n")
    );
    assert!(!state_home.join("node-install-exchange.json").exists());
    let requests = server.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.contains("/join-code HTTP/1.1"))
            .count(),
        1
    );
}

#[cfg(unix)]
#[test]
fn node_install_rejects_ssh_option_injection_before_issuing_a_code() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "349aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let mut node = node_item(node_id);
    node["ssh_user"] = serde_json::json!("-oProxyCommand=bad");
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [node.clone()]}}),
        serde_json::json!({"data": {"items": [node]}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-injection-token");

    let ssh = temporary.path().join("ssh");
    fs::write(&ssh, "#!/bin/sh\ntouch \"$TEST_NODE_SSH_CALLS\"\n").unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let output = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("selected Node has an invalid managed SSH user"));
    assert!(!calls.exists());
    assert!(!state_home.join("node-install-exchange.json").exists());
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests
        .iter()
        .all(|request| !request.contains("/join-code HTTP/1.1")));
}

#[cfg(unix)]
#[test]
fn node_install_recovers_consumed_exchange_without_reissuing_or_reusing_code() {
    let temporary = tempfile::tempdir().unwrap();
    let release = write_node_release_fixture(temporary.path());
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let node_id = "249aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let join_code = "jcode_contract_response_lost_012345";
    let initial = node_item(node_id);
    let mut recovered = node_item(node_id);
    recovered["status"] = serde_json::json!("healthy");
    recovered["version"] = serde_json::json!(managed_node_version());
    recovered["effective_enabled"] = serde_json::json!(true);
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [initial.clone()]}}),
        serde_json::json!({"data": {"items": [initial]}}),
        serde_json::json!({"data": {
            "node_id": node_id,
            "code": join_code,
            "expires_at": "2099-01-02T03:04:05Z",
            "ego_browser_enabled": null
        }}),
        serde_json::json!({"data": {"state": "consumed"}}),
        serde_json::json!({"data": {"items": [recovered.clone()]}}),
        serde_json::json!({"data": {"items": [recovered]}}),
        serde_json::json!({"data": {"state": "consumed"}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_node-recovery-token");

    let ssh = temporary.path().join("ssh");
    fs::write(
        &ssh,
        r#"#!/bin/sh
set -eu
count=0
if [ -f "$TEST_NODE_SSH_CALLS.count" ]; then count=$(cat "$TEST_NODE_SSH_CALLS.count"); fi
count=$((count + 1))
printf '%s' "$count" > "$TEST_NODE_SSH_CALLS.count"
command=${6-}
printf '%s' "$command" > "$TEST_NODE_SSH_CALLS.command-$count"
case "$command" in
  *'uname -s'*)
    kind=probe
    printf '%s\n' linux-amd64-glibc
    ;;
  *'path, version, target = sys.argv'*)
    kind=inspect
    printf '%s\n' "$kind" >> "$TEST_NODE_SSH_CALLS"
    exit 1
    ;;
  *'.incoming.$$'*) kind=transfer ;;
  *'--no-start'*) kind=install ;;
  *'--join-code-stdin'*) kind=enroll-code ;;
  *'rm -rf -- "$stage"'*) kind=cleanup ;;
  *'agent-remote-node'*) kind=enroll-recover ;;
  *) kind=unexpected ;;
esac
printf '%s\n' "$kind" >> "$TEST_NODE_SSH_CALLS"
cat > "$TEST_NODE_SSH_CALLS.stdin-$count"
if [ "$kind" = enroll-code ] && [ ! -f "$TEST_NODE_SSH_CALLS.failed" ]; then
  : > "$TEST_NODE_SSH_CALLS.failed"
  exit 255
fi
[ "$kind" != unexpected ]
"#,
    )
    .unwrap();
    fs::set_permissions(&ssh, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("ssh-calls");

    let first = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(!first.status.success());
    assert!(String::from_utf8_lossy(&first.stderr).contains("state=exchange_pending"));
    assert!(!String::from_utf8_lossy(&first.stderr).contains(join_code));
    let state_path = state_home.join("node-install-exchange.json");
    let state_bytes = fs::read(&state_path).unwrap();
    let state: serde_json::Value = serde_json::from_slice(&state_bytes).unwrap();
    let exchange_id = state["exchange_id"].as_str().unwrap().to_owned();
    assert_eq!(state["stage"], "issued");
    assert!(!String::from_utf8_lossy(&state_bytes).contains(join_code));
    assert!(!String::from_utf8_lossy(&state_bytes).contains("art_node-recovery-token"));
    assert_eq!(
        fs::metadata(&state_path).unwrap().permissions().mode() & 0o777,
        0o600
    );

    let second = run_node_install(&state_home, &ssh, node_id, &calls, &release);
    assert!(
        second.status.success(),
        "Node recovery failed: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    assert!(!state_path.exists());
    let call_lines: Vec<_> = fs::read_to_string(&calls)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    assert_eq!(
        call_lines,
        [
            "probe",
            "inspect",
            "transfer",
            "install",
            "enroll-code",
            "probe",
            "enroll-recover",
            "cleanup",
        ]
    );
    let first_enrollment = fs::read_to_string(format!("{}.command-5", calls.display())).unwrap();
    let recovered_enrollment =
        fs::read_to_string(format!("{}.command-7", calls.display())).unwrap();
    assert_eq!(
        argument_after(&first_enrollment, "--exchange-id"),
        exchange_id
    );
    assert_eq!(
        argument_after(&recovered_enrollment, "--exchange-id"),
        exchange_id
    );
    assert!(first_enrollment.contains("--join-code-stdin"));
    assert!(!recovered_enrollment.contains("--join-code-stdin"));
    assert!(!fs::read_to_string(&calls).unwrap().contains(join_code));
    assert_eq!(
        fs::read_to_string(format!("{}.stdin-5", calls.display())).unwrap(),
        format!("{join_code}\n")
    );
    assert_eq!(
        fs::read_to_string(format!("{}.stdin-7", calls.display())).unwrap(),
        ""
    );

    let requests = server.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST /api/v1/nodes/")
                && request.contains("/join-code HTTP/1.1"))
            .count(),
        1
    );
    let issue = requests
        .iter()
        .find(|request| {
            request.starts_with("POST /api/v1/nodes/") && request.contains("/join-code HTTP/1.1")
        })
        .map(|request| request_body(request))
        .unwrap();
    assert_eq!(issue["exchange_id"], exchange_id);
    let revoke_ids: Vec<_> = requests
        .iter()
        .filter(|request| request.contains("/join-code/revoke HTTP/1.1"))
        .map(|request| {
            request_body(request)["exchange_id"]
                .as_str()
                .unwrap()
                .to_owned()
        })
        .collect();
    assert_eq!(revoke_ids, vec![exchange_id.clone(), exchange_id]);
}

#[cfg(unix)]
#[test]
fn switch_server_retries_only_the_incomplete_stage_and_preserves_operation_id() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let store = temporary.path().join("device-store");
    fs::create_dir_all(&state_home).unwrap();

    let old_device = "old-device";
    let (old_server, server) = spawn_http_responses(vec![
        serde_json::json!({"data": {"items": [ego_device_data(old_device, "active")]}}),
        serde_json::json!({"data": ego_device_data(old_device, "revoked")}),
    ]);
    let new_listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let new_server = format!("http://{}", new_listener.local_addr().unwrap());
    drop(new_listener);

    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{old_server}\"\n"),
    );
    write_user_token(&state_home, &old_server, "art_old-user-token");
    write_user_token(&state_home, &new_server, "art_new-user-token");
    write_test_credential(&store, old_device, &old_server, 1);

    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_DEVICE_CALLS"
case "$1" in
  metadata)
    exit 2
    ;;
  purge-local)
    rm -f "$EGO_BROWSER_DEVICE_HOME/ego-browser-credential.json" \
      "$EGO_BROWSER_DEVICE_HOME/ego-browser-device-key.bin" \
      "$EGO_BROWSER_DEVICE_HOME/ego-browser-device-metadata.json" \
      "$EGO_BROWSER_DEVICE_HOME/ego-browser-active-binding.json" \
      "$EGO_BROWSER_DEVICE_HOME/ego-browser-pending-registration.json"
    ;;
  ensure)
    cat >/dev/null
    count=0
    if [ -f "$TEST_ENSURE_COUNT" ]; then count=$(cat "$TEST_ENSURE_COUNT"); fi
    count=$((count + 1))
    printf '%s' "$count" > "$TEST_ENSURE_COUNT"
    revision=0
    expires=0
    if [ "$count" -ge 3 ]; then revision=1; expires=4102444800; fi
    umask 077
    printf '{"version":1,"device_id":"new-device","server_url":"%s","token":"egbc_new","credential_id":"credential-new","release_profile":"community-local-trust","credential_profile":"community_file","expires_at_unix":%s,"revision":%s,"device_generation":1}' \
      "$TEST_NEW_SERVER" "$expires" "$revision" \
      > "$EGO_BROWSER_DEVICE_HOME/ego-browser-credential.json"
    if [ "$count" -lt 3 ]; then
      printf '%s\n' 'error=server_unreachable' >&2
      exit 2
    fi
    ;;
  *)
    exit 64
    ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("device-calls");
    let ensure_count = temporary.path().join("ensure-count");

    let first = run_switch_server(
        &state_home,
        &store,
        &device_client,
        &new_server,
        &calls,
        &ensure_count,
    );
    assert!(!first.status.success());
    let pending_path = state_home.join("ego-browser-pending-revocation.json");
    let first_pending: serde_json::Value =
        serde_json::from_slice(&fs::read(&pending_path).unwrap()).unwrap();
    let operation_id = first_pending["operation_id"].as_str().unwrap().to_owned();
    assert_eq!(first_pending["old_origin_revoked"], true);
    assert_eq!(first_pending["local_purged"], true);
    assert_eq!(first_pending["config_switched"], true);
    assert_eq!(first_pending["new_identity_ensured"], false);

    let requests = server.join().unwrap();
    assert_eq!(
        requests,
        vec![
            "GET /api/v1/ego-browser/devices HTTP/1.1",
            "POST /api/v1/ego-browser/devices/old-device/revoke HTTP/1.1"
        ]
    );

    let second = run_switch_server(
        &state_home,
        &store,
        &device_client,
        &new_server,
        &calls,
        &ensure_count,
    );
    assert!(!second.status.success());
    let second_pending: serde_json::Value =
        serde_json::from_slice(&fs::read(&pending_path).unwrap()).unwrap();
    assert_eq!(second_pending["operation_id"], operation_id);
    assert_eq!(second_pending["retry_count"], 2);

    let third = run_switch_server(
        &state_home,
        &store,
        &device_client,
        &new_server,
        &calls,
        &ensure_count,
    );
    assert!(
        third.status.success(),
        "switch retry failed: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    assert!(!pending_path.exists());
    assert_eq!(fs::read_to_string(&ensure_count).unwrap(), "3");
    let calls = fs::read_to_string(&calls).unwrap();
    assert_eq!(
        calls
            .lines()
            .filter(|line| *line == "purge-local --confirmed-revoked")
            .count(),
        1
    );
    assert_eq!(
        calls
            .lines()
            .filter(|line| line.starts_with("ensure "))
            .count(),
        3
    );
    let admission: serde_json::Value =
        serde_json::from_slice(&fs::read(store.join("ego-browser-local-admission.json")).unwrap())
            .unwrap();
    assert_eq!(admission["state"], "ready");
    assert!(fs::read_to_string(state_home.join("config.toml"))
        .unwrap()
        .contains(&new_server));
}

#[cfg(unix)]
#[test]
fn switch_server_recovers_a_revoked_old_origin_without_reposting_revoke() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let store = temporary.path().join("device-store");
    fs::create_dir_all(&state_home).unwrap();
    let old_device = "old-device";
    let (old_server, server) = spawn_http_responses(vec![
        serde_json::json!({"data": {"items": [ego_device_data(old_device, "revoked")]}}),
    ]);
    let new_server = "http://127.0.0.1:9";
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{old_server}\"\n"),
    );
    write_user_token(&state_home, &old_server, "art_old-user-token");
    write_user_token(&state_home, new_server, "art_new-user-token");
    write_test_credential(&store, old_device, &old_server, 1);

    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        r#"#!/bin/sh
set -eu
printf '%s\n' "$*" >> "$TEST_DEVICE_CALLS"
case "$1" in
  metadata) exit 2 ;;
  purge-local) rm -f "$EGO_BROWSER_DEVICE_HOME/ego-browser-credential.json" ;;
  ensure)
    cat >/dev/null
    umask 077
    printf '{"version":1,"device_id":"new-device","server_url":"%s","token":"egbc_new","credential_id":"credential-new","release_profile":"community-local-trust","credential_profile":"community_file","expires_at_unix":4102444800,"revision":1,"device_generation":1}' \
      "$TEST_NEW_SERVER" > "$EGO_BROWSER_DEVICE_HOME/ego-browser-credential.json"
    ;;
  *) exit 64 ;;
esac
"#,
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("device-calls");
    let ensure_count = temporary.path().join("ensure-count");
    let output = run_switch_server(
        &state_home,
        &store,
        &device_client,
        new_server,
        &calls,
        &ensure_count,
    );
    assert!(
        output.status.success(),
        "switch recovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        server.join().unwrap(),
        vec!["GET /api/v1/ego-browser/devices HTTP/1.1"]
    );
}

#[cfg(unix)]
#[test]
fn switch_server_with_ensured_target_identity_only_finalizes() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    let store = temporary.path().join("device-store");
    fs::create_dir_all(&state_home).unwrap();
    let new_server = "http://127.0.0.1:9";
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{new_server}\"\n"),
    );
    write_test_credential(&store, "new-device", new_server, 1);
    write_private_file(
        &state_home.join("ego-browser-pending-revocation.json"),
        serde_json::json!({
            "version": 1,
            "scope": "device",
            "device_id": "old-device",
            "binding_id": null,
            "device_generation": 1,
            "reason": "switch_server",
            "operation_id": "op_finalize-only",
            "target_binding_generation": null,
            "retry_count": 3,
            "next_retry_at_unix": 1,
            "server_url": "http://127.0.0.1:8",
            "target_server_url": new_server,
            "old_origin_revoked": true,
            "local_purged": true,
            "config_switched": true,
            "new_identity_ensured": false,
            "created_at_unix": 1
        })
        .to_string(),
    );
    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TEST_DEVICE_CALLS\"\nexit 99\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let calls = temporary.path().join("device-calls");
    let ensure_count = temporary.path().join("ensure-count");

    let output = run_switch_server(
        &state_home,
        &store,
        &device_client,
        new_server,
        &calls,
        &ensure_count,
    );
    assert!(
        output.status.success(),
        "finalize recovery failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !calls.exists(),
        "Device Client was invoked during finalize-only recovery"
    );
    assert!(!state_home
        .join("ego-browser-pending-revocation.json")
        .exists());
    assert!(store.join("ego-browser-credential.json").exists());
}

#[cfg(target_os = "macos")]
#[test]
fn ego_browser_claim_discovers_the_standard_installed_device_client() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let device_client = temporary.path().join(
        "Library/Application Support/Agent Remote Ego Browser/current/bin/ego-browser-device",
    );
    fs::create_dir_all(device_client.parent().unwrap()).unwrap();
    fs::write(
        &device_client,
        "#!/bin/sh\nprintf '%s\\n' \"$*\" > \"$TEST_DEVICE_ARGS\"\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let args_log = temporary.path().join("device-args");
    let tool_session = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";

    let output = Command::new(AGENT_REMOTE)
        .args([
            "--color",
            "never",
            "ego-browser",
            "claim",
            tool_session,
            "--yes",
        ])
        .env("HOME", temporary.path())
        .env("PATH", "/usr/bin:/bin")
        .env_remove("AGENT_REMOTE_EGO_BROWSER_DEVICE")
        .env("TEST_DEVICE_ARGS", &args_log)
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "claim delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        fs::read_to_string(args_log).unwrap(),
        format!("claim {tool_session} --confirm\n")
    );
}

#[cfg(unix)]
#[test]
fn ego_browser_claim_hides_device_client_output_and_reports_a_safe_summary() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        "#!/bin/sh\nprintf 'raw success output with /private/path and token=secret\n'\nprintf 'raw warning\n' >&2\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();
    let session = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";

    let output = Command::new(AGENT_REMOTE)
        .args([
            "--json",
            "--color",
            "never",
            "ego-browser",
            "claim",
            session,
            "--yes",
        ])
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device_client)
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", temporary.path().join("agent-remote"))
        .env(
            "AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME",
            temporary.path().join("device-home"),
        )
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "claim delegation failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let value: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(value["error_code"], serde_json::Value::Null);
    assert_eq!(value["command"], "claim");
    assert_eq!(value["result"], "claim_submitted");
    assert_eq!(value["next_action"], "status");
    assert!(!stdout.contains("raw success output"));
    assert!(!stdout.contains("OK Ego-browser"));
    assert!(!stdout.contains("secret"));
    assert!(!stderr.contains("raw warning"));
}

#[cfg(unix)]
#[test]
fn ego_browser_list_json_is_single_structured_content_free_document() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let binding_id = "249aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let (server_url, server) = spawn_http_exchange_responses(vec![serde_json::json!({
        "data": {"items": [{
            "id": binding_id,
            "ego_browser_device_id": "349aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "tool_session_id": "449aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "node_id": "549aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "status": "paused",
            "relay_binding_kind": "opaque",
            "authorization_mode": "ego_browser_script_full_trust",
            "release_profile": "community-local-trust",
            "local_runtime_version": "0.4.7.4",
            "ego_lite_runtime_version": "0.4.7.4",
            "skill_version": "1.2.3",
            "bridge_protocol_version": "ego-browser-bridge-v1",
            "allowlist_revision": 4,
            "learning_bundle_digest": "a".repeat(64),
            "lease_until": null,
            "lease_health": "paused",
            "generation": 8,
            "binding_generation": 8,
            "connected_at": null,
            "stop_reason": null,
            "private_key": "private-key-material-do-not-leak"
        }]}
    })]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_list-json-token");

    let output = Command::new(AGENT_REMOTE)
        .args(["--json", "ego-browser", "list"])
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "JSON list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error_code"], serde_json::Value::Null);
    assert_eq!(value["command"], "list");
    assert_eq!(value["bindings"][0]["id"], binding_id);
    assert_eq!(value["bindings"][0]["binding_generation"], 8);
    let rendered = String::from_utf8_lossy(&output.stdout);
    assert!(!rendered.contains("art_list-json-token"));
    assert!(!rendered.contains("Cookie"));
    assert!(!rendered.contains("payload"));
    assert!(!rendered.contains("private-key-material-do-not-leak"));
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("GET /api/v1/ego-browser/bindings HTTP/1.1"));
}

#[cfg(unix)]
#[test]
fn ego_browser_requests_json_is_single_structured_content_free_document() {
    let temporary = tempfile::tempdir().unwrap();
    let state_home = temporary.path().join("agent-remote");
    fs::create_dir_all(&state_home).unwrap();
    let binding_id = "649aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let request_id = "749aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let (server_url, server) = spawn_http_exchange_responses(vec![
        serde_json::json!({"data": {"items": [{
            "id": binding_id,
            "ego_browser_device_id": "849aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "tool_session_id": "949aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "node_id": "a49aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "status": "active",
            "relay_binding_kind": "opaque",
            "authorization_mode": "ego_browser_script_full_trust",
            "release_profile": "community-local-trust",
            "local_runtime_version": "0.4.7.4",
            "ego_lite_runtime_version": "0.4.7.4",
            "skill_version": "1.2.3",
            "bridge_protocol_version": "ego-browser-bridge-v1",
            "allowlist_revision": 4,
            "learning_bundle_digest": "a".repeat(64),
            "lease_until": "2099-01-02T03:04:05Z",
            "lease_health": "healthy",
            "generation": 8,
            "binding_generation": 8,
            "connected_at": "2026-09-14T00:00:00Z",
            "stop_reason": null
        }]}}),
        serde_json::json!({"data": {"items": [{
            "id": request_id,
            "binding_id": binding_id,
            "generation": 8,
            "binding_generation": 8,
            "request_id": "opaque-request-001",
            "sequence": 3,
            "message_type": "execute",
            "payload_bytes": 512,
            "status": "accepted",
            "created_at": "2026-09-14T00:00:01Z",
            "private_key": "private-key-material-do-not-leak"
        }]}}),
    ]);
    write_private_file(
        &state_home.join("config.toml"),
        format!("server_url = \"{server_url}\"\n"),
    );
    write_user_token(&state_home, &server_url, "art_requests-json-token");

    let output = Command::new(AGENT_REMOTE)
        .args(["--json", "ego-browser", "requests", binding_id])
        .env("AGENT_REMOTE_HOME", &state_home)
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "JSON requests failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["error_code"], serde_json::Value::Null);
    assert_eq!(value["command"], "requests");
    assert_eq!(value["binding_id"], binding_id);
    assert_eq!(value["requests"][0]["id"], request_id);
    assert_eq!(value["requests"][0]["binding_generation"], 8);
    assert_eq!(value["requests"][0]["payload_bytes"], 512);
    let rendered = String::from_utf8_lossy(&output.stdout);
    for forbidden in [
        "art_requests-json-token",
        "Cookie",
        "script",
        "page",
        "ciphertext",
        "private-key-material-do-not-leak",
        &server_url,
    ] {
        assert!(!rendered.contains(forbidden));
    }
    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert!(requests[0].starts_with("GET /api/v1/ego-browser/bindings HTTP/1.1"));
    assert!(requests[1].starts_with(&format!(
        "GET /api/v1/ego-browser/bindings/{binding_id}/requests HTTP/1.1"
    )));
}

#[cfg(unix)]
#[test]
fn ego_browser_claim_reduces_device_client_failure_to_a_safe_error_code() {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let temporary = tempfile::tempdir().unwrap();
    let device_client = temporary.path().join("ego-browser-device");
    fs::write(
        &device_client,
        "#!/bin/sh\nprintf 'private path /tmp/secret\nerror=secret-token\nerror=policy_invalid\n' >&2\nexit 2\n",
    )
    .unwrap();
    fs::set_permissions(&device_client, fs::Permissions::from_mode(0o700)).unwrap();

    let output = Command::new(AGENT_REMOTE)
        .args([
            "--color",
            "never",
            "ego-browser",
            "claim",
            "149aef7a-ba99-4bd5-a0e9-baf1a2635c09",
            "--yes",
        ])
        .env("AGENT_REMOTE_EGO_BROWSER_DEVICE", &device_client)
        .env("HOME", temporary.path())
        .env("AGENT_REMOTE_HOME", temporary.path().join("agent-remote"))
        .env(
            "AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME",
            temporary.path().join("device-home"),
        )
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("policy_invalid"));
    assert!(!stderr.contains("/tmp/secret"));
    assert!(!stderr.contains("private path"));
    assert!(!stderr.contains("secret-token"));
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
