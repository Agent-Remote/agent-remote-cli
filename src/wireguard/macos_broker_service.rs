//! Protected macOS WireGuard broker service.
//!
//! This is the privileged side of the fixed LaunchDaemon socket described by
//! [`super::macos_broker`].  It intentionally has no command-line or PATH
//! supplied execution mode: the daemon is installed at a fixed path, accepts
//! only the strict JSON envelope, authenticates the kernel peer, validates the
//! transferred configuration, re-observes the reviewed target, and invokes a
//! trusted `wg-quick` executable with a root-created temporary configuration.
//! Any uncertainty closes the connection without producing an execution
//! receipt.

#![allow(dead_code)]

use std::fs;
use std::io::{Read, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use sha2::{Digest, Sha256};
use tempfile::NamedTempFile;
use uuid::Uuid;

use super::broker::BrokerExecutionRequest;
use super::execution_config::ExecutionConfig;
use super::macos_broker::{
    self, ExecutionPermit, IpcRequest, IpcResponse, PeerIdentity, IPC_SOCKET_PATH,
};
use super::replay::ReplayJournal;
use super::target::{self, TargetObservation, TargetState};
use super::tunnel::Action;
use crate::config::AppPaths;

const IPC_PROTOCOL_VERSION: u32 = 1;
const MAX_IPC_FRAME: usize = 128 * 1024;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;
const PERMIT_TTL_SECONDS: u64 = 30;
// macOS's built-in administrator group has a stable gid in supported
// releases.  The socket is therefore reachable by administrators while
// remaining inaccessible to ordinary local users; peer credentials still
// authenticate the process after the ACL check.
const BROKER_SOCKET_GROUP_GID: libc::gid_t = 80;
const BROKER_ID_DOMAIN: &[u8] = b"agent-remote:wireguard:macos-broker-instance:v1\0";
const REPLAY_JOURNAL: &str = "/var/db/agent-remote-wireguard/requests.log";

/// Run the installed LaunchDaemon until it receives SIGTERM/SIGINT or the
/// listener fails.  The caller is expected to be PID 1 of the LaunchDaemon
/// process and must already run as root.
pub fn run() -> Result<()> {
    if unsafe { libc::geteuid() } != 0 {
        anyhow::bail!("wireguard_macos_broker_root_required");
    }
    let listener = bind_listener(Path::new(IPC_SOCKET_PATH))?;
    let broker_instance_sha256 = broker_instance_digest();
    let state = Arc::new(Mutex::new(ServiceState::new()?));
    loop {
        let (stream, _) = listener
            .accept()
            .context("wireguard broker accept failed")?;
        stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();
        let result = handle_connection(stream, &broker_instance_sha256, &state);
        if let Err(error) = result {
            // The protocol deliberately exposes only a fixed error class to a
            // client.  Detailed errors stay in the daemon's stderr/log sink.
            eprintln!("agent-remote-wireguard-broker: {error:#}");
        }
    }
}

struct ServiceState {
    /// A request digest is a one-shot operation key.  A replay receives a
    /// fixed denial even when the original command completed successfully.
    replay: ReplayJournal,
}

impl ServiceState {
    fn new() -> Result<Self> {
        Ok(Self {
            replay: ReplayJournal::open(REPLAY_JOURNAL)
                .map_err(|error| anyhow::anyhow!(error.0))?,
        })
    }
}

fn handle_connection(
    mut stream: UnixStream,
    broker_instance_sha256: &str,
    state: &Mutex<ServiceState>,
) -> Result<()> {
    let peer = macos_broker::peer_identity(&stream)?;
    let request: IpcRequest = read_frame(&mut stream)?;
    let response = match request.method.as_str() {
        "status" => status_response(&request, broker_instance_sha256),
        "execute" => execute_response(&request, &peer, broker_instance_sha256, state),
        _ => Err(anyhow::anyhow!("wireguard_macos_broker_method_invalid")),
    };
    let response = match response {
        Ok(response) => response,
        Err(error) => IpcResponse {
            version: IPC_PROTOCOL_VERSION,
            ok: false,
            error: Some(public_error(&error)),
            broker_instance_sha256: Some(broker_instance_sha256.to_string()),
            permit: None,
            operation_id: None,
            target_state: None,
        },
    };
    write_frame(&mut stream, &response)
}

fn status_response(request: &IpcRequest, broker_instance_sha256: &str) -> Result<IpcResponse> {
    if request.version != IPC_PROTOCOL_VERSION
        || request.request_id.is_some()
        || request.plan_sha256.is_some()
        || request.caller_sha256.is_some()
        || request.request_sha256.is_some()
        || request.target_scope_sha256.is_some()
        || request.action.is_some()
        || request.logical_name.is_some()
        || request.config_file_identity.is_some()
        || request.config_content_sha256.is_some()
        || request.config_public_key.is_some()
        || request.config_b64.is_some()
    {
        anyhow::bail!("wireguard_macos_broker_status_invalid");
    }
    Ok(IpcResponse {
        version: IPC_PROTOCOL_VERSION,
        ok: true,
        error: None,
        broker_instance_sha256: Some(broker_instance_sha256.to_string()),
        permit: None,
        operation_id: None,
        target_state: None,
    })
}

fn execute_response(
    request: &IpcRequest,
    peer: &PeerIdentity,
    broker_instance_sha256: &str,
    state: &Mutex<ServiceState>,
) -> Result<IpcResponse> {
    validate_envelope(request, peer)?;
    let request_id = required_digest(request.request_id.as_deref())?;
    let plan_sha256 = required_digest(request.plan_sha256.as_deref())?;
    let target_scope_sha256 = required_digest(request.target_scope_sha256.as_deref())?;
    let action = request
        .action
        .ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_action_missing"))?;
    let logical_name = request
        .logical_name
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_target_missing"))?;
    if !target::valid_name(logical_name) {
        anyhow::bail!("wireguard_macos_broker_target_invalid");
    }
    let config_file_identity = required_digest(request.config_file_identity.as_deref())?;
    let config_content_sha256 = required_digest(request.config_content_sha256.as_deref())?;
    let config_public_key = request
        .config_public_key
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_config_invalid"))?;
    let encoded = request
        .config_b64
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_config_missing"))?;
    let config_bytes = BASE64
        .decode(encoded)
        .map_err(|_| anyhow::anyhow!("wireguard_macos_broker_config_invalid"))?;
    if config_bytes.is_empty() || config_bytes.len() > 1024 * 1024 {
        anyhow::bail!("wireguard_macos_broker_config_invalid");
    }
    if hex(&Sha256::digest(&config_bytes)) != config_content_sha256 {
        anyhow::bail!("wireguard_macos_broker_config_changed");
    }
    let binding = super::inspection::ConfigBinding {
        file_identity: config_file_identity,
        content_sha256: config_content_sha256,
        public_key: config_public_key.to_string(),
    };
    // Reparse transferred bytes before any command or temporary file is
    // created. This validates all directives and the public key binding while
    // retaining the bytes in a zeroizing owner.
    let config = ExecutionConfig::from_transfer(config_bytes, &binding)
        .map_err(|error| anyhow::anyhow!(error.0))?;
    let request_digest = macos_broker::execution_request_digest(&BrokerExecutionRequest {
        request_id: request_id.clone(),
        plan_sha256,
        target_scope_sha256: target_scope_sha256.clone(),
        action,
        logical_name: logical_name.to_string(),
        config: binding.clone(),
        config_bytes: config.as_bytes().to_vec(),
    });
    if request
        .request_sha256
        .as_deref()
        .is_none_or(|value| value != request_digest)
    {
        anyhow::bail!("wireguard_macos_broker_request_binding_invalid");
    }
    let expected_caller = peer.caller_sha256();
    if request.caller_sha256.as_deref() != Some(expected_caller.as_str()) {
        anyhow::bail!("wireguard_macos_broker_caller_mismatch");
    }
    let now = unix_time_seconds()?;
    {
        let mut state = state
            .lock()
            .map_err(|_| anyhow::anyhow!("wireguard_macos_broker_state_unavailable"))?;
        // Reserve the request before the command is launched.  This is the
        // durable one-shot boundary; restart cannot make an uncertain request
        // executable again.
        state
            .replay
            .reserve(&request_digest)
            .map_err(|error| anyhow::anyhow!(error.0))?;
    }
    let expected_scope =
        target::scope_digest_for_broker(logical_name).map_err(|error| anyhow::anyhow!(error.0))?;
    if expected_scope != target_scope_sha256 {
        anyhow::bail!("wireguard_macos_broker_target_changed");
    }
    let expected_target = observe_target(logical_name)?;
    match (action, &expected_target.state) {
        (Action::Up, TargetState::Absent) | (Action::Down, TargetState::Present) => {}
        _ => anyhow::bail!("wireguard_macos_broker_target_precondition"),
    }
    let permit_id = digest(
        format!(
            "{broker_instance_sha256}:{request_digest}:{now}:{}",
            Uuid::new_v4()
        )
        .as_bytes(),
    );
    let permit = ExecutionPermit {
        version: IPC_PROTOCOL_VERSION,
        permit_id: permit_id.clone(),
        caller_sha256: expected_caller,
        request_sha256: request_digest,
        broker_instance_sha256: broker_instance_sha256.to_string(),
        issued_at_unix: now,
        expires_at_unix: now.saturating_add(PERMIT_TTL_SECONDS),
    };
    execute_tool(action, config.as_bytes())?;
    let observed = observe_target(logical_name)?;
    let expected_state = match action {
        Action::Up => TargetState::Present,
        Action::Down => TargetState::Absent,
    };
    if observed.state != expected_state {
        anyhow::bail!("wireguard_macos_broker_target_observation_failed");
    }
    Ok(IpcResponse {
        version: IPC_PROTOCOL_VERSION,
        ok: true,
        error: None,
        broker_instance_sha256: Some(broker_instance_sha256.to_string()),
        permit: Some(permit),
        operation_id: Some(digest(permit_id.as_bytes())),
        target_state: Some(observed.state),
    })
}

fn validate_envelope(request: &IpcRequest, peer: &PeerIdentity) -> Result<()> {
    if request.version != IPC_PROTOCOL_VERSION || request.method != "execute" {
        anyhow::bail!("wireguard_macos_broker_protocol_invalid");
    }
    // The peer identity is deliberately read before this function.  This
    // check keeps a future caller-auth implementation from accepting a root
    // or malformed identity copied into JSON.
    if peer.pid == 0 || peer.start_time_ns == 0 {
        anyhow::bail!("wireguard_macos_broker_peer_invalid");
    }
    Ok(())
}

fn observe_target(logical_name: &str) -> Result<TargetObservation> {
    let paths = AppPaths::new(Some(PathBuf::from("/var/empty")))?;
    let cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime
        .block_on(target::observe(&paths, logical_name, cancel))
        .map_err(|error| anyhow::anyhow!(error.0))
}

fn execute_tool(action: Action, config_bytes: &[u8]) -> Result<()> {
    let tool = trusted_wg_quick()?;
    let mut temporary = secure_temp_config(config_bytes)?;
    let action = match action {
        Action::Up => "up",
        Action::Down => "down",
    };
    let mut command = Command::new(tool);
    command
        .arg(action)
        .arg(temporary.path())
        .env_clear()
        .env(
            "PATH",
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
        )
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .context("wireguard_macos_broker_spawn_failed")?;
    let deadline = Instant::now() + COMMAND_TIMEOUT;
    loop {
        if let Some(status) = child.try_wait()? {
            let output = child.wait_with_output()?;
            if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT
            {
                anyhow::bail!("wireguard_macos_broker_output_too_large");
            }
            if !status.success() {
                anyhow::bail!("wireguard_macos_broker_execution_failed");
            }
            break;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            anyhow::bail!("wireguard_macos_broker_execution_timeout");
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    // Explicitly remove the temporary file before returning.  NamedTempFile's
    // Drop is the final guard if command execution returns an error.
    temporary.as_file_mut().set_len(0).ok();
    Ok(())
}

fn secure_temp_config(bytes: &[u8]) -> Result<NamedTempFile> {
    let directories = [
        Path::new("/var/run"),
        Path::new("/private/var/run"),
        Path::new("/tmp"),
    ];
    for directory in directories {
        let Ok(metadata) = fs::symlink_metadata(directory) else {
            continue;
        };
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            continue;
        }
        let Ok(mut file) = tempfile::Builder::new()
            .prefix(".agent-remote-wireguard-")
            .tempfile_in(directory)
        else {
            continue;
        };
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(bytes)?;
        file.as_file().sync_all()?;
        return Ok(file);
    }
    anyhow::bail!("wireguard_macos_broker_tempfile_unavailable")
}

fn trusted_wg_quick() -> Result<PathBuf> {
    for candidate in [
        "/opt/homebrew/bin/wg-quick",
        "/usr/local/bin/wg-quick",
        "/usr/bin/wg-quick",
        "/Applications/WireGuard.app/Contents/Resources/wg-quick",
    ] {
        let path = Path::new(candidate);
        let Ok(canonical) = fs::canonicalize(path) else {
            continue;
        };
        let Ok(metadata) = fs::symlink_metadata(&canonical) else {
            continue;
        };
        if metadata.file_type().is_symlink()
            || !metadata.is_file()
            || metadata.uid() != 0
            || metadata.nlink() != 1
            || metadata.mode() & 0o022 != 0
            || metadata.mode() & 0o111 == 0
        {
            continue;
        }
        return Ok(canonical);
    }
    anyhow::bail!("wireguard_macos_broker_tool_unavailable")
}

fn bind_listener(path: &Path) -> Result<UnixListener> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if metadata.file_type().is_symlink()
            || !metadata.file_type().is_socket()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
        {
            anyhow::bail!("wireguard_macos_broker_socket_unsafe");
        }
        fs::remove_file(path)?;
    }
    let listener = UnixListener::bind(path)?;
    if unsafe {
        libc::chown(
            std::ffi::CString::new(path.as_os_str().as_bytes())?.as_ptr(),
            0,
            BROKER_SOCKET_GROUP_GID,
        )
    } != 0
    {
        anyhow::bail!("wireguard_macos_broker_socket_owner_unavailable");
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o660))?;
    // A launch daemon may start with a permissive umask.  The mode and group
    // are set explicitly; peer credentials remain mandatory for execution.
    let metadata = fs::symlink_metadata(path)?;
    if metadata.uid() != 0
        || metadata.gid() != BROKER_SOCKET_GROUP_GID
        || metadata.mode() & 0o777 != 0o660
    {
        anyhow::bail!("wireguard_macos_broker_socket_unsafe");
    }
    Ok(listener)
}

fn broker_instance_digest() -> String {
    let pid = unsafe { libc::getpid() } as u64;
    let mut hash = Sha256::new();
    hash.update(BROKER_ID_DOMAIN);
    hash.update(pid.to_be_bytes());
    hash.update(unix_time_seconds().unwrap_or_default().to_be_bytes());
    hex(&hash.finalize())
}

fn unix_time_seconds() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("wireguard_macos_broker_clock_unavailable")?
        .as_secs())
}

fn required_digest(value: Option<&str>) -> Result<String> {
    let value = value.ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_digest_missing"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        anyhow::bail!("wireguard_macos_broker_digest_invalid");
    }
    Ok(value.to_string())
}

fn digest(value: &[u8]) -> String {
    hex(&Sha256::digest(value))
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        value.push(char::from(b"0123456789abcdef"[(byte & 0xf) as usize]));
    }
    value
}

fn public_error(error: &anyhow::Error) -> String {
    let value = error.to_string();
    if value.starts_with("wireguard_macos_broker_") {
        value
    } else {
        "wireguard_macos_broker_unavailable".to_string()
    }
}

fn write_frame<T: serde::Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_IPC_FRAME {
        anyhow::bail!("wireguard_macos_broker_frame_too_large");
    }
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<T: for<'de> serde::Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut bytes = Vec::with_capacity(4096);
    let mut byte = [0_u8; 1];
    loop {
        if stream.read(&mut byte)? == 0 {
            anyhow::bail!("wireguard_macos_broker_frame_eof");
        }
        if byte[0] == b'\n' {
            break;
        }
        bytes.push(byte[0]);
        if bytes.len() >= MAX_IPC_FRAME {
            anyhow::bail!("wireguard_macos_broker_frame_too_large");
        }
    }
    Ok(serde_json::from_slice(&bytes)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_is_lowercase_and_bounded() {
        assert_eq!(digest(b"agent-remote").len(), 64);
        assert!(required_digest(Some(&digest(b"x"))).is_ok());
        assert!(required_digest(Some(&"A".repeat(64))).is_err());
    }

    #[test]
    fn status_envelope_rejects_execute_fields() {
        let request = IpcRequest {
            version: IPC_PROTOCOL_VERSION,
            method: "status".into(),
            request_id: Some("a".repeat(64)),
            plan_sha256: None,
            caller_sha256: None,
            request_sha256: None,
            target_scope_sha256: None,
            action: None,
            logical_name: None,
            config_file_identity: None,
            config_content_sha256: None,
            config_public_key: None,
            config_b64: None,
        };
        assert!(status_response(&request, &"b".repeat(64)).is_err());
    }
}
