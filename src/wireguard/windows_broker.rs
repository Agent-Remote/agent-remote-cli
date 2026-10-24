//! Windows protected WireGuard worker transport.
//!
//! This module is deliberately a small transport boundary.  It creates a
//! local-only named pipe, binds every request to the process and token observed
//! by Windows, and gives the worker one bounded request window.  It does not
//! grant authorization by itself and it never infers that a broker is installed
//! merely because the helper is running.  The authenticated caller challenge
//! and the execution store remain separate gates.

use std::fmt;
use std::ptr::null_mut;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_CONNECTED,
    ERROR_PIPE_LISTENING, ERROR_SERVICE_DOES_NOT_EXIST, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::{
    GetLengthSid, GetTokenInformation, IsValidSid, TokenSessionId, TokenStatistics, TokenUser,
    TOKEN_QUERY, TOKEN_STATISTICS, TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    GetNamedPipeClientSessionId, PeekNamedPipe, SetNamedPipeHandleState, WaitNamedPipeW,
    NAMED_PIPE_MODE, PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
    PIPE_TYPE_MESSAGE, PIPE_WAIT,
};
use windows_sys::Win32::System::Services::{
    CloseServiceHandle, OpenSCManagerW, OpenServiceW, QueryServiceStatusEx, SC_MANAGER_CONNECT,
    SC_STATUS_PROCESS_INFO, SERVICE_QUERY_STATUS, SERVICE_RUNNING, SERVICE_STATUS_PROCESS,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken,
    PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Protocol version for the one-shot Windows worker pipe.
pub const PROTOCOL_VERSION: u32 = 1;
/// Maximum one-message request and response size.  This leaves room for a
/// private configuration while keeping a malicious worker frame bounded.
pub const MAX_FRAME_BYTES: usize = 64 * 1024;
/// Private config bytes are transferred as base64 in the bounded frame.
pub const MAX_CONFIG_BYTES: usize = 48 * 1024;
/// A UAC worker must not stay alive waiting for a caller indefinitely.
pub const MAX_WORKER_LIFETIME: Duration = Duration::from_secs(30);

const PIPE_PREFIX: &str = r"\\.\pipe\AgentRemote-WireGuard-v1-";
const SECURITY_DESCRIPTOR_REVISION: u32 = 1;
const PIPE_BUFFER_BYTES: u32 = MAX_FRAME_BYTES as u32;
const PIPE_GENERIC_READ: u32 = 0x8000_0000;
const PIPE_GENERIC_WRITE: u32 = 0x4000_0000;

/// Request sent over the protected pipe.  `config_b64` is private material;
/// its `Debug` implementation is redacted and it must never be logged.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub protocol_version: u32,
    pub request_id: String,
    pub caller_sha256: String,
    pub action: String,
    pub config_sha256: String,
    pub config_b64: String,
    pub expires_at_unix_ms: u64,
}

/// The broker-facing envelope adds the reviewed plan and target binding to
/// the transport request without changing the small legacy worker request
/// shape.  Every field is checked by the elevated service before it writes a
/// configuration or invokes WireGuard.
#[derive(Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerWorkerEnvelope {
    pub protocol_version: u32,
    pub worker: WorkerRequest,
    pub plan_sha256: String,
    pub target_scope_sha256: String,
    pub logical_name: String,
    pub config_file_identity: String,
    pub config_content_sha256: String,
    pub config_public_key: String,
}

impl fmt::Debug for BrokerWorkerEnvelope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BrokerWorkerEnvelope")
            .field("protocol_version", &self.protocol_version)
            .field("worker", &self.worker)
            .field("plan_sha256", &self.plan_sha256)
            .field("target_scope_sha256", &self.target_scope_sha256)
            .field("logical_name", &self.logical_name)
            .field("config_file_identity", &self.config_file_identity)
            .field("config_content_sha256", &self.config_content_sha256)
            .field("config_public_key", &self.config_public_key)
            .finish()
    }
}

/// Metadata after the broker envelope has passed identity and digest checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedBrokerEnvelope {
    pub worker: ValidatedRequest,
    pub plan_sha256: String,
    pub target_scope_sha256: String,
    pub logical_name: String,
    pub config_file_identity: String,
    pub config_content_sha256: String,
    pub config_public_key: String,
}

impl WorkerRequest {
    /// Construct a request from bytes after the desktop has obtained its own
    /// OS identity. The elevated side still observes and rechecks this
    /// identity; this constructor is convenience, never authorization.
    pub fn new(
        identity: &CallerIdentity,
        request_id: String,
        action: WorkerAction,
        config: &[u8],
        expires_at_unix_ms: u64,
    ) -> Result<Self> {
        if !digest(&request_id)
            || !digest(&identity.caller_sha256)
            || config.is_empty()
            || config.len() > MAX_CONFIG_BYTES
        {
            bail!("wireguard_windows_worker_request_invalid");
        }
        Ok(Self {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            caller_sha256: identity.caller_sha256.clone(),
            action: match action {
                WorkerAction::Up => "up".to_string(),
                WorkerAction::Down => "down".to_string(),
            },
            config_sha256: hex_digest(config),
            config_b64: STANDARD.encode(config),
            expires_at_unix_ms,
        })
    }
}

impl fmt::Debug for WorkerRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerRequest")
            .field("protocol_version", &self.protocol_version)
            .field("request_id", &self.request_id)
            .field("caller_sha256", &self.caller_sha256)
            .field("action", &self.action)
            .field("config_sha256", &self.config_sha256)
            .field("config_b64", &"<redacted>")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

/// The only request actions accepted by this worker boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkerAction {
    Up,
    Down,
}

/// A request after strict validation.  Private bytes are zeroized on drop and
/// never cross into the JSON desktop protocol or an operation record.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedRequest {
    pub request_id: String,
    pub action: WorkerAction,
    pub config_sha256: String,
    pub config_bytes: Zeroizing<Vec<u8>>,
    pub expires_at_unix_ms: u64,
}

impl fmt::Debug for ValidatedRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ValidatedRequest")
            .field("request_id", &self.request_id)
            .field("action", &self.action)
            .field("config_sha256", &self.config_sha256)
            .field("config_bytes", &"<redacted>")
            .field("expires_at_unix_ms", &self.expires_at_unix_ms)
            .finish()
    }
}

/// Identity independently observed from the named-pipe client token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CallerIdentity {
    pub process_id: u32,
    pub session_id: u32,
    pub user_sid_sha256: String,
    pub caller_sha256: String,
}

/// Observe the current process through the same token path used by the
/// elevated worker. A desktop client uses this only to populate a request;
/// the worker repeats the observation from the named pipe peer.
#[cfg(windows)]
pub fn observe_current_caller() -> Result<CallerIdentity> {
    let process_id = unsafe { GetCurrentProcessId() };
    if process_id == 0 {
        bail!("wireguard_windows_worker_caller_unavailable");
    }
    let mut token = null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0
        || token.is_null()
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows worker caller token");
    }
    let mut session_id = 0;
    let mut session_size = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenSessionId,
            &mut session_id as *mut u32 as *mut _,
            std::mem::size_of::<u32>() as u32,
            &mut session_size,
        )
    } == 0
    {
        unsafe { CloseHandle(token) };
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows worker caller session");
    }
    let identity = token_user_identity(token, process_id, session_id);
    unsafe { CloseHandle(token) };
    identity
}

/// A response contains no private configuration or tool output.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WorkerResponse {
    pub protocol_version: u32,
    pub request_id: String,
    pub accepted: bool,
    pub error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_state: Option<super::target::TargetState>,
}

/// Result of the transport handshake.  The request is validated against the
/// identity obtained from the pipe itself; the caller cannot provide a second
/// identity through JSON.
#[derive(Debug)]
pub struct WorkerHandshake {
    pub identity: CallerIdentity,
    pub request: ValidatedRequest,
    pub request_sha256: String,
}

/// Authenticated Windows broker handshake, including the reviewed plan and
/// target binding carried by the service envelope.
#[derive(Debug)]
pub struct BrokerWorkerHandshake {
    pub identity: CallerIdentity,
    pub request: ValidatedRequest,
    pub request_sha256: String,
    pub plan_sha256: String,
    pub target_scope_sha256: String,
    pub logical_name: String,
    pub config_file_identity: String,
    pub config_content_sha256: String,
    pub config_public_key: String,
}

impl BrokerWorkerHandshake {
    pub fn issue_permit(&self, journal_durable: bool, now_unix_ms: u64) -> Result<ExecutionPermit> {
        issue_permit(
            &self.request,
            &self.identity,
            &self.request_sha256,
            &self.target_scope_sha256,
            journal_durable,
            now_unix_ms,
        )
    }
}

/// A one-shot execution permit issued only after the operation's durable
/// submission boundary and target scope have been established by the broker.
/// The permit is intentionally private state: callers can consume it once but
/// cannot mint one by constructing JSON or by observing a status response.
#[derive(Debug)]
pub struct ExecutionPermit {
    permit_sha256: String,
    request_id: String,
    caller_sha256: String,
    config_sha256: String,
    action: WorkerAction,
    target_scope_sha256: String,
    expires_at_unix_ms: u64,
    consumed: bool,
}

/// Non-secret claims returned after a permit is consumed.  The worker may use
/// these claims to invoke a fixed WireGuard executable; private configuration
/// bytes stay in `ValidatedRequest` and never enter the permit or response.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PermitClaims {
    pub permit_sha256: String,
    pub request_id: String,
    pub caller_sha256: String,
    pub config_sha256: String,
    pub action: WorkerAction,
    pub target_scope_sha256: String,
}

/// Strict read-only status consumed by desktop `wireguard.bridge.status`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BrokerStatus {
    pub state: &'static str,
    pub installation: &'static str,
    pub approval: &'static str,
    pub protocol: &'static str,
    pub authentication: &'static str,
    pub execution: &'static str,
}

/// Read the fixed SCM installation boundary. Service presence is only an
/// installation observation; caller authentication still requires the live
/// protected pipe and is therefore kept unavailable here.
pub fn status() -> BrokerStatus {
    #[cfg(windows)]
    {
        return native_service_status();
    }
    BrokerStatus {
        state: "unsupported",
        installation: "not_installed",
        approval: "not_requested",
        protocol: "unsupported",
        authentication: "unavailable",
        execution: "unavailable",
    }
}

#[cfg(windows)]
fn native_service_status() -> BrokerStatus {
    const SERVICE_NAME: &str = "AgentRemoteWireGuardBroker";
    let manager = unsafe { OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT) };
    if manager.is_null() {
        return BrokerStatus {
            state: "unavailable",
            installation: "unknown",
            approval: "not_requested",
            protocol: "unknown",
            authentication: "unavailable",
            execution: "unavailable",
        };
    }
    let service_name: Vec<u16> = SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let service = unsafe { OpenServiceW(manager, service_name.as_ptr(), SERVICE_QUERY_STATUS) };
    if service.is_null() {
        let error = unsafe { GetLastError() };
        unsafe { CloseServiceHandle(manager) };
        if error == ERROR_SERVICE_DOES_NOT_EXIST {
            return BrokerStatus {
                state: "observed",
                installation: "not_installed",
                approval: "not_requested",
                protocol: "unsupported",
                authentication: "unavailable",
                execution: "unavailable",
            };
        }
        return BrokerStatus {
            state: "unavailable",
            installation: "unknown",
            approval: "not_requested",
            protocol: "unknown",
            authentication: "unavailable",
            execution: "unavailable",
        };
    }
    let mut status = SERVICE_STATUS_PROCESS::default();
    let mut returned = 0u32;
    let queried = unsafe {
        QueryServiceStatusEx(
            service,
            SC_STATUS_PROCESS_INFO,
            std::ptr::from_mut(&mut status).cast(),
            std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32,
            &mut returned,
        )
    } != 0;
    unsafe {
        CloseServiceHandle(service);
        CloseServiceHandle(manager);
    }
    if !queried || returned < std::mem::size_of::<SERVICE_STATUS_PROCESS>() as u32 {
        return BrokerStatus {
            state: "observed",
            installation: "installed",
            approval: "not_requested",
            protocol: "unknown",
            authentication: "unavailable",
            execution: "unavailable",
        };
    }
    let running = status.dwCurrentState == SERVICE_RUNNING;
    BrokerStatus {
        state: "observed",
        installation: "installed",
        approval: "not_requested",
        protocol: if running { "compatible" } else { "unknown" },
        authentication: "unavailable",
        execution: "unavailable",
    }
}

/// Dispatch the reviewed request to the installed Windows broker. The helper
/// transport below is intentionally the only future execution path: ordinary
/// `runas` elevation, a running process, or a status file never grants a
/// permit. Until the protected broker installer has registered a service and
/// its authenticated endpoint, this returns a stable fail-closed error.
pub(crate) fn execute(
    request: &super::broker::BrokerExecutionRequest,
) -> std::result::Result<super::broker::BrokerReceipt, super::configuration::ConfigError> {
    let identity = observe_current_caller().map_err(|_| {
        super::configuration::ConfigError("wireguard_windows_broker_identity_unavailable")
    })?;
    let action = match request.action {
        super::tunnel::Action::Up => WorkerAction::Up,
        super::tunnel::Action::Down => WorkerAction::Down,
    };
    let expires_at_unix_ms = now_unix_ms()
        .map_err(|_| {
            super::configuration::ConfigError("wireguard_windows_broker_clock_unavailable")
        })?
        .saturating_add(MAX_WORKER_LIFETIME.as_millis() as u64);
    let worker = WorkerRequest::new(
        &identity,
        request.request_id.clone(),
        action,
        &request.config_bytes,
        expires_at_unix_ms,
    )
    .map_err(|_| super::configuration::ConfigError("wireguard_execution_invalid"))?;
    let envelope = BrokerWorkerEnvelope {
        protocol_version: PROTOCOL_VERSION,
        worker,
        plan_sha256: request.plan_sha256.clone(),
        target_scope_sha256: request.target_scope_sha256.clone(),
        logical_name: request.logical_name.clone(),
        config_file_identity: request.config.file_identity.clone(),
        config_content_sha256: request.config.content_sha256.clone(),
        config_public_key: request.config.public_key.clone(),
    };
    let client = PipeClient::connect("service", Duration::from_secs(2))
        .map_err(|_| super::configuration::ConfigError("wireguard_windows_broker_unavailable"))?;
    let response = client.transact_broker(&envelope).map_err(|_| {
        super::configuration::ConfigError("wireguard_windows_broker_protocol_invalid")
    })?;
    if !response.accepted {
        return Err(super::configuration::ConfigError(
            "wireguard_windows_broker_execution_denied",
        ));
    }
    Ok(super::broker::BrokerReceipt {
        operation_id: response
            .operation_id
            .ok_or(super::configuration::ConfigError(
                "wireguard_windows_broker_receipt_invalid",
            ))?,
        target_state: response
            .target_state
            .ok_or(super::configuration::ConfigError(
                "wireguard_windows_broker_receipt_invalid",
            ))?,
    })
}

/// Validate the caller-bound request before any privileged operation.  The
/// named-pipe identity is supplied by `observe_caller`; a caller cannot choose
/// this value in the JSON request.
pub fn validate_request(
    request: WorkerRequest,
    identity: &CallerIdentity,
    now_unix_ms: u64,
) -> Result<ValidatedRequest> {
    if request.protocol_version != PROTOCOL_VERSION
        || !digest(&request.request_id)
        || !digest(&request.caller_sha256)
        || !digest(&request.config_sha256)
        || request.caller_sha256 != identity.caller_sha256
        || !matches!(request.action.as_str(), "up" | "down")
        || request.expires_at_unix_ms < now_unix_ms
        || request.expires_at_unix_ms.saturating_sub(now_unix_ms)
            > MAX_WORKER_LIFETIME.as_millis() as u64
    {
        bail!("wireguard_windows_worker_request_invalid");
    }
    let encoded_len = request.config_b64.len();
    if encoded_len == 0 || encoded_len > MAX_CONFIG_BYTES.saturating_mul(2) {
        bail!("wireguard_windows_worker_request_invalid");
    }
    let config = STANDARD
        .decode(request.config_b64.as_bytes())
        .context("wireguard_windows_worker_config_invalid")?;
    if config.is_empty() || config.len() > MAX_CONFIG_BYTES {
        bail!("wireguard_windows_worker_config_invalid");
    }
    if hex_digest(&config) != request.config_sha256 {
        bail!("wireguard_windows_worker_config_changed");
    }
    let action = if request.action == "up" {
        WorkerAction::Up
    } else {
        WorkerAction::Down
    };
    Ok(ValidatedRequest {
        request_id: request.request_id,
        action,
        config_sha256: request.config_sha256,
        config_bytes: Zeroizing::new(config),
        expires_at_unix_ms: request.expires_at_unix_ms,
    })
}

/// Decode one complete message frame.  A frame is always a single JSON value;
/// trailing bytes, unknown fields, and oversized values fail closed.
pub fn decode_request_frame(frame: &[u8]) -> Result<WorkerRequest> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    let request: WorkerRequest =
        serde_json::from_slice(frame).context("wireguard_windows_worker_request_invalid")?;
    let canonical =
        serde_json::to_vec(&request).context("wireguard_windows_worker_request_invalid")?;
    if canonical != frame {
        bail!("wireguard_windows_worker_request_noncanonical");
    }
    Ok(request)
}

/// Encode a request using the one canonical JSON representation used by the
/// named pipe.  This function is also used by a desktop-side UAC launcher.
pub fn encode_request_frame(request: &WorkerRequest) -> Result<Vec<u8>> {
    let frame = serde_json::to_vec(request).context("wireguard_windows_worker_request_invalid")?;
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    Ok(frame)
}

/// Decode and validate the complete reviewed broker envelope.  The private
/// bytes are still checked by `validate_request`; this second layer binds the
/// plan, target, path identity and public device key supplied by desktop.
pub fn decode_broker_frame(frame: &[u8]) -> Result<BrokerWorkerEnvelope> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    let envelope: BrokerWorkerEnvelope =
        serde_json::from_slice(frame).context("wireguard_windows_worker_request_invalid")?;
    let canonical =
        serde_json::to_vec(&envelope).context("wireguard_windows_worker_request_invalid")?;
    if canonical != frame || envelope.protocol_version != PROTOCOL_VERSION {
        bail!("wireguard_windows_worker_request_noncanonical");
    }
    validate_broker_envelope_shape(&envelope)?;
    Ok(envelope)
}

pub fn encode_broker_frame(envelope: &BrokerWorkerEnvelope) -> Result<Vec<u8>> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        bail!("wireguard_windows_worker_request_invalid");
    }
    validate_broker_envelope_shape(envelope)?;
    let frame = serde_json::to_vec(envelope).context("wireguard_windows_worker_request_invalid")?;
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    Ok(frame)
}

fn validate_broker_envelope_shape(envelope: &BrokerWorkerEnvelope) -> Result<()> {
    if !digest(&envelope.plan_sha256)
        || !digest(&envelope.target_scope_sha256)
        || !digest(&envelope.config_file_identity)
        || !digest(&envelope.config_content_sha256)
        || !super::validation::public_key(&envelope.config_public_key)
        || !valid_logical_name(&envelope.logical_name)
        || envelope.worker.config_sha256 != envelope.config_content_sha256
    {
        bail!("wireguard_windows_worker_request_invalid");
    }
    Ok(())
}

pub fn validate_broker_envelope(
    envelope: BrokerWorkerEnvelope,
    identity: &CallerIdentity,
    now_unix_ms: u64,
) -> Result<ValidatedBrokerEnvelope> {
    let worker = validate_request(envelope.worker, identity, now_unix_ms)?;
    if worker.config_sha256 != envelope.config_content_sha256 {
        bail!("wireguard_windows_worker_config_changed");
    }
    Ok(ValidatedBrokerEnvelope {
        worker,
        plan_sha256: envelope.plan_sha256,
        target_scope_sha256: envelope.target_scope_sha256,
        logical_name: envelope.logical_name,
        config_file_identity: envelope.config_file_identity,
        config_content_sha256: envelope.config_content_sha256,
        config_public_key: envelope.config_public_key,
    })
}

fn valid_logical_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && !matches!(value, "." | "..")
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_=+.-".contains(&byte))
        && !value.starts_with('.')
        && !value.ends_with('.')
}

/// Decode a worker response and enforce the exact response schema.  The
/// response is deliberately content-free and cannot carry tool output.
pub fn decode_response_frame(frame: &[u8]) -> Result<WorkerResponse> {
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    let response: WorkerResponse =
        serde_json::from_slice(frame).context("wireguard_windows_worker_response_invalid")?;
    let canonical =
        serde_json::to_vec(&response).context("wireguard_windows_worker_response_invalid")?;
    if canonical != frame {
        bail!("wireguard_windows_worker_response_noncanonical");
    }
    if response.protocol_version != PROTOCOL_VERSION || !digest(&response.request_id) {
        bail!("wireguard_windows_worker_response_invalid");
    }
    if response.accepted
        && (response.error.is_some()
            || response
                .operation_id
                .as_deref()
                .is_none_or(|value| !digest(value))
            || response.target_state.is_none())
    {
        bail!("wireguard_windows_worker_response_invalid");
    }
    if !response.accepted && (response.operation_id.is_some() || response.target_state.is_some()) {
        bail!("wireguard_windows_worker_response_invalid");
    }
    if response.error.as_deref().is_some_and(|error| {
        error.is_empty() || error.len() > 128 || error.bytes().any(|b| b.is_ascii_control())
    }) {
        bail!("wireguard_windows_worker_response_invalid");
    }
    Ok(response)
}

pub fn encode_response_frame(response: &WorkerResponse) -> Result<Vec<u8>> {
    if response.protocol_version != PROTOCOL_VERSION || !digest(&response.request_id) {
        bail!("wireguard_windows_worker_response_invalid");
    }
    if response.accepted
        && (response.error.is_some()
            || response
                .operation_id
                .as_deref()
                .is_none_or(|value| !digest(value))
            || response.target_state.is_none())
    {
        bail!("wireguard_windows_worker_response_invalid");
    }
    if !response.accepted && (response.operation_id.is_some() || response.target_state.is_some()) {
        bail!("wireguard_windows_worker_response_invalid");
    }
    let frame =
        serde_json::to_vec(response).context("wireguard_windows_worker_response_invalid")?;
    if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
        bail!("wireguard_windows_worker_frame_too_large");
    }
    Ok(frame)
}

/// Hash the exact request transcript before handing it to the privileged
/// worker. The hash binds every field, including the private config digest and
/// expiry, without copying private bytes into operation records.
pub fn request_sha256(request: &WorkerRequest) -> Result<String> {
    let frame = encode_request_frame(request)?;
    Ok(hex_digest(&frame))
}

pub fn broker_request_sha256(envelope: &BrokerWorkerEnvelope) -> Result<String> {
    Ok(hex_digest(&encode_broker_frame(envelope)?))
}

/// Issue a permit after the authenticated broker has durably recorded the
/// request and re-observed the target. `journal_durable` is an explicit fact;
/// false or an invalid scope digest can never produce a permit. The permit's
/// expiry is no later than the request expiry and the worker lifetime.
pub fn issue_permit(
    validated: &ValidatedRequest,
    identity: &CallerIdentity,
    request_sha256: &str,
    target_scope_sha256: &str,
    journal_durable: bool,
    now_unix_ms: u64,
) -> Result<ExecutionPermit> {
    if !journal_durable
        || !digest(request_sha256)
        || !digest(target_scope_sha256)
        || !digest(&identity.caller_sha256)
        || validated.expires_at_unix_ms <= now_unix_ms
        || validated.expires_at_unix_ms.saturating_sub(now_unix_ms)
            > MAX_WORKER_LIFETIME.as_millis() as u64
    {
        bail!("wireguard_windows_worker_permit_unavailable");
    }
    let action = match validated.action {
        WorkerAction::Up => "up",
        WorkerAction::Down => "down",
    };
    let mut transcript = Vec::with_capacity(256);
    transcript.extend_from_slice(b"agent-remote:wireguard:windows-execution-permit:v1\0");
    transcript.extend_from_slice(validated.request_id.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(identity.caller_sha256.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(validated.config_sha256.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(action.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(request_sha256.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(target_scope_sha256.as_bytes());
    transcript.extend_from_slice(&validated.expires_at_unix_ms.to_be_bytes());
    let permit_sha256 = hex_digest(&transcript);
    Ok(ExecutionPermit {
        permit_sha256,
        request_id: validated.request_id.clone(),
        caller_sha256: identity.caller_sha256.clone(),
        config_sha256: validated.config_sha256.clone(),
        action: validated.action,
        target_scope_sha256: target_scope_sha256.to_string(),
        expires_at_unix_ms: validated.expires_at_unix_ms,
        consumed: false,
    })
}

impl ExecutionPermit {
    /// Consume this permit exactly once, binding it again to the observed
    /// caller and validated request. Marking it consumed occurs before the
    /// caller receives claims, so a retry after an uncertain helper outcome
    /// cannot obtain a second execution opportunity.
    pub fn consume(
        &mut self,
        validated: &ValidatedRequest,
        identity: &CallerIdentity,
        now_unix_ms: u64,
    ) -> Result<PermitClaims> {
        if self.consumed
            || now_unix_ms >= self.expires_at_unix_ms
            || self.request_id != validated.request_id
            || self.caller_sha256 != identity.caller_sha256
            || self.config_sha256 != validated.config_sha256
            || self.action != validated.action
        {
            bail!("wireguard_windows_worker_permit_invalid");
        }
        self.consumed = true;
        Ok(PermitClaims {
            permit_sha256: self.permit_sha256.clone(),
            request_id: self.request_id.clone(),
            caller_sha256: self.caller_sha256.clone(),
            config_sha256: self.config_sha256.clone(),
            action: self.action,
            target_scope_sha256: self.target_scope_sha256.clone(),
        })
    }

    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    pub fn expires_at_unix_ms(&self) -> u64 {
        self.expires_at_unix_ms
    }
}

/// One bounded worker request.  Calling `accept` twice fails closed and a
/// worker must be dropped after the first response.
#[derive(Debug)]
pub struct WorkerLifetime {
    started: Instant,
    deadline: Instant,
    accepted: bool,
}

impl WorkerLifetime {
    pub fn new(now: Instant, lifetime: Duration) -> Result<Self> {
        if lifetime.is_zero() || lifetime > MAX_WORKER_LIFETIME {
            bail!("wireguard_windows_worker_lifetime_invalid");
        }
        Ok(Self {
            started: now,
            deadline: now + lifetime,
            accepted: false,
        })
    }

    pub fn accept(&mut self, now: Instant) -> Result<()> {
        if self.accepted || now >= self.deadline {
            bail!("wireguard_windows_worker_expired");
        }
        self.accepted = true;
        Ok(())
    }

    pub fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }

    pub fn remaining(&self, now: Instant) -> Duration {
        self.deadline.saturating_duration_since(now)
    }

    pub fn elapsed(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.started)
    }
}

impl WorkerHandshake {
    /// Issue a permit for this exact handshake. The caller must supply the
    /// broker's independently persisted journal and target-scope facts.
    pub fn issue_permit(
        &self,
        target_scope_sha256: &str,
        journal_durable: bool,
        now_unix_ms: u64,
    ) -> Result<ExecutionPermit> {
        issue_permit(
            &self.request,
            &self.identity,
            &self.request_sha256,
            target_scope_sha256,
            journal_durable,
            now_unix_ms,
        )
    }
}

/// Return a deterministic, validated local pipe name.  Remote clients are
/// rejected by the native pipe mode in `PipeWorker::bind`.
pub fn pipe_name(instance: &str) -> Result<String> {
    if instance.is_empty()
        || instance.len() > 64
        || !instance.bytes().all(|value| {
            value.is_ascii() && (value.is_ascii_alphanumeric() || value == b'-' || value == b'_')
        })
    {
        bail!("wireguard_windows_worker_pipe_invalid");
    }
    Ok(format!("{PIPE_PREFIX}{instance}"))
}

/// One-shot named-pipe server used by an elevated worker.  The default Windows
/// descriptor is replaced with a protected DACL (SYSTEM, Administrators and
/// the interactive user); the client token is still checked independently.
pub struct PipeWorker {
    handle: HANDLE,
    name: Vec<u16>,
}

/// Unprivileged side of the same one-shot named pipe. It never executes a
/// command locally; it only sends one canonical request and receives the
/// bounded worker response. The UAC launcher owns process creation separately.
pub struct PipeClient {
    handle: HANDLE,
}

impl PipeClient {
    pub fn connect(instance: &str, timeout: Duration) -> Result<Self> {
        let name = pipe_name(instance)?;
        let wide = wide_null(&name)?;
        let timeout_ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        if unsafe { WaitNamedPipeW(wide.as_ptr(), timeout_ms) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to connect to Windows worker pipe");
        }
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                PIPE_GENERIC_READ | PIPE_GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                null_mut(),
                OPEN_EXISTING,
                0,
                null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("failed to open Windows worker pipe");
        }
        let mut mode: NAMED_PIPE_MODE = PIPE_READMODE_MESSAGE | PIPE_WAIT;
        if unsafe { SetNamedPipeHandleState(handle, &mut mode, null_mut(), null_mut()) } == 0 {
            let error = std::io::Error::last_os_error();
            unsafe { CloseHandle(handle) };
            return Err(error).context("failed to configure Windows worker pipe");
        }
        Ok(Self { handle })
    }

    pub fn transact(&self, request: &WorkerRequest) -> Result<WorkerResponse> {
        let frame = encode_request_frame(request)?;
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.handle,
                frame.as_ptr(),
                frame.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
            || written as usize != frame.len()
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to send Windows worker request");
        }
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to flush Windows worker request");
        }
        let mut response = vec![0u8; MAX_FRAME_BYTES];
        let mut read = 0;
        if unsafe {
            ReadFile(
                self.handle,
                response.as_mut_ptr(),
                response.len() as u32,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to read Windows worker response");
        }
        response.truncate(read as usize);
        let result = decode_response_frame(&response)?;
        if result.request_id != request.request_id {
            bail!("wireguard_windows_worker_response_mismatch");
        }
        Ok(result)
    }

    pub fn transact_broker(&self, envelope: &BrokerWorkerEnvelope) -> Result<WorkerResponse> {
        let frame = encode_broker_frame(envelope)?;
        let mut written = 0;
        if unsafe {
            WriteFile(
                self.handle,
                frame.as_ptr(),
                frame.len() as u32,
                &mut written,
                null_mut(),
            )
        } == 0
            || written as usize != frame.len()
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to send Windows broker request");
        }
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to flush Windows broker request");
        }
        let mut response = vec![0u8; MAX_FRAME_BYTES];
        let mut read = 0;
        if unsafe {
            ReadFile(
                self.handle,
                response.as_mut_ptr(),
                response.len() as u32,
                &mut read,
                null_mut(),
            )
        } == 0
        {
            return Err(std::io::Error::last_os_error())
                .context("failed to read Windows broker response");
        }
        response.truncate(read as usize);
        let result = decode_response_frame(&response)?;
        if result.request_id != envelope.worker.request_id {
            bail!("wireguard_windows_worker_response_mismatch");
        }
        Ok(result)
    }
}

impl Drop for PipeClient {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.handle) };
    }
}

impl PipeWorker {
    pub fn bind(instance: &str) -> Result<Self> {
        let name = pipe_name(instance)?;
        let wide = wide_null(&name)?;
        let mut descriptor = null_mut();
        let sddl = wide_null("D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;IU)")?;
        let mut descriptor_size = 0;
        let converted = unsafe {
            windows_sys::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SECURITY_DESCRIPTOR_REVISION,
                &mut descriptor,
                &mut descriptor_size,
            )
        };
        if converted == 0 || descriptor.is_null() {
            bail!("failed to create Windows worker security descriptor");
        }
        let attributes = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>()
                as u32,
            lpSecurityDescriptor: descriptor,
            bInheritHandle: 0,
        };
        let handle = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                PIPE_BUFFER_BYTES,
                PIPE_BUFFER_BYTES,
                MAX_WORKER_LIFETIME.as_millis() as u32,
                &attributes,
            )
        };
        unsafe { LocalFree(descriptor as _) };
        if handle == INVALID_HANDLE_VALUE || handle.is_null() {
            return Err(std::io::Error::last_os_error())
                .context("failed to create protected Windows worker pipe");
        }
        Ok(Self { handle, name: wide })
    }

    /// Wait for one client, polling a nonblocking pipe so lifetime remains
    /// bounded even if UAC approval is abandoned.
    pub fn accept(&self, lifetime: &mut WorkerLifetime) -> Result<CallerIdentity> {
        let mut mode: NAMED_PIPE_MODE = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
        let _ = unsafe { SetNamedPipeHandleState(self.handle, &mut mode, null_mut(), null_mut()) };
        loop {
            if lifetime.expired(Instant::now()) {
                bail!("wireguard_windows_worker_expired");
            }
            let connected = unsafe { ConnectNamedPipe(self.handle, null_mut()) };
            if connected != 0 || unsafe { GetLastError() } == ERROR_PIPE_CONNECTED {
                // Restore blocking message reads after the bounded connect poll.
                let mut blocking = PIPE_READMODE_MESSAGE | PIPE_WAIT;
                let _ = unsafe {
                    SetNamedPipeHandleState(self.handle, &mut blocking, null_mut(), null_mut())
                };
                return observe_caller(self.handle);
            }
            let error = unsafe { GetLastError() };
            if error != ERROR_PIPE_LISTENING {
                return Err(std::io::Error::from_raw_os_error(error as i32).into());
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    pub fn read_frame(&self, lifetime: &WorkerLifetime) -> Result<Vec<u8>> {
        let deadline = Instant::now() + lifetime.remaining(Instant::now());
        let mut available = 0;
        loop {
            if Instant::now() >= deadline {
                bail!("wireguard_windows_worker_expired");
            }
            let ok = unsafe {
                PeekNamedPipe(
                    self.handle,
                    null_mut(),
                    0,
                    null_mut(),
                    &mut available,
                    null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_NO_DATA {
                    thread::sleep(Duration::from_millis(10));
                    continue;
                }
                return Err(std::io::Error::from_raw_os_error(error as i32).into());
            }
            if available == 0 {
                thread::sleep(Duration::from_millis(10));
                continue;
            }
            if available as usize > MAX_FRAME_BYTES {
                bail!("wireguard_windows_worker_frame_too_large");
            }
            let mut frame = vec![0u8; available as usize];
            let mut read = 0;
            let ok = unsafe {
                ReadFile(
                    self.handle,
                    frame.as_mut_ptr(),
                    frame.len() as u32,
                    &mut read,
                    null_mut(),
                )
            };
            if ok == 0 {
                let error = unsafe { GetLastError() };
                if error == ERROR_MORE_DATA {
                    bail!("wireguard_windows_worker_frame_too_large");
                }
                return Err(std::io::Error::from_raw_os_error(error as i32).into());
            }
            frame.truncate(read as usize);
            return Ok(frame);
        }
    }

    /// Perform the complete one-shot request handshake: obtain the named-pipe
    /// peer's process/session/token identity, read one canonical request,
    /// validate expiry and config bytes against that identity, and consume the
    /// worker lifetime. No privileged command is run by this method.
    pub fn handshake(
        &self,
        lifetime: &mut WorkerLifetime,
        now_unix_ms: u64,
    ) -> Result<WorkerHandshake> {
        let identity = self.accept(lifetime)?;
        let frame = self.read_frame(lifetime)?;
        let request = decode_request_frame(&frame)?;
        let request_sha256 = hex_digest(&frame);
        let validated = validate_request(request, &identity, now_unix_ms)?;
        lifetime.accept(Instant::now())?;
        Ok(WorkerHandshake {
            identity,
            request: validated,
            request_sha256,
        })
    }

    pub fn handshake_broker(
        &self,
        lifetime: &mut WorkerLifetime,
        now_unix_ms: u64,
    ) -> Result<BrokerWorkerHandshake> {
        let identity = self.accept(lifetime)?;
        let frame = self.read_frame(lifetime)?;
        let envelope = decode_broker_frame(&frame)?;
        let request_sha256 = hex_digest(&frame);
        let validated = validate_broker_envelope(envelope, &identity, now_unix_ms)?;
        lifetime.accept(Instant::now())?;
        Ok(BrokerWorkerHandshake {
            identity,
            request: validated.worker,
            request_sha256,
            plan_sha256: validated.plan_sha256,
            target_scope_sha256: validated.target_scope_sha256,
            logical_name: validated.logical_name,
            config_file_identity: validated.config_file_identity,
            config_content_sha256: validated.config_content_sha256,
            config_public_key: validated.config_public_key,
        })
    }

    /// Run one complete worker transaction. The callback is the only place
    /// where a platform executor may consume a permit and invoke the fixed
    /// WireGuard service. It receives no caller-controlled path or raw JSON.
    /// The pipe is disconnected after the response whether the callback
    /// succeeds or fails.
    pub fn serve_once<F>(
        &self,
        lifetime: &mut WorkerLifetime,
        now_unix_ms: u64,
        handler: F,
    ) -> Result<WorkerResponse>
    where
        F: FnOnce(WorkerHandshake) -> Result<WorkerResponse>,
    {
        let handshake = self.handshake(lifetime, now_unix_ms)?;
        let request_id = handshake.request_id().to_string();
        let response = handler(handshake).unwrap_or_else(|_| WorkerResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            accepted: false,
            error: Some("wireguard_windows_worker_execution_failed".to_string()),
            operation_id: None,
            target_state: None,
        });
        self.write_response(&response)?;
        self.disconnect();
        Ok(response)
    }

    pub fn serve_broker_once<F>(
        &self,
        lifetime: &mut WorkerLifetime,
        now_unix_ms: u64,
        handler: F,
    ) -> Result<WorkerResponse>
    where
        F: FnOnce(BrokerWorkerHandshake) -> Result<WorkerResponse>,
    {
        let handshake = self.handshake_broker(lifetime, now_unix_ms)?;
        let request_id = handshake.request.request_id.clone();
        let response = handler(handshake).unwrap_or_else(|_| WorkerResponse {
            protocol_version: PROTOCOL_VERSION,
            request_id,
            accepted: false,
            error: Some("wireguard_windows_worker_execution_failed".to_string()),
            operation_id: None,
            target_state: None,
        });
        self.write_response(&response)?;
        self.disconnect();
        Ok(response)
    }

    pub fn write_frame(&self, frame: &[u8]) -> Result<()> {
        if frame.is_empty() || frame.len() > MAX_FRAME_BYTES {
            bail!("wireguard_windows_worker_frame_too_large");
        }
        let mut written = 0;
        let ok = unsafe {
            WriteFile(
                self.handle,
                frame.as_ptr(),
                frame.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        if ok == 0 || written as usize != frame.len() {
            return Err(std::io::Error::last_os_error().into());
        }
        if unsafe { FlushFileBuffers(self.handle) } == 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to flush Windows worker response");
        }
        Ok(())
    }

    /// Write an exact response for a handshake. The request ID is checked by
    /// the caller before this function is called; response encoding performs
    /// its own schema and size checks.
    pub fn write_response(&self, response: &WorkerResponse) -> Result<()> {
        self.write_frame(&encode_response_frame(response)?)
    }

    pub fn disconnect(&self) {
        unsafe { DisconnectNamedPipe(self.handle) };
    }

    pub fn name(&self) -> String {
        String::from_utf16_lossy(&self.name[..self.name.len().saturating_sub(1)])
    }
}

impl WorkerHandshake {
    fn request_id(&self) -> &str {
        &self.request.request_id
    }
}

impl Drop for PipeWorker {
    fn drop(&mut self) {
        unsafe {
            DisconnectNamedPipe(self.handle);
            CloseHandle(self.handle);
        }
    }
}

fn observe_caller(pipe: HANDLE) -> Result<CallerIdentity> {
    let mut process_id = 0;
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut process_id) } == 0 || process_id == 0 {
        bail!("wireguard_windows_worker_caller_unavailable");
    }
    let mut session_id = 0;
    if unsafe { GetNamedPipeClientSessionId(pipe, &mut session_id) } == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows worker caller session");
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, process_id) };
    if process.is_null() {
        return Err(std::io::Error::last_os_error())
            .context("failed to open Windows worker caller process");
    }
    let mut token = null_mut();
    let token_result = unsafe { OpenProcessToken(process, TOKEN_QUERY, &mut token) };
    if token_result == 0 || token.is_null() {
        unsafe { CloseHandle(process) };
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows worker caller token");
    }
    let identity = token_user_identity(token, process_id, session_id);
    unsafe {
        CloseHandle(token);
        CloseHandle(process);
    }
    identity
}

fn token_user_identity(token: HANDLE, process_id: u32, session_id: u32) -> Result<CallerIdentity> {
    let mut needed = 0;
    unsafe {
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to size Windows worker caller token");
    }
    let mut bytes = vec![0u8; needed as usize];
    if unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            bytes.as_mut_ptr() as *mut _,
            bytes.len() as u32,
            &mut needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to read Windows worker caller token");
    }
    let token_user = unsafe { &*(bytes.as_ptr() as *const TOKEN_USER) };
    let sid = token_user.User.Sid;
    if sid.is_null() || unsafe { IsValidSid(sid) } == 0 {
        bail!("wireguard_windows_worker_caller_sid_invalid");
    }
    let sid_len = unsafe { GetLengthSid(sid) } as usize;
    if sid_len == 0 || sid_len > bytes.len() {
        bail!("wireguard_windows_worker_caller_sid_invalid");
    }
    let sid_bytes = unsafe { std::slice::from_raw_parts(sid as *const u8, sid_len) };
    let user_sid_sha256 = hex_digest(sid_bytes);
    // Bind the request to the token's locally unique authentication ID as
    // well as its SID. This prevents a copied SID from another logon token
    // from satisfying the same caller digest and makes token replacement
    // fail closed even when the process ID has not changed.
    let mut statistics = std::mem::MaybeUninit::<TOKEN_STATISTICS>::zeroed();
    let mut statistics_needed = 0;
    if unsafe {
        GetTokenInformation(
            token,
            TokenStatistics,
            statistics.as_mut_ptr() as *mut _,
            std::mem::size_of::<TOKEN_STATISTICS>() as u32,
            &mut statistics_needed,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error())
            .context("failed to inspect Windows worker token statistics");
    }
    let statistics = unsafe { statistics.assume_init() };
    let mut transcript = Vec::with_capacity(96);
    transcript.extend_from_slice(b"agent-remote:wireguard:windows-pipe-caller:v1\0");
    transcript.extend_from_slice(&process_id.to_le_bytes());
    transcript.extend_from_slice(&session_id.to_le_bytes());
    transcript.extend_from_slice(user_sid_sha256.as_bytes());
    transcript.extend_from_slice(&statistics.AuthenticationId.LowPart.to_le_bytes());
    transcript.extend_from_slice(&statistics.AuthenticationId.HighPart.to_le_bytes());
    let caller_sha256 = hex_digest(&transcript);
    Ok(CallerIdentity {
        process_id,
        session_id,
        user_sid_sha256,
        caller_sha256,
    })
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .fold(String::with_capacity(64), |mut output, byte| {
            output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
            output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
            output
        })
}

fn wide_null(value: &str) -> Result<Vec<u16>> {
    use std::os::windows::ffi::OsStrExt;

    let mut units: Vec<u16> = std::ffi::OsStr::new(value).encode_wide().collect();
    if units.contains(&0) {
        bail!("Windows worker value contains NUL");
    }
    units.push(0);
    Ok(units)
}

pub fn now_unix_ms() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("Windows worker clock is before Unix epoch")?
        .as_millis() as u64)
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_windows_broker.rs"]
mod tests;
