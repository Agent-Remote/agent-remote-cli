//! Read-only macOS protected-broker boundary.
//!
//! The Device.app Network Broker XPC service is a user application service and
//! is deliberately not treated as a WireGuard privilege broker.  This module
//! observes the separate, future LaunchDaemon installation contract only.  It
//! never installs, starts, stops, or connects to the service.  Every unknown
//! or incomplete fact is represented as unavailable so a caller cannot turn a
//! status probe into an execution permit.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

use anyhow::Result;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::configuration::ConfigError;
use super::target::TargetState;
use super::tunnel::Action;

const BROKER_LABEL: &str = "dev.agentremote.wireguard.broker";
const BROKER_BUNDLE_IDENTIFIER: &str = "dev.agentremote.wireguard.broker";
const BROKER_PLIST: &str = "/Library/LaunchDaemons/dev.agentremote.wireguard.broker.plist";
const BROKER_EXECUTABLE: &str = "/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker";
/// The LaunchDaemon owns this root/admin-group socket. It is deliberately
/// separate from Device.app's user XPC service; a user application endpoint
/// cannot satisfy the privileged WireGuard execution boundary.
pub(crate) const IPC_SOCKET_PATH: &str = "/var/run/agent-remote-wireguard.sock";
const IPC_PROTOCOL_VERSION: u32 = 1;
const MAX_IPC_FRAME: usize = 128 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(2);
#[allow(dead_code)]
const MAX_PERMITS: usize = 4096;
const PERMIT_TTL_SECONDS: u64 = 30;
const MAX_COMMAND_OUTPUT: usize = 64 * 1024;

// The macOS community build already pins this identity for Device.app and its
// XPC services.  A missing compile-time pin intentionally makes the broker
// identity unverified; it must never silently fall back to an arbitrary
// developer certificate.
const EXPECTED_CERTIFICATE_SHA1: Option<&str> =
    option_env!("AGENT_REMOTE_DEVICE_SIGNER_CERTIFICATE_SHA1");
const EXPECTED_TEAM_IDENTIFIER: Option<&str> = option_env!("AGENT_REMOTE_DEVICE_TEAM_IDENTIFIER");
/// This is the certificate common name used by the public community build.
/// The team/certificate pin remains mandatory below; the authority string by
/// itself is never accepted as an identity proof.
const COMMUNITY_AUTHORITY: &str = "Agent Remote Community";

/// Strict request envelope for the LaunchDaemon's Unix-socket protocol.
/// Native implementations may add methods in a later protocol version, but
/// version 1 rejects unknown fields and never treats arbitrary JSON as a
/// command.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IpcRequest {
    pub version: u32,
    pub method: String,
    pub request_id: Option<String>,
    /// Digest of the complete frozen TunnelPlan.  The broker never receives
    /// the plan itself, but carries this digest into the authenticated request
    /// binding so a caller cannot replace a reviewed plan with a new one.
    pub plan_sha256: Option<String>,
    pub caller_sha256: Option<String>,
    pub request_sha256: Option<String>,
    pub target_scope_sha256: Option<String>,
    pub action: Option<Action>,
    pub logical_name: Option<String>,
    pub config_file_identity: Option<String>,
    pub config_content_sha256: Option<String>,
    pub config_public_key: Option<String>,
    pub config_b64: Option<String>,
}

/// Strict response envelope returned by the native service.  A status reply
/// contains no permit.  An execute reply must carry a complete permit which
/// is bound to the request and authenticated peer.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct IpcResponse {
    pub version: u32,
    pub ok: bool,
    pub error: Option<String>,
    pub broker_instance_sha256: Option<String>,
    pub permit: Option<ExecutionPermit>,
    pub operation_id: Option<String>,
    pub target_state: Option<TargetState>,
}

/// A native broker execution permit.  The broker creates it only after the
/// caller-auth challenge, plan and target checks have passed.  The desktop
/// process treats it as opaque signed/validated broker output and binds every
/// field again before invoking the helper.  `permit_id` is consumed exactly
/// once by the broker (and by the local guard when a transport client uses
/// this module directly).
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionPermit {
    pub version: u32,
    pub permit_id: String,
    pub caller_sha256: String,
    pub request_sha256: String,
    pub broker_instance_sha256: String,
    pub issued_at_unix: u64,
    pub expires_at_unix: u64,
}

/// Bounded replay guard for native permits.  It is intentionally independent
/// of the challenge guard: a valid caller proof may produce only one execution
/// opportunity, even if a client retries after a transport timeout.
#[allow(dead_code)]
#[derive(Default)]
pub(crate) struct PermitReplayGuard {
    used: HashMap<String, u64>,
}

#[allow(dead_code)]
impl PermitReplayGuard {
    pub(crate) fn consume(
        &mut self,
        permit: &ExecutionPermit,
        expected_caller_sha256: &str,
        expected_request_sha256: &str,
        expected_broker_instance_sha256: &str,
        now_unix: u64,
    ) -> Result<(), anyhow::Error> {
        prune_permits(&mut self.used, now_unix);
        validate_permit(
            permit,
            expected_caller_sha256,
            expected_request_sha256,
            expected_broker_instance_sha256,
            now_unix,
        )?;
        if self.used.contains_key(&permit.permit_id) {
            anyhow::bail!("wireguard_macos_broker_permit_replayed");
        }
        if self.used.len() >= MAX_PERMITS {
            anyhow::bail!("wireguard_macos_broker_permit_unavailable");
        }
        self.used
            .insert(permit.permit_id.clone(), permit.expires_at_unix);
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BrokerState {
    NotInstalled,
    Running,
    Stopped,
    Invalid,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FactState {
    Confirmed,
    Missing,
    Invalid,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LaunchdState {
    Running,
    Stopped,
    Missing,
    Invalid,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Observation {
    pub(crate) state: BrokerState,
    pub(crate) installation: FactState,
    pub(crate) launchd: LaunchdState,
    pub(crate) identity: FactState,
    /// No Rust implementation of the native IPC protocol exists yet.
    pub(crate) protocol: FactState,
    /// No caller identity can be authenticated until native IPC exists.
    pub(crate) authentication: FactState,
}

impl Observation {
    /// Projection consumed by `wireguard.bridge.status`.  Even a fully
    /// verified launchd/code-signature snapshot cannot advertise execution:
    /// IPC and OS caller binding are separate release gates.
    pub(crate) fn bridge_projection(&self) -> BridgeProjection {
        let (state, installation) = match self.state {
            BrokerState::NotInstalled => ("unsupported", "not_installed"),
            BrokerState::Running => ("running", "installed"),
            BrokerState::Stopped => ("stopped", "installed"),
            BrokerState::Invalid => ("invalid", "invalid"),
            BrokerState::Unknown => ("unknown", "unknown"),
        };
        BridgeProjection {
            state,
            installation,
            // The LaunchDaemon contract is not SMAppService. Approval is not
            // inferred from launchctl, and remains unavailable to the UI.
            approval: "not_requested",
            protocol: if self.protocol == FactState::Confirmed {
                "unix_socket"
            } else {
                "unsupported"
            },
            authentication: if self.authentication == FactState::Confirmed {
                "kernel_peer"
            } else {
                "unavailable"
            },
            execution: if self.protocol == FactState::Confirmed
                && self.authentication == FactState::Confirmed
            {
                "available"
            } else {
                "unavailable"
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct BridgeProjection {
    pub(crate) state: &'static str,
    pub(crate) installation: &'static str,
    pub(crate) approval: &'static str,
    pub(crate) protocol: &'static str,
    pub(crate) authentication: &'static str,
    pub(crate) execution: &'static str,
}

/// Peer facts obtained from the kernel for a connected Unix-domain socket.
/// The broker must use these values from `getpeereid`/`LOCAL_PEERPID`; values
/// copied from the JSON request are never trusted.  The process start timestamp
/// prevents a reused PID from inheriting a prior caller binding.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct PeerIdentity {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
    pub start_time_ns: u64,
}

impl PeerIdentity {
    pub(crate) fn caller_sha256(&self) -> String {
        let mut digest = Sha256::new();
        digest.update(b"agent-remote:wireguard:macos-unix-peer:v1\0");
        digest.update(self.uid.to_be_bytes());
        digest.update(self.gid.to_be_bytes());
        digest.update(self.pid.to_be_bytes());
        digest.update(self.start_time_ns.to_be_bytes());
        hex(&digest.finalize())
    }
}

/// Read the kernel-authenticated peer identity.  This function is used by the
/// privileged LaunchDaemon, never by a caller-provided identity field.  It is
/// intentionally macOS-specific and uses LOCAL_PEERCRED/LOCAL_PEERPID rather
/// than a portable UID-only fallback.
#[allow(dead_code)]
pub(crate) fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity, anyhow::Error> {
    let fd = stream.as_raw_fd();
    let mut credentials = unsafe { std::mem::zeroed::<libc::xucred>() };
    let mut credentials_len = std::mem::size_of::<libc::xucred>() as libc::socklen_t;
    let credentials_result = unsafe {
        libc::getsockopt(
            fd,
            0,
            libc::LOCAL_PEERCRED,
            (&mut credentials as *mut libc::xucred).cast(),
            &mut credentials_len,
        )
    };
    if credentials_result != 0
        || credentials_len < std::mem::size_of::<libc::xucred>() as libc::socklen_t
        || credentials.cr_version == 0
        || credentials.cr_uid == libc::uid_t::MAX
    {
        anyhow::bail!("wireguard_macos_broker_peer_credentials_unavailable");
    }

    let mut pid: libc::c_int = 0;
    let mut pid_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let pid_result = unsafe {
        libc::getsockopt(
            fd,
            0,
            libc::LOCAL_PEERPID,
            (&mut pid as *mut libc::c_int).cast(),
            &mut pid_len,
        )
    };
    if pid_result != 0
        || pid_len < std::mem::size_of::<libc::c_int>() as libc::socklen_t
        || pid <= 0
    {
        anyhow::bail!("wireguard_macos_broker_peer_pid_unavailable");
    }
    let start_time_ns = process_start_time_ns(pid)?;
    if start_time_ns == 0 {
        anyhow::bail!("wireguard_macos_broker_peer_start_time_unavailable");
    }
    Ok(PeerIdentity {
        uid: credentials.cr_uid as u32,
        gid: credentials.cr_groups[0] as u32,
        pid: pid as u32,
        start_time_ns,
    })
}

fn process_start_time_ns(pid: libc::c_int) -> Result<u64, anyhow::Error> {
    let mut info = unsafe { std::mem::zeroed::<libc::proc_bsdinfo>() };
    let expected = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
    let received = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            (&mut info as *mut libc::proc_bsdinfo).cast(),
            expected,
        )
    };
    if received != expected {
        anyhow::bail!("wireguard_macos_broker_peer_process_unavailable");
    }
    info.pbi_start_tvsec
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec.saturating_mul(1_000)))
        .ok_or_else(|| anyhow::anyhow!("wireguard_macos_broker_peer_start_time_invalid"))
}

/// Validate a permit returned by the native service.  The permit's request and
/// caller digests must come from independently reviewed context.  This helper
/// does not grant privilege and does not execute any command.
pub(crate) fn validate_permit(
    permit: &ExecutionPermit,
    expected_caller_sha256: &str,
    expected_request_sha256: &str,
    expected_broker_instance_sha256: &str,
    now_unix: u64,
) -> Result<(), anyhow::Error> {
    if permit.version != IPC_PROTOCOL_VERSION
        || !digest(&permit.permit_id)
        || !digest(&permit.caller_sha256)
        || !digest(&permit.request_sha256)
        || !digest(&permit.broker_instance_sha256)
        || permit.issued_at_unix > now_unix
        || permit.expires_at_unix <= permit.issued_at_unix
        || permit.expires_at_unix <= now_unix
        || permit.expires_at_unix.saturating_sub(permit.issued_at_unix) > PERMIT_TTL_SECONDS
        || permit.caller_sha256 != expected_caller_sha256
        || permit.request_sha256 != expected_request_sha256
        || permit.broker_instance_sha256 != expected_broker_instance_sha256
    {
        anyhow::bail!("wireguard_macos_broker_permit_invalid");
    }
    Ok(())
}

#[allow(dead_code)]
fn prune_permits(used: &mut HashMap<String, u64>, now_unix: u64) {
    used.retain(|_, expires_at| *expires_at >= now_unix);
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn hex(bytes: &[u8]) -> String {
    let mut value = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        value.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        value.push(char::from(b"0123456789abcdef"[(byte & 0xf) as usize]));
    }
    value
}

/// Dispatch a reviewed request over the fixed LaunchDaemon Unix socket.
///
/// The peer credentials are obtained by the native broker from the connected
/// socket. The client also computes its own identity to bind the response
/// locally; a response that names a different caller, request, or broker
/// identity is rejected before any receipt is returned to desktop-control.
/// A missing socket, malformed frame, timeout, or missing one-shot permit is a
/// hard `unavailable` error. There is no sudo, launchctl, or helper fallback.
pub(crate) fn execute(
    request: &crate::wireguard::broker::BrokerExecutionRequest,
) -> Result<crate::wireguard::broker::BrokerReceipt, ConfigError> {
    let mut stream =
        connect_socket().map_err(|_| ConfigError("wireguard_execution_bridge_unavailable"))?;
    let caller =
        local_identity().map_err(|_| ConfigError("wireguard_macos_broker_caller_unavailable"))?;
    let caller_sha256 = caller.caller_sha256();
    let request_sha256 = execution_request_digest(request);
    let encoded = BASE64.encode(&request.config_bytes);
    let frame = IpcRequest {
        version: IPC_PROTOCOL_VERSION,
        method: "execute".to_string(),
        request_id: Some(request.request_id.clone()),
        plan_sha256: Some(request.plan_sha256.clone()),
        caller_sha256: Some(caller_sha256.clone()),
        request_sha256: Some(request_sha256.clone()),
        target_scope_sha256: Some(request.target_scope_sha256.clone()),
        action: Some(request.action),
        logical_name: Some(request.logical_name.clone()),
        config_file_identity: Some(request.config.file_identity.clone()),
        config_content_sha256: Some(request.config.content_sha256.clone()),
        config_public_key: Some(request.config.public_key.clone()),
        config_b64: Some(encoded),
    };
    write_frame(&mut stream, &frame)
        .map_err(|_| ConfigError("wireguard_macos_broker_protocol_unavailable"))?;
    let response: IpcResponse = read_frame(&mut stream)
        .map_err(|_| ConfigError("wireguard_macos_broker_protocol_invalid"))?;
    if response.version != IPC_PROTOCOL_VERSION || !response.ok {
        return Err(ConfigError("wireguard_macos_broker_execution_denied"));
    }
    let broker_instance_sha256 = response
        .broker_instance_sha256
        .as_deref()
        .ok_or(ConfigError("wireguard_macos_broker_identity_unavailable"))?;
    let permit = response
        .permit
        .as_ref()
        .ok_or(ConfigError("wireguard_macos_broker_permit_missing"))?;
    let now = super::caller_auth::unix_time_seconds()
        .map_err(|_| ConfigError("wireguard_macos_broker_clock_unavailable"))?;
    validate_permit(
        permit,
        &caller_sha256,
        &request_sha256,
        broker_instance_sha256,
        now,
    )
    .map_err(|_| ConfigError("wireguard_macos_broker_permit_invalid"))?;
    let operation_id = response
        .operation_id
        .filter(|value| digest(value))
        .ok_or(ConfigError("wireguard_macos_broker_receipt_invalid"))?;
    let target_state = response
        .target_state
        .ok_or(ConfigError("wireguard_macos_broker_receipt_invalid"))?;
    Ok(crate::wireguard::broker::BrokerReceipt {
        operation_id,
        target_state,
    })
}

fn connect_socket() -> Result<UnixStream, anyhow::Error> {
    let stream = UnixStream::connect(IPC_SOCKET_PATH)?;
    stream.set_read_timeout(Some(IPC_TIMEOUT))?;
    stream.set_write_timeout(Some(IPC_TIMEOUT))?;
    Ok(stream)
}

fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<(), anyhow::Error> {
    let mut bytes = serde_json::to_vec(value)?;
    if bytes.len() > MAX_IPC_FRAME {
        anyhow::bail!("wireguard_macos_broker_frame_too_large");
    }
    bytes.push(b'\n');
    stream.write_all(&bytes)?;
    stream.flush()?;
    Ok(())
}

fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T, anyhow::Error> {
    let mut bytes = Vec::with_capacity(4096);
    let mut byte = [0u8; 1];
    loop {
        let read = stream.read(&mut byte)?;
        if read == 0 {
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

fn local_identity() -> Result<PeerIdentity, anyhow::Error> {
    let pid = unsafe { libc::getpid() };
    if pid <= 0 {
        anyhow::bail!("wireguard_macos_broker_process_unavailable");
    }
    let start_time_ns = process_start_time_ns(pid)?;
    if start_time_ns == 0 {
        anyhow::bail!("wireguard_macos_broker_process_start_unavailable");
    }
    Ok(PeerIdentity {
        uid: unsafe { libc::getuid() } as u32,
        gid: unsafe { libc::getgid() } as u32,
        pid: pid as u32,
        start_time_ns,
    })
}

pub(crate) fn execution_request_digest(
    request: &crate::wireguard::broker::BrokerExecutionRequest,
) -> String {
    let mut digest = Sha256::new();
    digest.update(b"agent-remote:wireguard:macos-execution-request:v1\0");
    digest.update(request.request_id.as_bytes());
    digest.update([0]);
    digest.update(request.plan_sha256.as_bytes());
    digest.update([0]);
    digest.update(request.target_scope_sha256.as_bytes());
    digest.update([0]);
    digest.update(match request.action {
        Action::Up => b"up".as_slice(),
        Action::Down => b"down".as_slice(),
    });
    digest.update([0]);
    digest.update(request.logical_name.as_bytes());
    digest.update([0]);
    digest.update(request.config.file_identity.as_bytes());
    digest.update([0]);
    digest.update(request.config.content_sha256.as_bytes());
    digest.update([0]);
    digest.update(request.config.public_key.as_bytes());
    digest.update([0]);
    digest.update(&request.config_bytes);
    hex(&digest.finalize())
}

/// Observe the fixed system LaunchDaemon and its code-signature identity.
///
/// The paths and command arguments are constants.  The command output is
/// bounded and parsed as facts; output text never becomes an executable path
/// or an authorization decision.
pub(crate) fn observe() -> Observation {
    let plist = inspect_regular_root_file(Path::new(BROKER_PLIST));
    let executable = inspect_regular_root_file(Path::new(BROKER_EXECUTABLE));
    let socket = inspect_socket(Path::new(IPC_SOCKET_PATH));
    if plist == FactState::Missing && executable == FactState::Missing {
        return Observation {
            state: BrokerState::NotInstalled,
            installation: FactState::Missing,
            launchd: LaunchdState::Missing,
            identity: FactState::Missing,
            protocol: socket,
            authentication: FactState::Unknown,
        };
    }
    if plist != FactState::Confirmed || executable != FactState::Confirmed {
        return Observation {
            state: BrokerState::Invalid,
            installation: FactState::Invalid,
            launchd: LaunchdState::Unknown,
            identity: FactState::Unknown,
            protocol: FactState::Unknown,
            authentication: FactState::Unknown,
        };
    }

    let launchd = match run_launchctl() {
        Ok(output) => parse_launchctl(&output),
        Err(_) => LaunchdState::Unknown,
    };
    let identity = match inspect_identity(Path::new(BROKER_EXECUTABLE)) {
        Ok(state) => state,
        Err(_) => FactState::Unknown,
    };
    let state = match (launchd, identity) {
        (LaunchdState::Running, FactState::Confirmed) => BrokerState::Running,
        (LaunchdState::Stopped | LaunchdState::Missing, FactState::Confirmed) => {
            BrokerState::Stopped
        }
        (LaunchdState::Invalid, _) | (_, FactState::Invalid) => BrokerState::Invalid,
        _ => BrokerState::Unknown,
    };
    let (protocol, authentication) = if state == BrokerState::Running
        && identity == FactState::Confirmed
        && socket == FactState::Confirmed
    {
        match probe_protocol() {
            Ok(()) => (FactState::Confirmed, FactState::Confirmed),
            Err(_) => (FactState::Invalid, FactState::Unknown),
        }
    } else {
        (socket, FactState::Unknown)
    };
    Observation {
        state,
        installation: FactState::Confirmed,
        launchd,
        identity,
        protocol,
        authentication,
    }
}

fn inspect_regular_root_file(path: &Path) -> FactState {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return FactState::Missing;
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return FactState::Invalid;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != 0 || metadata.nlink() != 1 || metadata.mode() & 0o022 != 0 {
            return FactState::Invalid;
        }
    }
    FactState::Confirmed
}

fn inspect_socket(path: &Path) -> FactState {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return FactState::Missing;
    };
    if metadata.file_type().is_symlink() || !metadata.file_type().is_socket() {
        return FactState::Invalid;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // The LaunchDaemon owns the endpoint.  Administrator-group access is
        // required so a normal desktop process can connect; all other modes
        // and groups are rejected before launchd/protocol inspection.
        const ADMIN_GID: u32 = 80;
        if metadata.uid() != 0
            || metadata.gid() != ADMIN_GID
            || metadata.nlink() != 1
            || metadata.mode() & 0o777 != 0o660
        {
            return FactState::Invalid;
        }
    }
    FactState::Confirmed
}

fn probe_protocol() -> Result<(), anyhow::Error> {
    let mut stream = connect_socket()?;
    write_frame(
        &mut stream,
        &IpcRequest {
            version: IPC_PROTOCOL_VERSION,
            method: "status".to_string(),
            request_id: None,
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
        },
    )?;
    let response: IpcResponse = read_frame(&mut stream)?;
    if response.version != IPC_PROTOCOL_VERSION
        || !response.ok
        || response
            .broker_instance_sha256
            .as_deref()
            .is_none_or(|value| !digest(value))
        || response.permit.is_some()
        || response.operation_id.is_some()
        || response.target_state.is_some()
    {
        anyhow::bail!("wireguard_macos_broker_status_invalid");
    }
    Ok(())
}

fn run_launchctl() -> Result<Vec<u8>> {
    let output = Command::new("/bin/launchctl")
        .args([
            OsStr::new("print"),
            OsStr::new("system/dev.agentremote.wireguard.broker"),
        ])
        .output()?;
    bounded_output(output)
}

fn inspect_identity(path: &Path) -> Result<FactState> {
    let verify = Command::new("/usr/bin/codesign")
        .args([
            OsStr::new("--verify"),
            OsStr::new("--strict"),
            path.as_os_str(),
        ])
        .output()?;
    if !verify.status.success() {
        return Ok(FactState::Invalid);
    }
    let details = Command::new("/usr/bin/codesign")
        .args([
            OsStr::new("--display"),
            OsStr::new("--verbose=4"),
            path.as_os_str(),
        ])
        .output()?;
    let details = bounded_output(details)?;
    let text =
        String::from_utf8(details).map_err(|_| anyhow::anyhow!("codesign output is not UTF-8"))?;
    if !identity_matches(&text) {
        return Ok(FactState::Invalid);
    }
    Ok(FactState::Confirmed)
}

fn identity_matches(details: &str) -> bool {
    let identifier = details
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="))
        .is_some_and(|value| value == BROKER_BUNDLE_IDENTIFIER);
    if !identifier
        || details.lines().any(|line| line == "Authority=adhoc")
        || !details
            .lines()
            .any(|line| line == format!("Authority={COMMUNITY_AUTHORITY}"))
    {
        return false;
    }
    match (EXPECTED_TEAM_IDENTIFIER, EXPECTED_CERTIFICATE_SHA1) {
        (Some(team), certificate) => {
            let team_matches = details
                .lines()
                .find_map(|line| line.strip_prefix("TeamIdentifier="))
                .is_some_and(|value| value == team);
            let certificate_matches = certificate.is_none_or(|expected| {
                details
                    .lines()
                    .find_map(|line| line.strip_prefix("CDHash="))
                    .is_some_and(|value| value.eq_ignore_ascii_case(expected))
            });
            team_matches && certificate_matches
        }
        // Missing compile-time pins must fail closed.  Authority text is only
        // an additional consistency check; it is not a trust root.
        (None, _) => false,
    }
}

fn parse_launchctl(output: &[u8]) -> LaunchdState {
    let Ok(text) = std::str::from_utf8(output) else {
        return LaunchdState::Invalid;
    };
    let mut has_label = false;
    let mut state = None;
    for line in text.lines() {
        if line
            .trim_start()
            .starts_with(&format!("system/{BROKER_LABEL} ="))
        {
            has_label = true;
        }
        if let Some(value) = line.trim().strip_prefix("state = ") {
            state = Some(match value {
                "running" => LaunchdState::Running,
                "stopped" | "waiting" => LaunchdState::Stopped,
                _ => LaunchdState::Invalid,
            });
        }
    }
    if !has_label {
        return if text.contains("Could not find service") {
            LaunchdState::Missing
        } else {
            LaunchdState::Invalid
        };
    }
    state.unwrap_or(LaunchdState::Invalid)
}

fn bounded_output(output: Output) -> Result<Vec<u8>> {
    if output.stdout.len() > MAX_COMMAND_OUTPUT || output.stderr.len() > MAX_COMMAND_OUTPUT {
        anyhow::bail!("macOS broker command output exceeded the bound")
    }
    if output.status.success() {
        Ok(output.stdout)
    } else if output.stdout.is_empty() {
        Ok(output.stderr)
    } else {
        let mut bytes = output.stdout;
        bytes.extend_from_slice(&output.stderr);
        Ok(bytes)
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_macos_broker.rs"]
mod tests;
