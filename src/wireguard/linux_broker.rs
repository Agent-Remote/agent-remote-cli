//! Linux broker boundary for the protected WireGuard service.
//!
//! This module intentionally does not depend on a D-Bus or polkit client
//! library.  A privileged broker must obtain the values below from the native
//! transport (`org.freedesktop.DBus.GetConnectionUnix*`) and from polkit's
//! authorization result, then pass the observations to [`authenticate`].
//! The desktop process cannot manufacture a trusted observation.  In
//! particular, a matching UID, an effective UID of zero, or a `sudo` process
//! is never an authorization result by itself.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::configuration::ConfigError;

#[cfg(target_os = "linux")]
pub mod service {
    //! Root-owned system D-Bus service for reviewed WireGuard operations.
    //!
    //! The service is intentionally a separate binary (see
    //! `agent-remote-wireguard-broker`).  It never accepts a configuration
    //! path or a caller supplied executable.  Every mutating request is
    //! authenticated against the system bus peer and a non-interactive
    //! Polkit decision before the target is observed or touched.

    use std::collections::{HashMap, HashSet};
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use sha2::{Digest, Sha256};
    use tokio::signal::unix::{signal, SignalKind};
    use zbus::message::Header;
    use zbus::{interface, Connection, Proxy};

    use super::{
        authenticate, CallerObservation, DbusPeerObservation, PolkitAuthorizationObservation,
        BUS_NAME, INTERFACE, OBJECT_PATH, POLKIT_ACTION,
    };
    use crate::wireguard::broker::BrokerReceipt;
    use crate::wireguard::execution_config::ExecutionConfig;
    use crate::wireguard::inspection::ConfigBinding;
    use crate::wireguard::replay::ReplayJournal;
    use crate::wireguard::target::{self, TargetState};

    const MAX_FRAME: usize = 128 * 1024;
    const WIRE_PROTOCOL_VERSION: u32 = 1;
    const PROTOCOL_VERSION: u32 = 1;
    const STATUS_METHOD: &str = "Status";
    const EXECUTE_METHOD: &str = "Execute";
    const STAGING_DIR: &str = "/run/agent-remote-wireguard";
    const REPLAY_JOURNAL: &str = "/var/lib/agent-remote-wireguard/requests.log";

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct StatusWire {
        version: u32,
        platform: String,
        transport: String,
        bus_name: String,
        interface: String,
        object_path: String,
        polkit_action: String,
        state: String,
        installation: String,
        authorization: String,
        authentication: String,
        execution: String,
        reason: String,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteWireRequest {
        version: u32,
        request_id: String,
        plan_sha256: String,
        target_scope_sha256: String,
        action: String,
        logical_name: String,
        config: ConfigBinding,
        #[serde(with = "serde_bytes_compat")]
        config_bytes: Vec<u8>,
    }

    #[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
    #[serde(deny_unknown_fields)]
    struct ExecuteWireResponse {
        version: u32,
        operation_id: String,
        target_state: target::TargetState,
    }

    mod serde_bytes_compat {
        use serde::{Deserialize, Deserializer, Serializer};

        pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serializer.collect_seq(value.iter())
        }

        pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
        where
            D: Deserializer<'de>,
        {
            <Vec<u8>>::deserialize(deserializer)
        }
    }

    #[derive(Clone)]
    struct BrokerService {
        replay: Arc<Mutex<ReplayJournal>>,
        active: Arc<Mutex<HashSet<String>>>,
    }

    impl BrokerService {
        fn new() -> anyhow::Result<Self> {
            Ok(Self {
                replay: Arc::new(Mutex::new(
                    ReplayJournal::open(REPLAY_JOURNAL)
                        .map_err(|error| anyhow::anyhow!(error.0))?,
                )),
                active: Arc::new(Mutex::new(HashSet::new())),
            })
        }
    }

    #[interface(name = "dev.agentremote.WireGuardBroker1")]
    impl BrokerService {
        /// Return a caller-scoped readiness projection. Status is intentionally
        /// secret-free and does not grant a mutation permit. The D-Bus sender
        /// and process-start-bound polkit result are observed here as well as
        /// in Execute, so desktop cannot mistake a healthy root service for
        /// authorization of the current caller.
        #[zbus(name = "Status")]
        async fn status(
            &self,
            #[zbus(connection)] connection: &Connection,
            #[zbus(header)] header: Header<'_>,
        ) -> zbus::fdo::Result<Vec<u8>> {
            let facts = tokio::time::timeout(Duration::from_secs(2), async {
                if let Some(sender) = header.sender().map(|name| name.as_str().to_owned()) {
                    match observe_peer(connection, &sender).await {
                        Ok(peer) => check_polkit(connection, &peer).await.ok(),
                        Err(_) => None,
                    }
                } else {
                    None
                }
            })
            .await
            .ok()
            .flatten();
            let (authorization, authentication, execution, reason) = match facts {
                Some(authorization) if authorization.result == "yes" => (
                    "authorized",
                    "authenticated",
                    "ready",
                    "native_broker_ready",
                ),
                Some(_) => (
                    "unauthorized",
                    "authenticated",
                    "not_authorized",
                    "caller_not_authorized",
                ),
                None => (
                    "unavailable",
                    "unavailable",
                    "unavailable",
                    "caller_observation_unavailable",
                ),
            };
            let value = StatusWire {
                version: PROTOCOL_VERSION,
                platform: "linux".into(),
                transport: "dbus-system".into(),
                bus_name: BUS_NAME.into(),
                interface: INTERFACE.into(),
                object_path: OBJECT_PATH.into(),
                polkit_action: POLKIT_ACTION.into(),
                state: "ready".into(),
                installation: "installed".into(),
                authorization: authorization.into(),
                authentication: authentication.into(),
                execution: execution.into(),
                reason: reason.into(),
            };
            serde_json::to_vec(&value)
                .map_err(|_| zbus::fdo::Error::Failed("status_serialization_failed".into()))
        }

        /// Execute one reviewed request. The D-Bus header is the only source
        /// of caller identity; identity fields in the payload are absent by
        /// design and any malformed payload fails closed.
        #[zbus(name = "Execute")]
        async fn execute(
            &self,
            payload: Vec<u8>,
            #[zbus(connection)] connection: &Connection,
            #[zbus(header)] header: Header<'_>,
        ) -> zbus::fdo::Result<Vec<u8>> {
            if payload.len() > MAX_FRAME {
                return Err(denied("wireguard_linux_broker_frame_too_large"));
            }
            let request: ExecuteWireRequest = serde_json::from_slice(&payload)
                .map_err(|_| denied("wireguard_linux_broker_protocol_invalid"))?;
            validate_request(&request).map_err(denied)?;

            let sender = header
                .sender()
                .map(|name| name.as_str().to_owned())
                .ok_or_else(|| denied("wireguard_linux_broker_sender_missing"))?;
            let peer = observe_peer(connection, &sender).await.map_err(denied)?;
            let authorization = check_polkit(connection, &peer).await.map_err(denied)?;
            let now = unix_now().map_err(denied)?;
            authenticate(
                &CallerObservation {
                    peer: peer.clone(),
                    authorization,
                },
                now,
            )
            .map_err(|error| denied(error.0))?;

            // The scope digest is recomputed in this process and cannot be
            // supplied by the UI. This also proves that execution and target
            // observation occur in the same network namespace.
            let scope = target::scope_digest_for_broker(&request.logical_name)
                .map_err(|error| denied(error.0))?;
            if scope != request.target_scope_sha256 {
                return Err(denied("wireguard_linux_broker_scope_mismatch"));
            }

            let _guard = self.claim_request(&request.request_id)?;
            let config =
                ExecutionConfig::from_transfer(request.config_bytes.clone(), &request.config)
                    .map_err(|error| denied(error.0))?;
            let before = target::observe_native_for_broker(&request.logical_name);
            let expected = match request.action.as_str() {
                "up" if before.state == TargetState::Absent => TargetState::Present,
                "down" if before.state == TargetState::Present => TargetState::Absent,
                "up" => return Err(denied("wireguard_linux_broker_target_not_absent")),
                "down" => return Err(denied("wireguard_linux_broker_target_not_present")),
                _ => return Err(denied("wireguard_linux_broker_action_invalid")),
            };

            let operation_id = operation_digest(&request, &before);
            run_fixed_wg_quick(
                &request.action,
                &request.logical_name,
                config.as_bytes(),
                &operation_id,
            )
            .map_err(denied)?;
            let after = target::observe_native_for_broker(&request.logical_name);
            if after.logical_name != request.logical_name || after.state != expected {
                return Err(denied("wireguard_linux_broker_target_changed"));
            }
            let response = ExecuteWireResponse {
                version: WIRE_PROTOCOL_VERSION,
                operation_id,
                target_state: after.state,
            };
            serde_json::to_vec(&response)
                .map_err(|_| denied("wireguard_linux_broker_response_invalid"))
        }
    }

    impl BrokerService {
        fn claim_request(&self, request_id: &str) -> zbus::fdo::Result<RequestGuard> {
            let mut replay = self
                .replay
                .lock()
                .map_err(|_| denied("wireguard_linux_broker_state_unavailable"))?;
            replay
                .reserve(request_id)
                .map_err(|error| denied(error.0))?;
            drop(replay);
            let mut active = self
                .active
                .lock()
                .map_err(|_| denied("wireguard_linux_broker_state_unavailable"))?;
            if !active.insert(request_id.to_owned()) {
                return Err(denied("wireguard_linux_broker_busy"));
            }
            Ok(RequestGuard {
                active: Arc::clone(&self.active),
                request_id: request_id.to_owned(),
            })
        }
    }

    struct RequestGuard {
        active: Arc<Mutex<HashSet<String>>>,
        request_id: String,
    }
    impl Drop for RequestGuard {
        fn drop(&mut self) {
            if let Ok(mut active) = self.active.lock() {
                active.remove(&self.request_id);
            }
        }
    }

    fn denied(message: impl Into<String>) -> zbus::fdo::Error {
        zbus::fdo::Error::AccessDenied(message.into())
    }

    fn validate_request(request: &ExecuteWireRequest) -> Result<(), &'static str> {
        let digest = |value: &str| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        if request.version != WIRE_PROTOCOL_VERSION
            || !digest(&request.request_id)
            || !digest(&request.plan_sha256)
            || !digest(&request.target_scope_sha256)
            || !target::valid_name(&request.logical_name)
            || request.config_bytes.is_empty()
            || request.config_bytes.len() > 1024 * 1024
            || !digest(&request.config.file_identity)
            || !digest(&request.config.content_sha256)
            || !crate::wireguard::validation::public_key(&request.config.public_key)
            || !matches!(request.action.as_str(), "up" | "down")
        {
            return Err("wireguard_linux_broker_request_invalid");
        }
        if format!("{:x}", Sha256::digest(&request.config_bytes)) != request.config.content_sha256 {
            return Err("wireguard_config_changed");
        }
        Ok(())
    }

    async fn observe_peer(
        connection: &Connection,
        sender: &str,
    ) -> Result<DbusPeerObservation, &'static str> {
        if !sender.starts_with(":1.") || sender.len() > 255 {
            return Err("wireguard_linux_broker_invalid_observation");
        }
        let proxy = zbus::fdo::DBusProxy::new(connection)
            .await
            .map_err(|_| "wireguard_linux_broker_dbus_unavailable")?;
        let bus_name = zbus::names::BusName::try_from(sender)
            .map_err(|_| "wireguard_linux_broker_invalid_observation")?;
        let uid = proxy
            .get_connection_unix_user(bus_name.clone())
            .await
            .map_err(|_| "wireguard_linux_broker_peer_unavailable")?;
        let pid = proxy
            .get_connection_unix_process_id(bus_name)
            .await
            .map_err(|_| "wireguard_linux_broker_peer_unavailable")?;
        let start_time_ticks =
            process_start_time(pid).ok_or("wireguard_linux_broker_peer_start_unavailable")?;
        Ok(DbusPeerObservation {
            sender: sender.to_owned(),
            uid,
            pid,
            start_time_ticks,
        })
    }

    async fn check_polkit(
        connection: &Connection,
        peer: &DbusPeerObservation,
    ) -> Result<PolkitAuthorizationObservation, &'static str> {
        use zbus::zvariant::{OwnedVariant, Variant};
        let authority = Proxy::new(
            connection,
            "org.freedesktop.PolicyKit1",
            "/org/freedesktop/PolicyKit1/Authority",
            "org.freedesktop.PolicyKit1.Authority",
        )
        .await
        .map_err(|_| "wireguard_linux_broker_polkit_unavailable")?;
        let mut subject_props = HashMap::new();
        subject_props.insert(
            "pid".to_owned(),
            OwnedVariant::try_from(Variant::from(peer.pid))
                .map_err(|_| "wireguard_linux_broker_polkit_invalid")?,
        );
        subject_props.insert(
            "start-time".to_owned(),
            OwnedVariant::try_from(Variant::from(peer.start_time_ticks))
                .map_err(|_| "wireguard_linux_broker_polkit_invalid")?,
        );
        let subject = ("unix-process".to_owned(), subject_props);
        let details: HashMap<String, String> = HashMap::new();
        // 1 == AllowUserInteraction. It is deliberately omitted here: the
        // broker must never turn a desktop request into an authentication UI.
        let (authorized, challenge, _details): (bool, bool, HashMap<String, String>) = authority
            .call(
                "CheckAuthorization",
                &(
                    subject,
                    POLKIT_ACTION.to_owned(),
                    details,
                    0u32,
                    String::new(),
                ),
            )
            .await
            .map_err(|_| "wireguard_linux_broker_unauthorized")?;
        let checked_at_unix = unix_now().map_err(|_| "wireguard_linux_broker_clock_unavailable")?;
        Ok(PolkitAuthorizationObservation {
            action: POLKIT_ACTION.into(),
            subject_kind: "unix-process".into(),
            subject_uid: peer.uid,
            subject_pid: peer.pid,
            subject_start_time_ticks: peer.start_time_ticks,
            result: if authorized { "yes" } else { "no" }.into(),
            challenge,
            checked_at_unix,
            expires_at_unix: checked_at_unix.saturating_add(30),
        })
    }

    fn process_start_time(pid: u32) -> Option<u64> {
        let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let after_name = raw.rsplit_once(") ")?.1;
        after_name
            .split_whitespace()
            .nth(19)
            .and_then(|value| value.parse().ok())
    }

    fn unix_now() -> Result<u64, &'static str> {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|_| "wireguard_linux_broker_clock_unavailable")
    }

    fn operation_digest(
        request: &ExecuteWireRequest,
        before: &target::TargetObservation,
    ) -> String {
        let mut digest = Sha256::new();
        digest.update(b"agent-remote:wireguard:linux-operation:v1\0");
        digest.update(request.request_id.as_bytes());
        digest.update(request.action.as_bytes());
        digest.update(request.config.content_sha256.as_bytes());
        digest.update(serde_json::to_vec(before).unwrap_or_default());
        format!("{:x}", digest.finalize())
    }

    fn run_fixed_wg_quick(
        action: &str,
        logical_name: &str,
        bytes: &[u8],
        operation_id: &str,
    ) -> Result<(), &'static str> {
        let executable =
            trusted_tool("wg-quick").ok_or("wireguard_linux_broker_tool_unavailable")?;
        // `wg-quick` is a shell script and resolves its networking helpers
        // through PATH.  Checking only the script itself would let a modified
        // dependency run as root.  Require the fixed, root-owned runtime
        // commands before staging any reviewed configuration bytes.
        trusted_tool("bash").ok_or("wireguard_linux_broker_bash_unavailable")?;
        trusted_tool("wg").ok_or("wireguard_linux_broker_wg_unavailable")?;
        trusted_tool("ip").ok_or("wireguard_linux_broker_ip_unavailable")?;
        fs::create_dir_all(STAGING_DIR)
            .map_err(|_| "wireguard_linux_broker_staging_unavailable")?;
        let mode = fs::metadata(STAGING_DIR)
            .map_err(|_| "wireguard_linux_broker_staging_unavailable")?
            .mode();
        if mode & 0o077 != 0 {
            return Err("wireguard_linux_broker_staging_unsafe");
        }
        let path = PathBuf::from(STAGING_DIR).join(format!("{operation_id}-{logical_name}.conf"));
        let mut file = OpenOptions::new();
        file.write(true).create_new(true).mode(0o600);
        let mut handle = file
            .open(&path)
            .map_err(|_| "wireguard_linux_broker_staging_unavailable")?;
        handle
            .write_all(bytes)
            .map_err(|_| "wireguard_linux_broker_staging_write_failed")?;
        handle
            .sync_all()
            .map_err(|_| "wireguard_linux_broker_staging_sync_failed")?;
        drop(handle);
        let result = Command::new(executable)
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .arg(action)
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|_| "wireguard_linux_broker_execution_failed")?;
        let _ = fs::remove_file(&path);
        if !result.success() {
            return Err("wireguard_linux_broker_execution_failed");
        }
        Ok(())
    }

    fn trusted_tool(name: &str) -> Option<PathBuf> {
        let candidates: &[&str] = match name {
            "bash" => &["/usr/bin/bash", "/bin/bash", "/usr/local/bin/bash"],
            "wg" => &[
                "/usr/bin/wg",
                "/bin/wg",
                "/usr/sbin/wg",
                "/sbin/wg",
                "/usr/local/bin/wg",
            ],
            "ip" => &[
                "/usr/bin/ip",
                "/bin/ip",
                "/usr/sbin/ip",
                "/sbin/ip",
                "/usr/local/bin/ip",
            ],
            "wg-quick" => &[
                "/usr/bin/wg-quick",
                "/bin/wg-quick",
                "/usr/local/bin/wg-quick",
            ],
            _ => return None,
        };
        candidates.iter().map(Path::new).find_map(|path| {
            let metadata = fs::symlink_metadata(path).ok()?;
            if !metadata.file_type().is_file()
                || metadata.file_type().is_symlink()
                || metadata.uid() != 0
                || metadata.nlink() != 1
                || metadata.mode() & 0o022 != 0
                || metadata.mode() & 0o111 == 0
            {
                return None;
            }
            Some(path.to_path_buf())
        })
    }

    /// Run the broker until SIGTERM/SIGINT. Startup is fail-closed unless the
    /// process is root and can acquire the fixed system-bus name.
    pub fn run() -> anyhow::Result<()> {
        if unsafe { libc::geteuid() } != 0 {
            anyhow::bail!("agent-remote-wireguard-broker must run as root")
        }
        zbus::block_on(async {
            let connection = Connection::system().await?;
            connection.request_name(BUS_NAME).await?;
            connection
                .object_server()
                .at(OBJECT_PATH, BrokerService::new()?)
                .await?;
            let mut term = signal(SignalKind::terminate())?;
            let mut interrupt = signal(SignalKind::interrupt())?;
            tokio::select! {
                _ = term.recv() => {},
                _ = interrupt.recv() => {},
            }
            Ok::<(), anyhow::Error>(())
        })
    }
}

/// Well-known name reserved for the installed Linux broker.
pub const BUS_NAME: &str = "dev.agentremote.WireGuardBroker";
/// D-Bus interface implemented by the installed Linux broker.
pub const INTERFACE: &str = "dev.agentremote.WireGuardBroker1";
/// Object path implemented by the installed Linux broker.
pub const OBJECT_PATH: &str = "/dev/agentremote/WireGuardBroker";
/// polkit action checked for each mutating request.
pub const POLKIT_ACTION: &str = "dev.agentremote.wireguard.manage";

/// Versioned D-Bus payload exchanged with the installed privileged helper.
/// The payload is transported as one `ay` argument to keep private
/// configuration bytes out of the desktop JSON protocol.  The broker derives
/// the caller digest from the D-Bus peer; no caller identity is accepted in
/// this envelope.
const WIRE_PROTOCOL_VERSION: u32 = 1;
const STATUS_METHOD: &str = "Status";
const EXECUTE_METHOD: &str = "Execute";

const PROTOCOL_VERSION: u32 = 1;
const AUTHORIZATION_TTL_SECONDS: u64 = 30;
const MAX_SENDER_LENGTH: usize = 255;

/// A peer identity read from the D-Bus daemon for one connection.
///
/// `sender` is the unique name returned by the D-Bus daemon.  The PID and
/// process-start value are required because a PID can be reused while a
/// connection or authorization record is being retained.  All fields must be
/// obtained from the daemon; values supplied by the desktop request are not
/// trusted.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DbusPeerObservation {
    pub sender: String,
    pub uid: u32,
    pub pid: u32,
    pub start_time_ticks: u64,
}

/// The independently observed result of a polkit check.
///
/// The broker must ask polkit for this exact action and bind its Unix-process
/// subject to the D-Bus peer.  `result` must be exactly `yes`; `challenge` is
/// required to be false because this boundary cannot safely prompt or defer a
/// privilege decision.  A result with only a matching UID is rejected.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PolkitAuthorizationObservation {
    pub action: String,
    pub subject_kind: String,
    pub subject_uid: u32,
    pub subject_pid: u32,
    pub subject_start_time_ticks: u64,
    pub result: String,
    pub challenge: bool,
    pub checked_at_unix: u64,
    pub expires_at_unix: u64,
}

/// The two facts that must be joined before a mutating broker method is
/// considered authenticated.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CallerObservation {
    pub peer: DbusPeerObservation,
    pub authorization: PolkitAuthorizationObservation,
}

/// Content-free authentication result.  Authorization of a particular tunnel
/// request and target checks remain separate steps in the broker.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AuthenticatedCaller {
    pub sender: String,
    pub caller_sha256: String,
}

/// Explicit Linux broker readiness projection.
///
/// The current CLI has no native privileged service to query, so [`status`]
/// always reports an unavailable broker.  Keeping this state explicit avoids
/// treating a discoverable executable, a user-session bus, or a successful
/// same-UID probe as a protected installation.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BrokerStatus {
    pub version: u32,
    pub platform: &'static str,
    pub transport: &'static str,
    pub bus_name: &'static str,
    pub interface: &'static str,
    pub object_path: &'static str,
    pub polkit_action: &'static str,
    pub state: &'static str,
    pub installation: &'static str,
    pub authorization: &'static str,
    pub authentication: &'static str,
    pub execution: &'static str,
    pub reason: &'static str,
}

/// Return the fail-closed status until a native broker is installed and
/// authenticated.  This function performs no PATH lookup or shell command;
/// an untrusted command named `busctl` or `pkcheck` cannot make the broker look
/// ready.
pub fn status() -> BrokerStatus {
    // A system-bus call is the only way for a broker to become ready.  In
    // particular, this intentionally does not inspect PATH, environment
    // variables, a user-session bus, or a helper executable.  Any transport,
    // decoding, or protocol error stays unavailable.
    if let Some(status) = native_status() {
        return status;
    }
    unavailable_status()
}

fn unavailable_status() -> BrokerStatus {
    BrokerStatus {
        version: PROTOCOL_VERSION,
        platform: "linux",
        transport: "dbus-system",
        bus_name: BUS_NAME,
        interface: INTERFACE,
        object_path: OBJECT_PATH,
        polkit_action: POLKIT_ACTION,
        state: "unavailable",
        installation: "not_installed",
        authorization: "unavailable",
        authentication: "unavailable",
        execution: "unavailable",
        reason: "native_broker_unavailable",
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StatusWire {
    version: u32,
    platform: String,
    transport: String,
    bus_name: String,
    interface: String,
    object_path: String,
    polkit_action: String,
    state: String,
    installation: String,
    authorization: String,
    authentication: String,
    execution: String,
    reason: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExecuteWireRequest {
    version: u32,
    request_id: String,
    plan_sha256: String,
    target_scope_sha256: String,
    action: String,
    logical_name: String,
    config: super::inspection::ConfigBinding,
    #[serde(with = "serde_bytes_compat")]
    config_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ExecuteWireResponse {
    version: u32,
    operation_id: String,
    target_state: super::target::TargetState,
}

// serde_json already encodes a byte vector as an array.  Keeping this module
// local avoids introducing a second serialization crate solely for a payload
// that is bounded and validated before it reaches D-Bus.
mod serde_bytes_compat {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.collect_seq(value.iter())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        <Vec<u8>>::deserialize(deserializer)
    }
}

#[cfg(target_os = "linux")]
fn native_status() -> Option<BrokerStatus> {
    let result = run_zbus(async {
        let connection = zbus::Connection::system().await.map_err(|_| ())?;
        let proxy = zbus::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, INTERFACE)
            .await
            .map_err(|_| ())?;
        let payload: Vec<u8> = proxy.call(STATUS_METHOD, &()).await.map_err(|_| ())?;
        let status: StatusWire = serde_json::from_slice(&payload).map_err(|_| ())?;
        if status.version != PROTOCOL_VERSION
            || status.platform != "linux"
            || status.transport != "dbus-system"
            || status.bus_name != BUS_NAME
            || status.interface != INTERFACE
            || status.object_path != OBJECT_PATH
            || status.polkit_action != POLKIT_ACTION
        {
            return Err(());
        }
        Ok(BrokerStatus {
            version: status.version,
            platform: "linux",
            transport: "dbus-system",
            bus_name: BUS_NAME,
            interface: INTERFACE,
            object_path: OBJECT_PATH,
            polkit_action: POLKIT_ACTION,
            state: leak_status(status.state)?,
            installation: leak_status(status.installation)?,
            authorization: leak_status(status.authorization)?,
            authentication: leak_status(status.authentication)?,
            execution: leak_status(status.execution)?,
            reason: leak_status(status.reason)?,
        })
    });
    result.ok()
}

#[cfg(target_os = "linux")]
fn run_zbus<F, T>(future: F) -> Result<T, ()>
where
    F: std::future::Future<Output = Result<T, ()>> + Send + 'static,
    T: Send + 'static,
{
    // Desktop-control already runs on Tokio. zbus::block_on intentionally
    // panics when nested in a runtime, so move the short system-bus exchange
    // to a dedicated thread in that case.
    if tokio::runtime::Handle::try_current().is_ok() {
        std::thread::Builder::new()
            .name("agent-remote-linux-broker".into())
            .spawn(move || zbus::block_on(future))
            .map_err(|_| ())?
            .join()
            .map_err(|_| ())?
    } else {
        zbus::block_on(future)
    }
}

#[cfg(not(target_os = "linux"))]
fn native_status() -> Option<BrokerStatus> {
    None
}

/// Convert untrusted wire values to the finite static projection consumed by
/// the desktop.  A broker can never inject arbitrary strings into status
/// labels, and a newly added state remains fail-closed until this client is
/// updated deliberately.
#[cfg(target_os = "linux")]
fn leak_status(value: String) -> Result<&'static str, ()> {
    const ALLOWED: &[&str] = &[
        "ready",
        "unavailable",
        "not_installed",
        "installed",
        "authorized",
        "unauthorized",
        "authenticated",
        "unavailable",
        "not_authorized",
        "executed",
        "unknown",
        "native_broker_unavailable",
        "native_broker_invalid",
        "native_broker_ready",
        "caller_not_authorized",
        "caller_observation_unavailable",
        "dbus_unavailable",
    ];
    ALLOWED
        .iter()
        .copied()
        .find(|candidate| *candidate == value)
        .ok_or(())
}

/// Dispatch one frozen request through the installed Linux D-Bus service.
/// `Execute` is a one-shot operation: the service authenticates this
/// connection's unique sender, performs a non-interactive polkit check, and
/// consumes one execution permit before touching the target.  The client does
/// not retry because an interrupted D-Bus call leaves the outcome unknown.
pub(crate) fn execute(
    request: &crate::wireguard::broker::BrokerExecutionRequest,
) -> Result<crate::wireguard::broker::BrokerReceipt, ConfigError> {
    let payload = ExecuteWireRequest {
        version: WIRE_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        plan_sha256: request.plan_sha256.clone(),
        target_scope_sha256: request.target_scope_sha256.clone(),
        action: match request.action {
            super::tunnel::Action::Up => "up".into(),
            super::tunnel::Action::Down => "down".into(),
        },
        logical_name: request.logical_name.clone(),
        config: request.config.clone(),
        config_bytes: request.config_bytes.clone(),
    };
    let bytes =
        serde_json::to_vec(&payload).map_err(|_| ConfigError("wireguard_execution_invalid"))?;
    #[cfg(target_os = "linux")]
    {
        let reply = run_zbus(async {
            let connection = zbus::Connection::system().await.map_err(|_| ())?;
            let proxy = zbus::Proxy::new(&connection, BUS_NAME, OBJECT_PATH, INTERFACE)
                .await
                .map_err(|_| ())?;
            let response: Vec<u8> = proxy
                .call(EXECUTE_METHOD, &(bytes,))
                .await
                .map_err(|_| ())?;
            serde_json::from_slice::<ExecuteWireResponse>(&response).map_err(|_| ())
        })
        .map_err(|_| ConfigError("wireguard_execution_outcome_unknown"))?;
        if reply.version != WIRE_PROTOCOL_VERSION || !digest(&reply.operation_id) {
            return Err(ConfigError("wireguard_execution_outcome_unknown"));
        }
        return Ok(crate::wireguard::broker::BrokerReceipt {
            operation_id: reply.operation_id,
            target_state: reply.target_state,
        });
    }
    #[allow(unreachable_code)]
    Err(unavailable())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Authenticate a caller from independently observed D-Bus and polkit facts.
///
/// This is a transport contract, not an elevation helper.  A caller may pass
/// only after a native broker has checked both sources.  The returned digest is
/// bound to the unique sender and process instance, so it cannot be replaced
/// with an arbitrary UID or a newly reused PID.
pub fn authenticate(
    observation: &CallerObservation,
    now_unix: u64,
) -> Result<AuthenticatedCaller, ConfigError> {
    validate_peer(&observation.peer)?;
    validate_authorization(&observation.authorization, now_unix)?;

    let peer = &observation.peer;
    let authorization = &observation.authorization;
    if authorization.subject_uid != peer.uid
        || authorization.subject_pid != peer.pid
        || authorization.subject_start_time_ticks != peer.start_time_ticks
    {
        return Err(ConfigError("wireguard_linux_broker_identity_mismatch"));
    }

    Ok(AuthenticatedCaller {
        sender: peer.sender.clone(),
        caller_sha256: caller_digest(peer),
    })
}

/// No generic Linux fallback can establish this boundary.  Callers that do
/// not have a native observation should use this explicit error rather than
/// treating the current process UID or `sudo` environment as authorization.
pub fn unavailable() -> ConfigError {
    ConfigError("wireguard_linux_broker_unavailable")
}

fn validate_peer(peer: &DbusPeerObservation) -> Result<(), ConfigError> {
    if !valid_sender(&peer.sender) || peer.pid == 0 || peer.start_time_ticks == 0 {
        return Err(ConfigError("wireguard_linux_broker_invalid_observation"));
    }
    Ok(())
}

fn validate_authorization(
    authorization: &PolkitAuthorizationObservation,
    now_unix: u64,
) -> Result<(), ConfigError> {
    if authorization.action != POLKIT_ACTION
        || authorization.subject_kind != "unix-process"
        || authorization.subject_pid == 0
        || authorization.subject_start_time_ticks == 0
        || authorization.result != "yes"
        || authorization.challenge
        || authorization.expires_at_unix <= authorization.checked_at_unix
        || authorization
            .expires_at_unix
            .saturating_sub(authorization.checked_at_unix)
            > AUTHORIZATION_TTL_SECONDS
    {
        return Err(ConfigError("wireguard_linux_broker_unauthorized"));
    }
    if authorization.checked_at_unix > now_unix
        || authorization.expires_at_unix <= now_unix
        || authorization
            .checked_at_unix
            .saturating_add(AUTHORIZATION_TTL_SECONDS)
            < now_unix
    {
        return Err(ConfigError("wireguard_linux_broker_authorization_expired"));
    }
    Ok(())
}

fn valid_sender(sender: &str) -> bool {
    if sender.len() > MAX_SENDER_LENGTH || !sender.starts_with(":1.") {
        return false;
    }
    let suffix = &sender[3..];
    !suffix.is_empty() && suffix.bytes().all(|byte| byte.is_ascii_digit())
}

fn caller_digest(peer: &DbusPeerObservation) -> String {
    let mut digest = Sha256::new();
    digest.update(b"agent-remote:wireguard:linux-dbus-peer:v1\0");
    digest.update(peer.sender.as_bytes());
    digest.update([0]);
    digest.update(peer.uid.to_be_bytes());
    digest.update(peer.pid.to_be_bytes());
    digest.update(peer.start_time_ticks.to_be_bytes());
    encode_hex(&digest.finalize())
}

fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(b"0123456789abcdef"[(byte >> 4) as usize]));
        output.push(char::from(b"0123456789abcdef"[(byte & 0x0f) as usize]));
    }
    output
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_linux_broker.rs"]
mod tests;
