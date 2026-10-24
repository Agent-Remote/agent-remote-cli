//! Passive native target facts. A snapshot is neither ownership nor execution authority.

use std::path::PathBuf;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};
#[cfg(any(unix, windows, test))]
use sha2::{Digest, Sha256};

use super::{configuration::ConfigError, status};
use crate::config::AppPaths;

#[cfg(target_os = "linux")]
#[path = "target/linux.rs"]
mod linux;
#[cfg(target_os = "macos")]
#[path = "target/macos.rs"]
mod macos;
#[cfg(windows)]
#[path = "target/windows.rs"]
mod windows;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetState {
    Absent,
    Present,
    Unknown,
    Conflict,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TargetReason {
    InvalidName,
    NativeQueryFailed,
    MappingMissing,
    MappingUnsafe,
    MappingStale,
    InterfaceNotWireguard,
    ServiceInvalid,
    TargetChanged,
    StatusUnavailable,
    TargetNotInStatus,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TargetIdentity {
    LinuxInterface {
        name: String,
        index: u32,
        namespace: String,
        public_key: Option<String>,
    },
    MacosInterface {
        name: String,
        index: u32,
        mapping_identity: String,
        socket_identity: String,
        public_key: Option<String>,
    },
    WindowsService {
        service_name: String,
        binary_path: PathBuf,
        config_path: PathBuf,
        config_identity: Option<String>,
        service_state: u32,
        start_type: u32,
        account: String,
        public_key: Option<String>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TargetObservation {
    pub logical_name: String,
    pub state: TargetState,
    pub reason: Option<TargetReason>,
    pub status_state: String,
    pub identity: Option<TargetIdentity>,
}

impl TargetObservation {
    fn empty(name: &str, state: TargetState, reason: Option<TargetReason>) -> Self {
        Self {
            logical_name: name.into(),
            state,
            reason,
            status_state: "not_queried".into(),
            identity: None,
        }
    }
    fn unknown(name: &str, reason: TargetReason) -> Self {
        Self::empty(name, TargetState::Unknown, Some(reason))
    }
    fn present(name: &str, identity: TargetIdentity) -> Self {
        Self {
            identity: Some(identity),
            ..Self::empty(name, TargetState::Present, None)
        }
    }
}

impl TargetIdentity {
    fn interface_name(&self) -> &str {
        match self {
            Self::LinuxInterface { name, .. } | Self::MacosInterface { name, .. } => name,
            Self::WindowsService { service_name, .. } => {
                service_name.strip_prefix("WireGuardTunnel$").unwrap_or("")
            }
        }
    }
    fn set_public_key(&mut self, key: Option<String>) {
        match self {
            Self::LinuxInterface { public_key, .. }
            | Self::MacosInterface { public_key, .. }
            | Self::WindowsService { public_key, .. } => *public_key = key,
        }
    }
}

/// Native calls execute on a read-only worker. Cancellation is checked around
/// native calls; blocking OS/RPC calls cannot be forcibly interrupted here. The
/// outer short-lived CLI process supplies the final lifetime boundary.
pub async fn observe(
    paths: &AppPaths,
    logical_name: &str,
    cancel: Arc<AtomicBool>,
) -> Result<TargetObservation, ConfigError> {
    canceled(&cancel)?;
    if !valid_name(logical_name) {
        return Ok(TargetObservation::unknown("", TargetReason::InvalidName));
    }
    let paths = paths.clone();
    let name = logical_name.to_owned();
    let runtime = tokio::runtime::Handle::current();
    let flag = cancel.clone();
    let mut lifetime = CancelWorker(Some(cancel.clone()));
    // Keep both native snapshots and the wg child spawn on one OS thread. On
    // Linux the child's network namespace must be the namespace just observed.
    let result = tokio::task::spawn_blocking(move || {
        canceled(&flag)?;
        let before = native_observe(&name, &flag);
        canceled(&flag)?;
        if before.state != TargetState::Present {
            return Ok(before);
        }
        let status = runtime.block_on(status::inspect(&paths, flag.clone()))?;
        canceled(&flag)?;
        let after = native_observe(&name, &flag);
        canceled(&flag)?;
        Ok(combine(before, after, &status))
    })
    .await
    .map_err(|_| ConfigError("wireguard_target_unavailable"))?;
    lifetime.0 = None;
    canceled(&cancel)?;
    result
}

/// Observe only the kernel target from the broker's authority.  This is kept
/// separate from [`observe`] because the protected broker does not have a
/// user configuration home or a caller-selected tool path.  The result is
/// still the same bounded target projection and is used for the before/after
/// execution fence.
pub(crate) fn observe_native_for_broker(logical_name: &str) -> TargetObservation {
    let canceled = AtomicBool::new(false);
    native_observe(logical_name, &canceled)
}

/// Return a digest of the network scope that the broker can independently
/// observe.  The desktop sends this value as request metadata; the broker
/// recomputes it in the privileged process before executing.  A namespace
/// identity is deliberately used instead of a user supplied path or host
/// label.
pub fn scope_digest_for_broker(logical_name: &str) -> Result<String, ConfigError> {
    #[cfg(target_os = "linux")]
    {
        return linux::scope_digest(logical_name)
            .map_err(|_| ConfigError("wireguard_target_unavailable"));
    }
    #[cfg(target_os = "macos")]
    {
        return macos::scope_digest(logical_name)
            .map_err(|_| ConfigError("wireguard_target_unavailable"));
    }
    #[cfg(windows)]
    {
        return windows::scope_digest(logical_name)
            .map_err(|_| ConfigError("wireguard_target_unavailable"));
    }
    #[allow(unreachable_code)]
    Err(ConfigError("wireguard_target_unavailable"))
}

fn combine(
    mut before: TargetObservation,
    after: TargetObservation,
    status: &status::StatusResult,
) -> TargetObservation {
    if before != after {
        let mut changed =
            TargetObservation::unknown(&before.logical_name, TargetReason::TargetChanged);
        changed.status_state = status.state.into();
        return changed;
    }
    before.status_state = status.state.into();
    if status.state != "observed" {
        before.reason = Some(TargetReason::StatusUnavailable);
        return before;
    }
    if let Some(identity) = before.identity.as_mut() {
        if let Some(interface) = status
            .interfaces
            .iter()
            .find(|interface| interface.name == identity.interface_name())
        {
            identity.set_public_key(interface.public_key.clone());
        } else {
            before.reason = Some(TargetReason::TargetNotInStatus);
        }
    }
    before
}

struct CancelWorker(Option<Arc<AtomicBool>>);
impl Drop for CancelWorker {
    fn drop(&mut self) {
        if let Some(flag) = self.0.take() {
            flag.store(true, Ordering::Release);
        }
    }
}

fn native_observe(name: &str, cancel: &AtomicBool) -> TargetObservation {
    #[cfg(target_os = "linux")]
    return linux::observe(name, cancel);
    #[cfg(target_os = "macos")]
    return macos::observe(name, cancel);
    #[cfg(windows)]
    return windows::observe(name, cancel);
}

fn canceled(cancel: &AtomicBool) -> Result<(), ConfigError> {
    if cancel.load(Ordering::Acquire) {
        Err(ConfigError("canceled"))
    } else {
        Ok(())
    }
}

pub(crate) fn valid_name(name: &str) -> bool {
    let limit = if cfg!(windows) { 32 } else { 15 };
    if name.is_empty()
        || name.len() > limit
        || matches!(name, "." | "..")
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_=+.-".contains(&byte))
    {
        return false;
    }
    #[cfg(windows)]
    {
        if name.starts_with('.') || name.ends_with('.') {
            return false;
        }
        let reserved = |value: &str| {
            let upper = value.to_ascii_uppercase();
            matches!(upper.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || (upper.len() == 4
                    && (upper.starts_with("COM") || upper.starts_with("LPT"))
                    && matches!(upper.as_bytes()[3], b'1'..=b'9'))
        };
        if reserved(name)
            || name
                .rsplit_once('.')
                .is_some_and(|(base, _)| reserved(base))
        {
            return false;
        }
    }
    true
}

#[cfg(any(unix, test))]
fn fingerprint(domain: &[u8], value: &[u8]) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(value);
    format!("{:x}", hash.finalize())
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_target.rs"]
mod tests;
