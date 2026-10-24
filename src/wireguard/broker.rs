//! Unified protected WireGuard broker boundary.
//!
//! The desktop client freezes a complete read-only plan and transfers only
//! the reviewed configuration bytes and digests to a platform broker.  A
//! broker must authenticate the native caller, obtain a one-shot execution
//! permit, independently observe the target, and return a receipt.  This
//! module deliberately keeps those requirements explicit so a platform
//! implementation cannot fall back to `sudo`, process elevation, or a path
//! lookup as authorization.

use sha2::{Digest, Sha256};

use super::configuration::ConfigError;
use super::execution_config::ExecutionConfig;
use super::inspection::ConfigBinding;
use super::target::TargetState;
use super::tunnel::{Action, TunnelPlan};
use crate::config::AppPaths;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokerExecutionRequest {
    pub request_id: String,
    pub plan_sha256: String,
    pub target_scope_sha256: String,
    pub action: Action,
    pub logical_name: String,
    pub config: ConfigBinding,
    pub config_bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrokerReceipt {
    pub operation_id: String,
    pub target_state: TargetState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BrokerStatusProjection {
    pub state: &'static str,
    pub installation: &'static str,
    pub approval: &'static str,
    pub protocol: &'static str,
    pub authentication: &'static str,
    pub execution: &'static str,
}

/// Return the platform-native broker observation.  Unknown and missing
/// services are represented explicitly and never become an execution permit.
#[allow(clippy::needless_return)]
pub(crate) fn status() -> BrokerStatusProjection {
    #[cfg(target_os = "macos")]
    {
        let projection = super::macos_broker::observe().bridge_projection();
        return normalize_status(
            projection.state,
            projection.installation,
            projection.approval,
            projection.protocol,
            projection.authentication,
            projection.execution,
            false,
        );
    }
    #[cfg(target_os = "linux")]
    {
        let projection = super::linux_broker::status();
        return normalize_status(
            projection.state,
            projection.installation,
            projection.authorization,
            projection.transport,
            projection.authentication,
            projection.execution,
            true,
        );
    }
    #[cfg(windows)]
    {
        let projection = super::windows_broker::status();
        return normalize_status(
            projection.state,
            projection.installation,
            projection.approval,
            projection.protocol,
            projection.authentication,
            projection.execution,
            true,
        );
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        BrokerStatusProjection {
            state: "unsupported",
            installation: "not_installed",
            approval: "not_requested",
            protocol: "unsupported",
            authentication: "unavailable",
            execution: "unavailable",
        }
    }
}

/// Convert the platform broker's private observation vocabulary into the
/// versioned `wireguard.bridge.status` vocabulary consumed by desktop.  The
/// native services intentionally use transport-specific values (`dbus-system`,
/// `unix_socket`, `named_pipe`) and lifecycle states such as `running`; leaking
/// those values makes a valid installed broker fail desktop's strict decoder
/// (or, worse, lets the UI infer readiness from an implementation detail).
fn normalized_state(value: &str) -> &'static str {
    match value {
        "unsupported" => "unsupported",
        "unavailable" => "unavailable",
        // A successful native observation is represented as `observed` even
        // when the service is stopped or a later authorization gate is still
        // pending.  The individual facts below remain fail-closed.
        _ => "observed",
    }
}

fn normalized_installation(value: &str) -> &'static str {
    match value {
        "not_installed" => "not_installed",
        "installed" => "installed",
        _ => "unknown",
    }
}

fn normalized_protocol(value: &str) -> &'static str {
    match value {
        // These are the only fixed native transports currently implemented.
        "dbus-system" | "unix_socket" | "named_pipe" | "compatible" => "compatible",
        "incompatible" => "incompatible",
        "unsupported" => "unsupported",
        _ => "unknown",
    }
}

fn normalized_authentication(value: &str) -> &'static str {
    match value {
        "authenticated" | "kernel_peer" | "token_sid" => "authenticated",
        "unauthenticated" => "unauthenticated",
        "unavailable" => "unavailable",
        _ => "unknown",
    }
}

fn normalized_execution(value: &str, available_is_ready: bool) -> &'static str {
    match value {
        "ready" => "ready",
        // macOS's current observation only proves that an authenticated
        // socket is present.  It does not prove per-operation authorization;
        // keep that gate visibly blocked until the native approval contract
        // is implemented.
        "available" if available_is_ready => "ready",
        "available" => "not_ready",
        "not_authorized" => "not_authorized",
        "not_ready" => "not_ready",
        _ => "unavailable",
    }
}

fn normalized_approval(value: &str, observed: bool) -> &'static str {
    if !observed {
        return "not_requested";
    }
    match value {
        "approved" | "authorized" => "approved",
        "pending" => "pending",
        "not_requested" => "not_requested",
        _ => "unknown",
    }
}

fn normalize_status(
    state: &str,
    installation: &str,
    approval: &str,
    protocol: &str,
    authentication: &str,
    execution: &str,
    available_is_ready: bool,
) -> BrokerStatusProjection {
    let observed = state != "unsupported" && state != "unavailable";
    BrokerStatusProjection {
        state: normalized_state(state),
        installation: normalized_installation(installation),
        approval: normalized_approval(approval, observed),
        protocol: if observed {
            normalized_protocol(protocol)
        } else {
            "unsupported"
        },
        authentication: normalized_authentication(authentication),
        execution: normalized_execution(execution, available_is_ready),
    }
}

/// Dispatch an exact reviewed request to the platform broker.
#[allow(clippy::needless_return)]
pub(crate) fn execute(request: BrokerExecutionRequest) -> Result<BrokerReceipt, ConfigError> {
    validate_request(&request)?;
    #[cfg(target_os = "macos")]
    {
        return super::macos_broker::execute(&request);
    }
    #[cfg(target_os = "linux")]
    {
        return super::linux_broker::execute(&request);
    }
    #[cfg(windows)]
    {
        return super::windows_broker::execute(&request);
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        Err(ConfigError("wireguard_execution_bridge_required"))
    }
}

/// Build a broker request from the exact frozen plan. The source file is read
/// while the desktop process still has ordinary user authority; the native
/// broker receives bytes and bindings, never a user-controlled path.
pub(crate) fn execute_reviewed(
    _paths: &AppPaths,
    original_request_id: &str,
    config_path: &Path,
    plan: &TunnelPlan,
) -> Result<BrokerReceipt, ConfigError> {
    let binding = plan
        .binding
        .clone()
        .ok_or(ConfigError("wireguard_config_unavailable"))?;
    if plan.config.path != config_path {
        return Err(ConfigError("wireguard_plan_stale"));
    }
    let config = ExecutionConfig::from_source(config_path, &binding)?;
    let plan_bytes =
        serde_json::to_vec(plan).map_err(|_| ConfigError("wireguard_execution_invalid"))?;
    let logical_name = plan
        .config
        .path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
        .to_string();
    let target_scope_sha256 = {
        #[cfg(target_os = "linux")]
        {
            super::target::scope_digest_for_broker(&logical_name)?.to_string()
        }
        #[cfg(not(target_os = "linux"))]
        {
            let target_bytes = serde_json::to_vec(&plan.target)
                .map_err(|_| ConfigError("wireguard_execution_invalid"))?;
            digest(&target_bytes)
        }
    };
    let request = BrokerExecutionRequest {
        request_id: digest(original_request_id.as_bytes()),
        plan_sha256: digest(&plan_bytes),
        target_scope_sha256,
        action: plan.action,
        logical_name,
        config: binding,
        config_bytes: config.as_bytes().to_vec(),
    };
    execute(request)
}

fn validate_request(request: &BrokerExecutionRequest) -> Result<(), ConfigError> {
    if !valid_digest(&request.request_id)
        || !valid_digest(&request.plan_sha256)
        || !valid_digest(&request.target_scope_sha256)
        || !super::target::valid_name(&request.logical_name)
        || request.config_bytes.is_empty()
        || request.config_bytes.len() > 1024 * 1024
        || !valid_digest(&request.config.file_identity)
        || !valid_digest(&request.config.content_sha256)
        || !super::validation::public_key(&request.config.public_key)
    {
        return Err(ConfigError("wireguard_execution_invalid"));
    }
    let digest = format!("{:x}", Sha256::digest(&request.config_bytes));
    if digest != request.config.content_sha256 {
        return Err(ConfigError("wireguard_config_changed"));
    }
    Ok(())
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn digest(value: &[u8]) -> String {
    format!("{:x}", Sha256::digest(value))
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_broker.rs"]
mod tests;

#[cfg(test)]
mod projection_tests {
    use super::*;

    #[test]
    fn linux_native_ready_status_matches_desktop_contract() {
        let projection = normalize_status(
            "ready",
            "installed",
            "authorized",
            "dbus-system",
            "authenticated",
            "ready",
            true,
        );
        assert_eq!(projection.state, "observed");
        assert_eq!(projection.installation, "installed");
        assert_eq!(projection.approval, "approved");
        assert_eq!(projection.protocol, "compatible");
        assert_eq!(projection.authentication, "authenticated");
        assert_eq!(projection.execution, "ready");
    }

    #[test]
    fn missing_native_service_remains_unavailable() {
        let projection = normalize_status(
            "unavailable",
            "not_installed",
            "unavailable",
            "dbus-system",
            "unavailable",
            "unavailable",
            true,
        );
        assert_eq!(projection.state, "unavailable");
        assert_eq!(projection.installation, "not_installed");
        assert_eq!(projection.approval, "not_requested");
        assert_eq!(projection.protocol, "unsupported");
        assert_eq!(projection.authentication, "unavailable");
        assert_eq!(projection.execution, "unavailable");
    }

    #[test]
    fn macos_socket_observation_does_not_claim_authorization() {
        let projection = normalize_status(
            "running",
            "installed",
            "not_requested",
            "unix_socket",
            "kernel_peer",
            "available",
            false,
        );
        assert_eq!(projection.state, "observed");
        assert_eq!(projection.protocol, "compatible");
        assert_eq!(projection.authentication, "authenticated");
        assert_eq!(projection.approval, "not_requested");
        assert_eq!(projection.execution, "not_ready");
    }
}
