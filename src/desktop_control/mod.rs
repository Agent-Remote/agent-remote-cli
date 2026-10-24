//! Versioned, bounded desktop operations. Human CLI output is never a wire format.

mod account_defaults;
mod account_import;
mod accounts;
mod command_diagnostics;
mod credentials;
mod device;
mod device_code;
mod device_local_plan;
mod device_local_status;
mod diagnostics;
mod ego_browser_binding;
mod ego_browser_claim;
mod ego_browser_delete;
mod ego_browser_requests;
mod ego_browser_status;
mod login;
mod logout;
mod mutagen_environment;
mod nodes;
mod port_forward;
mod queries;
mod runtime_recovery;
mod session_creation;
mod session_delete;
mod session_stop;
mod setup;
mod skill_mutation;
mod skill_retry;
mod sync;
mod transport;
mod wireguard;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub use transport::run_stdio;

const VERSION: u32 = 1;

/// Only a standalone flag enters the machine protocol; state selection uses
/// AGENT_REMOTE_HOME, just as normal CLI invocations do.
pub fn requested() -> bool {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    args.len() == 1 && args[0] == "--desktop-control"
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol_version: u32,
    request_id: String,
    method: String,
    /// Request an optional progress stream before the terminal response.
    ///
    /// This is deliberately opt-in so existing callers continue to receive
    /// exactly one JSONL record. Unknown request fields remain rejected by
    /// `deny_unknown_fields`.
    #[serde(default)]
    stream_events: bool,
    params: Value,
}

#[derive(Serialize)]
struct Failure {
    code: &'static str,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    http_status: Option<u16>,
}

impl Failure {
    fn new(code: &'static str) -> Self {
        Self {
            code,
            retryable: false,
            http_status: None,
        }
    }

    fn api(error: crate::api::ApiError) -> Self {
        let http_status = error.status_code();
        let code = match http_status {
            Some(401) => "authentication_required",
            Some(403) => "permission_denied",
            Some(429) => "rate_limited",
            _ => "server_unavailable",
        };
        Self {
            code,
            retryable: http_status.is_none_or(|status| status == 429 || status >= 500),
            http_status,
        }
    }
}

fn error_response(request_id: Option<&str>, failure: Failure) -> Value {
    json!({"protocol_version": VERSION, "request_id": request_id,
        "type": "error", "phase": "failed", "error": failure})
}

async fn handle(bytes: &[u8]) -> Value {
    let request = match serde_json::from_slice::<Request>(bytes) {
        Ok(request) if valid_id(&request.request_id) => request,
        _ => return error_response(None, Failure::new("invalid_request")),
    };
    if request.protocol_version != VERSION {
        return error_response(
            Some(&request.request_id),
            Failure::new("unsupported_version"),
        );
    }
    let mutation = matches!(
        request.method.as_str(),
        "login.password"
            | "login.device_code"
            | "logout"
            | "setup.local"
            | "wireguard.config.apply"
            | "accounts.default.set"
            | "accounts.default.clear"
            | "accounts.create"
            | "accounts.bind"
            | "accounts.verify"
            | "accounts.disable"
            | "credentials.create"
            | "credentials.bind"
            | "credentials.unbind"
            | "accounts.import.apply"
            | "accounts.import.validate"
            | "accounts.import.forget"
            | "accounts.runtime_recovery.apply"
            | "accounts.runtime_recovery.forget"
            | "sync.ensure"
            | "sync.pause"
            | "sync.resume"
            | "sync.resolve"
            | "sync.reset"
            | "sync.recovery.apply"
            | "mutagen.environment.apply"
            | "sessions.create"
            | "sessions.stop"
            | "sessions.delete"
            | "port_forwards.create"
            | "port_forwards.stop"
            | "port_forwards.reconnect"
            | "wireguard.tunnel.apply"
            | "skills.change"
            | "skills.retry.control"
            | "device.revoke"
            | "device.rotate_token"
            | "ego_browser.request.cancel"
            | "ego_browser.binding.control"
            | "ego_browser.delete.control"
            | "ego_browser.claim.control"
            | "doctor.repair"
            | "deps.repair"
    );
    let deadline = match request.method.as_str() {
        "login.device_code" => 1950,
        _ if mutation => 120,
        _ => 75,
    };
    let result = tokio::time::timeout(std::time::Duration::from_secs(deadline), async {
        if request.method.starts_with("accounts.runtime_recovery.") {
            runtime_recovery::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "sessions.create"
                | "sessions.create.request"
                | "sessions.stop"
                | "sessions.stop.request"
                | "sessions.stop.status"
                | "sessions.delete"
                | "sessions.delete.request"
                | "sessions.delete.status"
                | "port_forwards.list"
                | "port_forwards.create"
                | "port_forwards.stop"
                | "port_forwards.reconnect"
        ) {
            if request.method.starts_with("sessions.stop") {
                session_stop::execute(&request).await
            } else if request.method.starts_with("sessions.delete") {
                session_delete::execute(&request).await
            } else if request.method.starts_with("port_forwards.") {
                port_forward::execute(&request).await
            } else {
                session_creation::execute(&request).await
            }
        } else if request.method.starts_with("accounts.import.") {
            account_import::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "mutagen.environment.preview" | "mutagen.environment.apply"
        ) {
            mutagen_environment::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "sync.status"
                | "sync.ensure"
                | "sync.pause"
                | "sync.resume"
                | "sync.resolve"
                | "sync.reset"
                | "sync.recovery.preview"
                | "sync.recovery.apply"
        ) {
            sync::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "accounts.default.get" | "accounts.default.set" | "accounts.default.clear"
        ) {
            account_defaults::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "accounts.create"
                | "accounts.status"
                | "accounts.bind"
                | "accounts.verify"
                | "accounts.disable"
        ) {
            accounts::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "credentials.create" | "credentials.bind" | "credentials.unbind"
        ) {
            credentials::execute(&request).await
        } else if request.method == "login.password" {
            login::password(&request).await
        } else if request.method == "login.device_code" {
            device_code::execute(&request).await
        } else if request.method == "logout" {
            logout::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "device.status" | "device.revoke" | "device.rotate_token"
        ) {
            device::execute(&request).await
        } else if request.method == "device.local.status" {
            device_local_status::execute(&request).await
        } else if request.method == "device.local.plan" {
            device_local_plan::execute(&request).await
        } else if request.method == "ego_browser.status" {
            ego_browser_status::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "ego_browser.requests"
                | "ego_browser.request.cancel"
                | "ego_browser.binding.plan"
                | "ego_browser.binding.control"
                | "ego_browser.delete.plan"
                | "ego_browser.delete.control"
                | "ego_browser.candidates"
                | "ego_browser.claim.plan"
                | "ego_browser.claim.control"
        ) {
            if request.method.starts_with("ego_browser.claim.") {
                ego_browser_claim::execute(&request).await
            } else if request.method.starts_with("ego_browser.binding.") {
                ego_browser_binding::execute(&request).await
            } else if request.method.starts_with("ego_browser.delete.") {
                ego_browser_delete::execute(&request).await
            } else {
                ego_browser_requests::execute(&request).await
            }
        } else if request.method == "nodes.list" {
            nodes::execute(&request).await
        } else if request.method == "skills.change" {
            skill_mutation::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "skills.retry.plan" | "skills.retry.control"
        ) {
            skill_retry::execute(&request).await
        } else if request.method == "setup.local" {
            setup::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "wireguard.config.plan"
                | "wireguard.config.apply"
                | "wireguard.check"
                | "wireguard.status"
                | "wireguard.bridge.status"
                | "wireguard.tunnel.plan"
                | "wireguard.tunnel.apply"
        ) {
            wireguard::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "diagnostics.inspect" | "dependencies.inspect"
        ) {
            diagnostics::execute(&request).await
        } else if matches!(
            request.method.as_str(),
            "status.inspect"
                | "doctor.inspect"
                | "doctor.repair"
                | "deps.inspect"
                | "deps.repair"
                | "ssh.inspect"
        ) {
            command_diagnostics::execute(&request).await
        } else {
            queries::execute(&request).await
        }
    })
    .await
    .unwrap_or({
        Err(Failure {
            code: if request.method == "logout" {
                "logout_outcome_unknown"
            } else if request.method == "setup.local" {
                "setup_outcome_unknown"
            } else if request.method == "wireguard.config.apply" {
                "wireguard_outcome_unknown"
            } else if request.method == "wireguard.tunnel.apply" {
                "timeout"
            } else if matches!(
                request.method.as_str(),
                "accounts.default.set" | "accounts.default.clear"
            ) {
                "default_outcome_unknown"
            } else if matches!(
                request.method.as_str(),
                "accounts.create" | "accounts.bind" | "accounts.verify" | "accounts.disable"
            ) {
                "account_outcome_unknown"
            } else if matches!(
                request.method.as_str(),
                "credentials.create" | "credentials.bind" | "credentials.unbind"
            ) {
                "credential_outcome_unknown"
            } else if request.method.starts_with("accounts.import.") && mutation {
                "account_import_outcome_unknown"
            } else if request.method.starts_with("accounts.runtime_recovery.") && mutation {
                "runtime_recovery_outcome_unknown"
            } else if request.method == "mutagen.environment.apply" {
                "sync_mutagen_environment_outcome_unknown"
            } else if matches!(request.method.as_str(), "doctor.repair" | "deps.repair") {
                "repair_outcome_unknown"
            } else if request.method == "sessions.create" {
                "SESSION_CREATE_SUBMISSION_UNKNOWN"
            } else if request.method == "sessions.stop" {
                "SESSION_STOP_SUBMISSION_UNKNOWN"
            } else if request.method == "sessions.delete" {
                "SESSION_DELETE_SUBMISSION_UNKNOWN"
            } else if request.method == "port_forwards.create" {
                "PORT_FORWARD_SUBMISSION_UNKNOWN"
            } else if request.method == "port_forwards.reconnect" {
                "PORT_FORWARD_RECONNECT_UNKNOWN"
            } else if request.method == "port_forwards.stop" {
                "PORT_FORWARD_OUTCOME_UNKNOWN"
            } else if request.method == "skills.change" {
                "skill_outcome_unknown"
            } else if request.method == "skills.retry.control" {
                "skill_retry_outcome_unknown"
            } else if matches!(
                request.method.as_str(),
                "device.revoke" | "device.rotate_token"
            ) {
                "device_outcome_unknown"
            } else if request.method == "ego_browser.request.cancel" {
                "ego_browser_request_outcome_unknown"
            } else if request.method == "ego_browser.binding.control" {
                "ego_browser_binding_outcome_unknown"
            } else if request.method == "ego_browser.delete.control" {
                "ego_browser_delete_outcome_unknown"
            } else if request.method == "ego_browser.claim.control" {
                "ego_browser_claim_outcome_unknown"
            } else if request.method.starts_with("sync.") && mutation {
                "sync_outcome_unknown"
            } else if mutation {
                "login_outcome_unknown"
            } else {
                "timeout"
            },
            retryable: !mutation,
            http_status: None,
        })
    });
    match result {
        Ok(value) => json!({"protocol_version": VERSION, "request_id": request.request_id,
            "type": "result", "phase": "completed", "result": value}),
        Err(failure) => error_response(Some(&request.request_id), failure),
    }
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
}
