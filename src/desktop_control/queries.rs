use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::ApiClient,
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request, VERSION};

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SessionFilter {
    #[serde(default)]
    tool_type: Option<String>,
    #[serde(default)]
    statuses: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillListRequest {
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    effective: bool,
    #[serde(default)]
    include_system: bool,
}

/// Exact read-only selector for the dedicated Skill details view.  The
/// identifier is either a canonical UUID or the same lower-case library name
/// accepted by `skill info`; scope is explicit and mutually exclusive.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillInfoRequest {
    skill: String,
    #[serde(default)]
    tool: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillStateConflictsRequest {
    account_id: String,
    scope: String,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default = "default_conflict_limit")]
    limit: u16,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    migration_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillStateListRequest {
    account_id: String,
    scope: String,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default = "default_conflict_limit")]
    limit: u16,
    #[serde(default)]
    cursor: Option<String>,
    #[serde(default)]
    pending_cursor: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillStateInfoRequest {
    checkpoint_id: String,
}

/// Bounded, metadata-only state diff query. A current selector and an
/// immutable checkpoint are mutually exclusive; checkpoint cursors are opaque
/// API path cursors and are validated before any configuration or credential
/// lookup occurs.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SkillStateDiffRequest {
    #[serde(default)]
    account_id: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    skill: Option<String>,
    #[serde(default)]
    checkpoint_id: Option<String>,
    #[serde(default = "default_diff_limit")]
    limit: u16,
    #[serde(default)]
    cursor: Option<String>,
}

fn default_conflict_limit() -> u16 {
    100
}

fn default_diff_limit() -> u16 {
    100
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    // Validate the entire operation before touching configuration or credentials.
    let skill_filter = if request.method == "skills.list" {
        let input: SkillListRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if input
            .tool
            .as_deref()
            .is_some_and(|tool| !super::valid_id(tool))
            || input
                .account_id
                .as_deref()
                .is_some_and(|account| uuid::Uuid::parse_str(account).is_err())
            || input.tool.is_some() && input.account_id.is_some()
        {
            return Err(Failure::new("invalid_params"));
        }
        Some(input)
    } else {
        None
    };
    let skill_info = if request.method == "skills.info" {
        let input: SkillInfoRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let valid_identifier =
            uuid::Uuid::parse_str(&input.skill).is_ok_and(|id| id.to_string() == input.skill)
                || super::valid_id(&input.skill)
                    && input.skill.len() <= 64
                    && input.skill.bytes().all(|byte| {
                        byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                    });
        if !valid_identifier
            || input
                .tool
                .as_deref()
                .is_some_and(|tool| !super::valid_id(tool))
            || input
                .account_id
                .as_deref()
                .is_some_and(|account| uuid::Uuid::parse_str(account).is_err())
            || input.tool.is_some() && input.account_id.is_some()
        {
            return Err(Failure::new("invalid_params"));
        }
        Some(input)
    } else {
        None
    };
    let skill_state_conflicts = if request.method == "skills.state.conflicts" {
        let input: SkillStateConflictsRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let scope = match input.scope.as_str() {
            "item" | "account-directory" => input.scope.as_str(),
            _ => return Err(Failure::new("invalid_params")),
        };
        if uuid::Uuid::parse_str(&input.account_id).is_err()
            || input
                .skill
                .as_deref()
                .is_some_and(|skill| uuid::Uuid::parse_str(skill).is_err())
            || (scope == "account-directory" && input.skill.is_some())
            || (scope == "item" && input.skill.is_none())
            || !(1..=200).contains(&input.limit)
            || input
                .cursor
                .as_deref()
                .is_some_and(|cursor| uuid::Uuid::parse_str(cursor).is_err())
            || input
                .migration_cursor
                .as_deref()
                .is_some_and(|cursor| uuid::Uuid::parse_str(cursor).is_err())
        {
            return Err(Failure::new("invalid_params"));
        }
        Some(input)
    } else {
        None
    };
    let skill_state_list = if request.method == "skills.state.list" {
        let input: SkillStateListRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let scope = match input.scope.as_str() {
            "item" | "account-directory" => input.scope.as_str(),
            _ => return Err(Failure::new("invalid_params")),
        };
        if uuid::Uuid::parse_str(&input.account_id).is_err()
            || input
                .skill
                .as_deref()
                .is_some_and(|skill| uuid::Uuid::parse_str(skill).is_err())
            || (scope == "account-directory" && input.skill.is_some())
            || (scope == "item" && input.skill.is_none())
            || !(1..=200).contains(&input.limit)
            || input
                .cursor
                .as_deref()
                .is_some_and(|cursor| uuid::Uuid::parse_str(cursor).is_err())
            || input
                .pending_cursor
                .as_deref()
                .is_some_and(|cursor| uuid::Uuid::parse_str(cursor).is_err())
        {
            return Err(Failure::new("invalid_params"));
        }
        Some(input)
    } else {
        None
    };
    let skill_state_info = if request.method == "skills.state.info" {
        let input: SkillStateInfoRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if uuid::Uuid::parse_str(&input.checkpoint_id).is_err()
            || uuid::Uuid::parse_str(&input.checkpoint_id)
                .is_ok_and(|id| id.to_string() != input.checkpoint_id)
        {
            return Err(Failure::new("invalid_params"));
        }
        Some(input)
    } else {
        None
    };
    let skill_state_diff = if request.method == "skills.state.diff" {
        let input: SkillStateDiffRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !(1..=500).contains(&input.limit)
            || input.cursor.as_deref().is_some_and(|cursor| {
                cursor.is_empty() || cursor.len() > 16384 || cursor.chars().any(char::is_control)
            })
            || input.checkpoint_id.as_deref().is_some_and(|id| {
                uuid::Uuid::parse_str(id).is_err()
                    || uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() != id)
            })
        {
            return Err(Failure::new("invalid_params"));
        }
        let checkpoint_mode = input.checkpoint_id.is_some();
        if checkpoint_mode {
            if input.account_id.is_some() || input.scope.is_some() || input.skill.is_some() {
                return Err(Failure::new("invalid_params"));
            }
        } else {
            let account = input.account_id.as_deref();
            let scope = input.scope.as_deref();
            if account.is_none()
                || account.is_some_and(|value| uuid::Uuid::parse_str(value).is_err())
                || !matches!(scope, Some("item") | Some("account-directory"))
                || (scope == Some("item") && input.skill.is_none())
                || (scope == Some("account-directory") && input.skill.is_some())
                || input
                    .skill
                    .as_deref()
                    .is_some_and(|skill| uuid::Uuid::parse_str(skill).is_err())
            {
                return Err(Failure::new("invalid_params"));
            }
        }
        Some(input)
    } else {
        None
    };
    let filter = match request.method.as_str() {
        "sessions.list" => {
            let filter: SessionFilter = serde_json::from_value(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            if filter
                .tool_type
                .as_deref()
                .is_some_and(|tool| !super::valid_id(tool))
                || filter.statuses.len() > 16
                || filter
                    .statuses
                    .iter()
                    .any(|status| !super::valid_id(status))
            {
                return Err(Failure::new("invalid_params"));
            }
            Some(filter)
        }
        "capabilities" | "context" | "accounts.list" | "credentials.list" | "skills.info"
        | "nodes.list" => {
            serde_json::from_value::<Empty>(request.params.clone())
                .map_err(|_| Failure::new("invalid_params"))?;
            None
        }
        "skills.list" => None,
        "skills.state.conflicts"
        | "skills.state.list"
        | "skills.state.info"
        | "skills.state.diff" => None,
        _ => return Err(Failure::new("unsupported_method")),
    };
    if request.method == "capabilities" {
        return Ok(
            json!({"protocol_version": VERSION, "cli_version": crate::cli::VERSION,
            "platform": std::env::consts::OS,
            "attachment_transfer": {
                "supported": true,
                "protocol_version": 1,
                "max_bytes": 268435456,
                "max_entries": 32
            },
            "terminal_operations": [
                {"method":"accounts.binding.attach", "protocol_version":1},
                {"method":"sessions.attach", "protocol_version":1},
                {"method":"fclaude run", "protocol_version":1},
                {"method":"fclaude new", "protocol_version":1},
                {"method":"fclaude list", "protocol_version":1},
                {"method":"agent-remote doctor", "protocol_version":1},
                {"method":"agent-remote ssh check", "protocol_version":1},
                {"method":"agent-remote node install", "protocol_version":1},
                {"method":"agent-remote device install", "protocol_version":1},
                {"method":"agent-remote device uninstall", "protocol_version":1},
                {"method":"agent-remote device status", "protocol_version":1},
                {"method":"agent-remote device launch", "protocol_version":1},
                {"method":"agent-remote device diagnose", "protocol_version":1},
                {"method":"agent-remote skill state prune", "protocol_version":1, "effect":"write", "credential":"stored", "confirmation":"exact_request", "workflow":"skill_state_prune"},
                {"method":"agent-remote skill state reset", "protocol_version":1, "effect":"write", "credential":"stored", "confirmation":"exact_request", "workflow":"skill_state_reset"},
                {"method":"agent-remote skill state migrate", "protocol_version":1, "effect":"write", "credential":"stored", "confirmation":"exact_request", "workflow":"skill_state_migrate"},
                {"method":"agent-remote skill state resolve", "protocol_version":1, "effect":"write", "credential":"stored", "confirmation":"exact_request", "workflow":"skill_state_resolve"},
                {"method":"agent-remote skill state restore", "protocol_version":1, "effect":"write", "credential":"stored", "confirmation":"exact_request", "workflow":"skill_state_restore"},
                {"method":"agent-remote skill state list", "protocol_version":1},
                {"method":"agent-remote skill state conflicts", "protocol_version":1, "effect":"read", "credential":"user", "workflow":"skill_state_conflicts"},
                {"method":"agent-remote skill state info", "protocol_version":1},
                {"method":"agent-remote skill state diff", "protocol_version":1},
                {"method":"agent-remote skill state export", "protocol_version":1},
                {"method":"agent-remote skill add", "protocol_version":1},
                {"method":"agent-remote skill update", "protocol_version":1},
                {"method":"agent-remote skill enable", "protocol_version":1},
                {"method":"agent-remote skill disable", "protocol_version":1},
                {"method":"agent-remote skill pin", "protocol_version":1},
                {"method":"agent-remote skill unpin", "protocol_version":1},
                {"method":"agent-remote skill inherit", "protocol_version":1},
                {"method":"agent-remote skill remove", "protocol_version":1},
                {"method":"agent-remote skill rollback", "protocol_version":1},
                {"method":"agent-remote skill check", "protocol_version":1},
                {"method":"agent-remote skill info", "protocol_version":1},
                {"method":"agent-remote skill status", "protocol_version":1},
                {"method":"agent-remote skill list", "protocol_version":1},
                {"method":"agent-remote skill retry", "protocol_version":1},
                {"method":"agent-remote ego-browser setup", "protocol_version":1},
                {"method":"agent-remote ego-browser connect", "protocol_version":1},
                {"method":"agent-remote ego-browser repair", "protocol_version":1},
                {"method":"agent-remote ego-browser upgrade", "protocol_version":1},
                {"method":"agent-remote ego-browser remove", "protocol_version":1},
                {"method":"agent-remote ego-browser forget-this-mac", "protocol_version":1},
                {"method":"agent-remote ego-browser forget", "protocol_version":1},
                {"method":"agent-remote ego-browser re-enroll", "protocol_version":1},
                {"method":"agent-remote ego-browser device-rotate", "protocol_version":1},
                {"method":"agent-remote ego-browser switch-server", "protocol_version":1},
                {"method":"agent-remote ego-browser register", "protocol_version":1},
                {"method":"agent-remote ego-browser status", "protocol_version":1},
                {"method":"agent-remote ego-browser list", "protocol_version":1},
                {"method":"agent-remote ego-browser requests", "protocol_version":1},
                {"method":"agent-remote ego-browser cancel-request", "protocol_version":1},
                {"method":"agent-remote ego-browser claim", "protocol_version":1},
                {"method":"agent-remote ego-browser pause", "protocol_version":1},
                {"method":"agent-remote ego-browser resume", "protocol_version":1},
                {"method":"agent-remote ego-browser stop", "protocol_version":1},
                {"method":"agent-remote ego-browser revoke", "protocol_version":1},
                {"method":"agent-remote ego-browser delete-device", "protocol_version":1},
                {"method":"agent-remote ego-browser device-delete", "protocol_version":1},
                {"method":"agent-remote ego-browser delete-binding", "protocol_version":1},
                {"method":"agent-remote ego-browser binding-delete", "protocol_version":1}
            ],
            "operations": [
                {"method": "capabilities", "effect": "read", "credential": "none"},
                {"method": "context", "effect": "read", "credential": "none"},
                {"method": "accounts.default.get", "effect": "read", "credential": "none"},
                {"method": "accounts.default.set", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.default.clear", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "accounts.create", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.status", "effect": "read", "credential": "device"},
                {"method": "accounts.bind", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.verify", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.disable", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.list", "effect": "read", "credential": "device"},
                {"method": "credentials.list", "effect": "read", "credential": "device"},
                {"method": "credentials.create", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "credentials.bind", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "credentials.unbind", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "skills.list", "effect": "read", "credential": "user"},
                {"method": "skills.info", "effect": "read", "credential": "user"},
                {"method": "skills.state.list", "effect": "read", "credential": "user"},
                {"method": "skills.state.conflicts", "effect": "read", "credential": "user"},
                {"method": "skills.state.info", "effect": "read", "credential": "user"},
                {"method": "skills.state.diff", "effect": "read", "credential": "user"},
                {"method": "skills.change", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "skills.retry.plan", "effect": "read", "credential": "user", "confirmation": ""},
                {"method": "skills.retry.control", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "accounts.import.discover", "effect": "read", "credential": "none"},
                {"method": "accounts.import.prepare", "effect": "read", "credential": "none"},
                {"method": "accounts.import.pending", "effect": "read", "credential": "none"},
                {"method": "accounts.import.validate", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.import.apply", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "accounts.import.status", "effect": "read", "credential": "device"},
                {"method": "accounts.import.forget", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "accounts.runtime_recovery.authority", "effect": "read", "credential": "user"},
                {"method": "accounts.runtime_recovery.inspect", "effect": "read", "credential": "user"},
                {"method": "accounts.runtime_recovery.apply", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "accounts.runtime_recovery.status", "effect": "read", "credential": "user"},
                {"method": "accounts.runtime_recovery.pending", "effect": "read", "credential": "none"},
                {"method": "accounts.runtime_recovery.forget", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "sync.status", "effect": "read", "credential": "device"},
                {"method": "sync.recovery.preview", "effect": "read", "credential": "device"},
                {"method": "sync.recovery.apply", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sync.ensure", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sync.pause", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sync.resume", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sync.resolve", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sync.reset", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sessions.list", "effect": "read", "credential": "device"},
                {"method": "sessions.create", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sessions.create.request", "effect": "read", "credential": "device"},
                {"method": "sessions.stop", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sessions.stop.request", "effect": "read", "credential": "device"},
                {"method": "sessions.stop.status", "effect": "read", "credential": "device"},
                {"method": "sessions.delete", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "sessions.delete.request", "effect": "read", "credential": "device"},
                {"method": "sessions.delete.status", "effect": "read", "credential": "device"},
                {"method": "port_forwards.list", "effect": "read", "credential": "device"},
                {"method": "port_forwards.create", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "port_forwards.stop", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "port_forwards.reconnect", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "diagnostics.inspect", "effect": "read", "credential": "none"},
                {"method": "dependencies.inspect", "effect": "read", "credential": "none"},
                {"method": "status.inspect", "effect": "read", "credential": "none"},
                {"method": "doctor.inspect", "effect": "read", "credential": "none"},
                {"method": "doctor.repair", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "deps.inspect", "effect": "read", "credential": "none"},
                {"method": "deps.repair", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "ssh.inspect", "effect": "read", "credential": "none"},
                {"method": "mutagen.environment.preview", "effect": "read", "credential": "none"},
                {"method": "mutagen.environment.apply", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "setup.local", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "wireguard.config.plan", "effect": "read", "credential": "none"},
                {"method": "wireguard.config.apply", "effect": "write", "credential": "device", "confirmation": "exact_request"},
                {"method": "wireguard.check", "effect": "read", "credential": "none"},
                {"method": "wireguard.status", "effect": "read", "credential": "none"},
                {"method": "wireguard.bridge.status", "effect": "read", "credential": "none"},
                {"method": "wireguard.tunnel.plan", "effect": "read", "credential": "none"},
                {"method": "wireguard.tunnel.apply", "effect": "write", "credential": "none", "confirmation": "exact_request"},
                {"method": "login.password", "effect": "write", "credential": "password", "confirmation": "exact_request"},
                {"method": "login.device_code", "effect": "write", "credential": "browser", "confirmation": "exact_request"},
                {"method": "device.status", "effect": "read", "credential": "device"},
                {"method": "device.local.status", "effect": "read", "credential": "none"},
                {"method": "device.local.plan", "effect": "read", "credential": "none"},
                {"method": "device.revoke", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "device.rotate_token", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "ego_browser.status", "effect": "read", "credential": "user"},
                {"method": "ego_browser.candidates", "effect": "read", "credential": "user"},
                {"method": "ego_browser.claim.plan", "effect": "read", "credential": "user"},
                {"method": "ego_browser.claim.control", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "ego_browser.requests", "effect": "read", "credential": "user"},
                {"method": "ego_browser.request.cancel", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "ego_browser.binding.plan", "effect": "read", "credential": "user"},
                {"method": "ego_browser.binding.control", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "ego_browser.delete.plan", "effect": "read", "credential": "user"},
                {"method": "ego_browser.delete.control", "effect": "write", "credential": "user", "confirmation": "exact_request"},
                {"method": "nodes.list", "effect": "read", "credential": "user"},
                {"method": "logout", "effect": "write", "credential": "stored", "confirmation": "exact_request"}
            ]}),
        );
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if request.method == "context" {
        return Ok(
            json!({"home": paths.home(), "server_url": config.server_url,
            "active_device_id": config.active_device_id}),
        );
    }
    if request.method == "skills.list" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_filter.expect("validated skills.list input");
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let library = client
            .list_skill_catalog(
                &token,
                input.tool.as_deref(),
                input.account_id.as_deref(),
                input.effective,
                input.include_system,
            )
            .await
            .map_err(Failure::api)?;
        let items: Vec<_> = library
            .data
            .as_ref()
            .map(|library| {
                library
                    .items
                    .iter()
                    .map(|item| {
                        json!({
                            "id": item.id,
                            "name": item.name,
                            "removed": item.removed,
                            "default_enabled": item.default_enabled,
                            "default_revision_id": item.default_revision_id,
                            "effective": item.effective.as_ref().map(|rule| json!({
                                "enabled": rule.enabled,
                                "revision_id": rule.revision_id,
                                "eligible": rule.eligible,
                                "included": rule.included,
                                "exclusion_reason": rule.exclusion_reason,
                            })),
                            "project_discovery": item.project_discovery,
                            "model_loaded": item.model_loaded,
                            "revision_count": item.revisions.len(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let local_items: Vec<_> = library
            .data
            .as_ref()
            .map(|library| {
                library
                    .local_items
                    .iter()
                    .map(|item| {
                        json!({
                            "id": item.id,
                            "name": item.name,
                            "account_id": item.account_id,
                            "status": item.status,
                            "enabled": item.enabled,
                            "revision_id": item.default_revision_id,
                            "model_loaded": item.model_loaded,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        let generation = library.data.as_ref().map_or(0, |value| value.generation);
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "generation": generation,
            "items": items,
            "local_items": local_items,
        }));
    }
    if request.method == "skills.info" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_info.expect("validated skills.info input");
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let details = client
            .skill_info(
                &token,
                &input.skill,
                input.tool.as_deref(),
                input.account_id.as_deref(),
            )
            .await
            .map_err(Failure::api)?
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        // Deliberate metadata-only projection. Source locators, tracking,
        // revision metadata, paths, content and account credentials remain in
        // Rust/API and never cross the desktop-control boundary.
        let item = match details {
            crate::api::skills::SkillDetails::Library(value) => {
                let revisions = value
                    .revisions
                    .into_iter()
                    .map(|revision| {
                        json!({
                            "id": revision.id,
                            "number": revision.number,
                            "retained": revision.retained,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "kind": "library",
                    "id": value.id,
                    "name": value.name,
                    "removed": value.removed,
                    "epoch": value.epoch,
                    "default_enabled": value.default_enabled,
                    "default_revision_id": value.default_revision_id,
                    "revision_count": revisions.len(),
                    "revisions": revisions,
                    "effective": value.effective.as_ref().map(|rule| json!({
                        "enabled": rule.enabled,
                        "revision_id": rule.revision_id,
                        "eligible": rule.eligible,
                        "included": rule.included,
                        "exclusion_reason": rule.exclusion_reason,
                    })),
                    "project_discovery": value.project_discovery,
                    "model_loaded": value.model_loaded,
                })
            }
            crate::api::skills::SkillDetails::Local(value) => {
                let revisions = value
                    .revisions
                    .into_iter()
                    .map(|revision| {
                        json!({
                            "id": revision.id,
                            "number": revision.number,
                            "retained": revision.retained,
                        })
                    })
                    .collect::<Vec<_>>();
                json!({
                    "kind": "account_local",
                    "id": value.id,
                    "name": value.name,
                    "status": value.status,
                    "removed": value.status == "removed",
                    "account_id": value.account_id,
                    "default_revision_id": value.default_revision_id,
                    "source_checkpoint_id": value.source_checkpoint_id,
                    "revision_count": revisions.len(),
                    "revisions": revisions,
                    "effective": json!({
                        "enabled": value.effective.enabled,
                        "revision_id": value.effective.revision_id,
                        "eligible": value.effective.eligible,
                        "included": value.effective.included,
                        "exclusion_reason": value.effective.exclusion_reason,
                    }),
                    "model_loaded": value.model_loaded,
                })
            }
        };
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "selector": {"skill": input.skill, "tool": input.tool, "account_id": input.account_id},
            "item": item,
        }));
    }
    if request.method == "skills.state.conflicts" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_state_conflicts.expect("validated skills.state.conflicts input");
        let selector = crate::api::skill_state::StateSelector {
            account_id: input.account_id,
            scope: if input.scope == "item" {
                crate::api::skill_state::StateScope::Item
            } else {
                crate::api::skill_state::StateScope::AccountDirectory
            },
            skill: input.skill,
        };
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let publications = client
            .skill_publication_conflicts(&token, &selector, input.limit, input.cursor.as_deref())
            .await
            .map_err(Failure::api)?
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        let migrations = client
            .skill_migration_conflicts(
                &token,
                &selector,
                input.limit,
                input.migration_cursor.as_deref(),
            )
            .await
            .map_err(Failure::api)?
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        // The desktop receives only bounded conflict metadata. Saved branch
        // inputs, paths, digests, and resolution choices stay in the CLI/API.
        let publication_cursor = publications.next_cursor;
        let publications = publications
            .items
            .into_iter()
            .map(|value| {
                json!({
                    "id": value.id,
                    "attempt": value.attempt,
                    "status": value.status,
                    "reason": value.reason,
                })
            })
            .collect::<Vec<_>>();
        let migration_cursor = migrations.next_cursor;
        let migrations = migrations
            .items
            .into_iter()
            .map(|value| {
                json!({
                    "id": value.id,
                    "skill_id": value.skill_id,
                    "name": value.name,
                    "mode": value.mode,
                    "status": value.status,
                    "installation_epoch": value.installation_epoch,
                    "target_epoch": value.target_epoch,
                    "directory_epoch": value.directory_epoch,
                    "created_at": value.created_at,
                })
            })
            .collect::<Vec<_>>();
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "selector": selector,
            "publications": {"items": publications, "next_cursor": publication_cursor},
            "migrations": {"items": migrations, "next_cursor": migration_cursor},
        }));
    }
    if request.method == "skills.state.list" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_state_list.expect("validated skills.state.list input");
        let selector = crate::api::skill_state::StateSelector {
            account_id: input.account_id,
            scope: if input.scope == "item" {
                crate::api::skill_state::StateScope::Item
            } else {
                crate::api::skill_state::StateScope::AccountDirectory
            },
            skill: input.skill,
        };
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let checkpoints = client
            .skill_state_history(&token, &selector, input.limit, input.cursor.as_deref())
            .await
            .map_err(Failure::api)?
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        let pending = client
            .skill_state_pending(
                &token,
                &selector,
                input.limit,
                input.pending_cursor.as_deref(),
            )
            .await
            .map_err(Failure::api)?
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        // Keep the desktop boundary metadata-only. Paths, manifests, storage
        // diagnostics and retained content remain owned by the CLI/API.
        let checkpoint_items: Vec<_> = checkpoints
            .items
            .into_iter()
            .map(|item| {
                json!({
                    "id": item.id,
                    "account_id": item.account_id,
                    "scope": item.scope,
                    "state_id": item.state_id,
                    "skill_id": item.skill_id,
                    "origin": item.origin,
                    "revision_id": item.revision_id,
                    "installation_epoch": item.installation_epoch,
                    "state_epoch": item.state_epoch,
                    "directory_epoch": item.directory_epoch,
                    "current_state_epoch": item.current_state_epoch,
                    "current_directory_epoch": item.current_directory_epoch,
                    "parent_id": item.parent_id,
                    "content_digest": item.content_digest,
                    "retained": item.retained,
                    "is_head": item.is_head,
                    "invalid_skill_format": item.invalid_skill_format,
                    "source_session_reference_id": item.source_session_reference_id,
                    "finalization_id": item.finalization_id,
                    "finalization_status": item.finalization_status,
                    "storage_location": item.storage_location,
                    "created_at": item.created_at,
                })
            })
            .collect();
        let pending_items: Vec<_> = pending
            .items
            .into_iter()
            .map(|item| {
                json!({
                    "id": item.id,
                    "snapshot_id": item.snapshot_id,
                    "session_reference_id": item.session_reference_id,
                    "node_id": item.node_id,
                    "incoming_digest": item.incoming_digest,
                    "status": item.status,
                    "storage_location": item.storage_location,
                    "exportable_from_server": item.exportable_from_server,
                })
            })
            .collect();
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "selector": {
                "account_id": selector.account_id,
                "scope": selector.scope,
                "skill": selector.skill,
            },
            "checkpoints": {"items": checkpoint_items, "next_cursor": checkpoints.next_cursor},
            "pending": {"items": pending_items, "next_cursor": pending.next_cursor},
        }));
    }
    if request.method == "skills.state.info" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_state_info.expect("validated skills.state.info input");
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let response = client
            .skill_checkpoint(&token, &input.checkpoint_id)
            .await
            .map_err(Failure::api)?;
        let checkpoint = response.data.map(|item| {
            json!({
                "id": item.id,
                "account_id": item.account_id,
                "scope": item.scope,
                "state_id": item.state_id,
                "skill_id": item.skill_id,
                "origin": item.origin,
                "revision_id": item.revision_id,
                "installation_epoch": item.installation_epoch,
                "state_epoch": item.state_epoch,
                "directory_epoch": item.directory_epoch,
                "current_state_epoch": item.current_state_epoch,
                "current_directory_epoch": item.current_directory_epoch,
                "parent_id": item.parent_id,
                "content_digest": item.content_digest,
                "retained": item.retained,
                "is_head": item.is_head,
                "invalid_skill_format": item.invalid_skill_format,
                "source_session_reference_id": item.source_session_reference_id,
                "finalization_id": item.finalization_id,
                "finalization_status": item.finalization_status,
                "storage_location": item.storage_location,
                "created_at": item.created_at,
            })
        });
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "status": response.status,
            "checkpoint": checkpoint,
        }));
    }
    if request.method == "skills.state.diff" {
        let server = config
            .server_url
            .clone()
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let token = auth::load_user_token(&paths, &server)
            .await
            .map_err(|_| Failure::new("credential_unavailable"))?
            .ok_or_else(|| Failure::new("authentication_required"))?;
        let input = skill_state_diff.expect("validated skills.state.diff input");
        let client = ApiClient::new(server.clone())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let response = if let Some(checkpoint_id) = input.checkpoint_id.as_deref() {
            client
                .skill_checkpoint_diff(&token, checkpoint_id, input.limit, input.cursor.as_deref())
                .await
                .map_err(Failure::api)?
        } else {
            let selector = crate::api::skill_state::StateSelector {
                account_id: input.account_id.clone().expect("validated account_id"),
                scope: if input.scope.as_deref() == Some("item") {
                    crate::api::skill_state::StateScope::Item
                } else {
                    crate::api::skill_state::StateScope::AccountDirectory
                },
                skill: input.skill.clone(),
            };
            client
                .skill_current_diff(&token, &selector, input.limit)
                .await
                .map_err(Failure::api)?
        };
        let value = response
            .data
            .ok_or_else(|| Failure::new("server_unavailable"))?;
        // A diff is useful in the GUI only as a bounded review of changed
        // paths and metadata. File content, manifests and server paths stay
        // behind the CLI/API boundary.
        let changes = value
            .items
            .into_iter()
            .map(|change| {
                json!({
                    "path": change.path,
                    "base": project_diff_entry(change.base.as_ref()),
                    "current": project_diff_entry(change.current.as_ref()),
                })
            })
            .collect::<Vec<_>>();
        return Ok(json!({
            "context": {"home": paths.home(), "server_url": server, "active_device_id": config.active_device_id},
            "mode": if input.checkpoint_id.is_some() { "checkpoint" } else { "current" },
            "checkpoint_id": value.checkpoint_id,
            "base_kind": value.base_kind,
            "base_reference_id": value.base_reference_id,
            "base_tree_digest": value.base_tree_digest,
            "current_tree_digest": value.current_tree_digest,
            "items": changes,
            "next_cursor": value.next_cursor,
        }));
    }
    if config.server_url.is_none() || config.active_device_id.is_none() {
        return Err(Failure::new("authentication_required"));
    }
    let (server, device, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?;
    let context = json!({"home": paths.home(), "server_url": server, "active_device_id": device});
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    if request.method == "credentials.list" {
        let items = client
            .list_developer_credential_profiles(&token)
            .await
            .map_err(Failure::api)?;
        // Deliberate projection: profile identity and Git metadata are not
        // needed by the desktop inventory view and must not cross the control
        // boundary. Modes and timestamps are sufficient for review.
        let items: Vec<_> = items
            .into_iter()
            .map(|profile| {
                json!({
                    "id": profile.id,
                    "display_name": profile.display_name,
                    "status": profile.status,
                    "github_cli_mode": profile.github_cli_mode,
                    "ssh_mode": profile.ssh_mode,
                    "created_at": profile.created_at,
                    "updated_at": profile.updated_at
                })
            })
            .collect();
        return Ok(json!({"items": items, "context": context}));
    }
    if let Some(filter) = filter {
        let items = client
            .list_sessions(&token, filter.tool_type.as_deref(), &filter.statuses)
            .await
            .map_err(Failure::api)?;
        // Deliberate projections: future API additions must not expose new private data.
        let items: Vec<_> = items.into_iter().map(|s| json!({
            "id": s.id, "tool_type": s.tool_type, "tool_account_id": s.tool_account_id,
            "workspace_id": s.workspace_id, "workspace_local_path": s.workspace_local_path,
            "workspace_remote_path": s.workspace_remote_path, "node_id": s.node_id,
            "project_key": s.project_key, "status": s.status, "runtime_backend": s.runtime_backend,
            "runtime_resource_id": s.runtime_resource_id, "stop_task_id": s.stop_task_id,
            "skill_finalization_operation_id": s.skill_finalization_operation_id,
            "created_at": s.created_at, "updated_at": s.updated_at
        })).collect();
        Ok(json!({"items": items, "context": context}))
    } else {
        let items = client
            .list_tool_accounts(&token)
            .await
            .map_err(Failure::api)?;
        let items: Vec<_> = items
            .into_iter()
            .map(|a| {
                json!({
                    "id": a.id, "tool_type": a.tool_type, "display_name": a.display_name,
                    "status": a.status, "region_code": a.region_code, "timezone": a.timezone,
                    "locale": a.locale, "runtime_backend": a.runtime_backend
                })
            })
            .collect();
        Ok(json!({"items": items, "context": context}))
    }
}

fn project_diff_entry(entry: Option<&crate::skills::manifest::Entry>) -> Value {
    entry
        .map(|item| {
            json!({
                "path": item.path,
                "kind": item.kind,
                "mode": item.mode,
                "size": item.size,
                "sha256": item.sha256,
                "content_kind": item.content_kind,
            })
        })
        .unwrap_or(Value::Null)
}
