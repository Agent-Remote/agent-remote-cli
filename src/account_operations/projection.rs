use serde::Serialize;

use crate::api::{BindingStatusData, ToolAccountData};

use super::{Error, Result};

/// Explicit public metadata. New API fields never automatically enter desktop output.
#[derive(Serialize)]
pub struct Account {
    pub id: String,
    pub tool_type: String,
    pub display_name: String,
    pub status: String,
    pub region_code: String,
    pub timezone: String,
    pub locale: String,
    pub preferred_node_tags: Vec<String>,
    pub affinity_node_id: Option<String>,
    pub runtime_backend: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

/// Informational binding state, never executable connection instructions.
#[derive(Serialize)]
pub struct Binding {
    pub tool_account_id: String,
    pub status: String,
    pub node_id: Option<String>,
    pub binding_session_id: Option<String>,
    pub tmux_session_name: Option<String>,
    pub account_remote_path: Option<String>,
    pub task_id: Option<String>,
    pub error_code: Option<&'static str>,
}

pub(super) fn account(value: ToolAccountData) -> Result<Account> {
    if !id(&value.id)
        || !id(&value.tool_type)
        || !text(&value.display_name, 256)
        || !status(&value.status)
        || !text(&value.region_code, 64)
        || !text(&value.timezone, 128)
        || !text(&value.locale, 128)
        || !tags(&value.preferred_node_tags)
        || value.affinity_node_id.as_deref().is_some_and(|v| !id(v))
        || value
            .runtime_backend
            .as_deref()
            .is_some_and(|v| !matches!(v, "native" | "docker_sandbox"))
        || !text(&value.created_at, 128)
        || !text(&value.updated_at, 128)
    {
        return Err(Error::new("account_response_invalid"));
    }
    Ok(Account {
        id: value.id,
        tool_type: value.tool_type,
        display_name: value.display_name,
        status: value.status,
        region_code: value.region_code,
        timezone: value.timezone,
        locale: value.locale,
        preferred_node_tags: value.preferred_node_tags,
        affinity_node_id: value.affinity_node_id,
        runtime_backend: value.runtime_backend,
        created_at: value.created_at,
        updated_at: value.updated_at,
    })
}

pub(super) fn binding(value: BindingStatusData, expected_id: &str) -> Result<Binding> {
    if value.tool_account_id != expected_id
        || !status(&value.status)
        || value.node_id.as_deref().is_some_and(|v| !id(v))
        || value
            .binding_session_id
            .as_deref()
            .is_some_and(|v| !text(v, 512))
        || value
            .tmux_session_name
            .as_deref()
            .is_some_and(|v| !text(v, 512))
        || value
            .account_remote_path
            .as_deref()
            .is_some_and(|v| !text(v, 4096))
        || value.task_id.as_deref().is_some_and(|v| !text(v, 512))
    {
        return Err(Error::new("account_response_invalid"));
    }
    Ok(Binding {
        tool_account_id: value.tool_account_id,
        status: value.status,
        node_id: value.node_id,
        binding_session_id: value.binding_session_id,
        tmux_session_name: value.tmux_session_name,
        account_remote_path: value.account_remote_path,
        task_id: value.task_id,
        error_code: value.error.map(|_| "binding_failed"),
    })
}

pub(crate) fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|v| v.is_ascii_alphanumeric() || b"-_".contains(&v))
}
pub(crate) fn text(value: &str, max: usize) -> bool {
    !value.is_empty()
        && value.len() <= max
        && value.trim() == value
        && !value.chars().any(char::is_control)
}
pub(crate) fn tags(values: &[String]) -> bool {
    values.len() <= 64 && values.iter().all(|v| text(v, 128))
}
fn status(value: &str) -> bool {
    matches!(
        value,
        "binding_requested"
            | "binding_session_starting"
            | "binding_waiting_user_login"
            | "binding_verifying"
            | "active"
            | "expired"
            | "disabled"
            | "failed"
            | "node_unavailable"
            | "migrating"
    )
}
