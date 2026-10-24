//! Bounded, secret-free managed Node inventory for desktop clients.

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    api::ApiClient,
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const MAX_NODES: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    if request.method != "nodes.list"
        || serde_json::from_value::<Empty>(request.params.clone()).is_err()
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let device = config.active_device_id.clone();
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let nodes = client.list_nodes(&token).await.map_err(Failure::api)?;
    if nodes.len() > MAX_NODES {
        return Err(Failure::new("server_unavailable"));
    }
    let mut seen = std::collections::HashSet::with_capacity(nodes.len());
    let mut items = Vec::with_capacity(nodes.len());
    for node in nodes {
        if !uuid::Uuid::parse_str(&node.id).is_ok_and(|id| id.to_string() == node.id)
            || !seen.insert(node.id.clone())
            || node.name.is_empty()
            || node.name.len() > 256
            || node.name.chars().any(char::is_control)
            || node.status.is_empty()
            || node.status.len() > 64
            || node.status.chars().any(char::is_control)
        {
            return Err(Failure::new("server_unavailable"));
        }
        if node
            .ssh_host
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 512 || v.chars().any(char::is_control))
            || node
                .ssh_user
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
            || node
                .version
                .as_ref()
                .is_some_and(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
            || node.ssh_port == Some(0)
        {
            return Err(Failure::new("server_unavailable"));
        }
        items.push(json!({
            "id": node.id, "name": node.name, "status": node.status,
            "ssh_host": node.ssh_host, "ssh_port": node.ssh_port, "ssh_user": node.ssh_user,
            "version": node.version, "ego_browser_enabled": node.ego_browser_enabled,
            "configured_enabled": node.configured_enabled, "effective_enabled": node.effective_enabled,
            "node_execution_allowed": node.node_execution_allowed,
            "enrollment_admission": node.enrollment_admission,
            "execution_admission": node.execution_admission,
        }));
    }
    Ok(json!({
        "schema_version": 1,
        "operation": "nodes.list",
        "context": {"home": paths.home(), "server_url": server, "active_device_id": device},
        "items": items,
    }))
}
