//! Structured port-forward operations for the Go desktop bridge.

use crate::{
    account_defaults::Context,
    api::{ApiClient, CreatePortForwardRequest, PortForwardData},
    auth,
    config::{AppPaths, Config},
    local_state::{LocalState, PortForwardCreateRecord},
};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct List {
    #[serde(default)]
    expected_context: Option<Context>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Create {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    session_id: String,
    expected_node_id: String,
    expected_runtime_backend: String,
    remote_port: u16,
    local_port: u16,
    client_instance_id: String,
    caller_request_id: String,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Stop {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    forward_id: String,
    expected_session_id: String,
    expected_node_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Reconnect {
    confirmed: bool,
    schema_version: u8,
    expected_context: Context,
    forward_id: String,
    expected_session_id: String,
    expected_node_id: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "port_forwards.list" => list(request).await,
        "port_forwards.create" => create(request).await,
        "port_forwards.stop" => stop(request).await,
        "port_forwards.reconnect" => reconnect(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn list(request: &Request) -> Result<Value, Failure> {
    let input: List = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let (_paths, server, token, device_id, context) =
        authenticated(input.expected_context.as_ref()).await?;
    let forwards = ApiClient::new(server)
        .map_err(|_| Failure::new("configuration_unavailable"))?
        .list_port_forwards(&token)
        .await
        .map_err(Failure::api)?;
    let items: Vec<_> = forwards
        .iter()
        .filter(|forward| forward.device_id == device_id)
        .map(forward_json)
        .collect();
    Ok(json!({"items": items, "context": context}))
}

async fn create(request: &Request) -> Result<Value, Failure> {
    let input: Create = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || !valid_context(&input.expected_context)
        || !uuid(&input.session_id)
        || (!input.expected_node_id.is_empty() && !uuid(&input.expected_node_id))
        || (!input.expected_runtime_backend.is_empty()
            && !valid_text(&input.expected_runtime_backend, 64))
        || (!input.caller_request_id.is_empty() && !valid_uuid(&input.caller_request_id))
        || !(1..=65535).contains(&input.remote_port)
        || !(1..=65535).contains(&input.local_port)
        || !valid_text(&input.client_instance_id, 128)
        || input
            .ttl_seconds
            .is_some_and(|ttl| !(60..=604800).contains(&ttl))
    {
        return Err(Failure::new("invalid_params"));
    }
    let (paths, server, token, _device_id, _) =
        authenticated(Some(&input.expected_context)).await?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let session = client
        .get_tool_session(&token, &input.session_id)
        .await
        .map_err(Failure::api)?;
    if session.id != input.session_id
        || (!input.expected_node_id.is_empty() && session.node_id != input.expected_node_id)
        || (!input.expected_runtime_backend.is_empty()
            && session.runtime_backend != input.expected_runtime_backend)
        || !matches!(session.status.as_str(), "running" | "active")
    {
        return Err(Failure::new("session_binding_changed"));
    }
    let caller_request_id = if input.caller_request_id.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        input.caller_request_id.clone()
    };
    let user_scope = crate::session_creation::authenticated_scope(&token);
    let mut record = PortForwardCreateRecord {
        home: paths.home().to_path_buf(),
        server_url: server.clone(),
        user_id: user_scope,
        request_id: caller_request_id.clone(),
        session_id: input.session_id.clone(),
        node_id: session.node_id.clone(),
        runtime_backend: session.runtime_backend.clone(),
        remote_port: input.remote_port,
        local_port: input.local_port,
        client_instance_id: input.client_instance_id.clone(),
        ttl_seconds: input.ttl_seconds,
        phase: "prepared".into(),
        forward_id: None,
        last_observation: None,
    };
    let state =
        LocalState::open(&paths).map_err(|_| Failure::new("port_forward_journal_unavailable"))?;
    state
        .init_schema()
        .map_err(|_| Failure::new("port_forward_journal_unavailable"))?;
    if !state
        .reserve_port_forward_create(&record)
        .map_err(|_| Failure::new("port_forward_journal_unavailable"))?
    {
        let prior = LocalState::port_forward_create_records(&paths)
            .map_err(|_| Failure::new("port_forward_journal_unavailable"))?
            .into_iter()
            .find(|value| value.request_id == caller_request_id)
            .ok_or_else(|| Failure::new("PORT_FORWARD_REQUEST_CONFLICT"))?;
        if !same_identity(&prior, &record) {
            return Err(Failure::new("PORT_FORWARD_REQUEST_CONFLICT"));
        }
        record = prior;
    }
    let result = client
        .create_port_forward_with_retry(
            &token,
            &input.session_id,
            &CreatePortForwardRequest {
                remote_port: input.remote_port,
                local_port: input.local_port,
                client_instance_id: input.client_instance_id,
                caller_request_id: Some(caller_request_id.clone()),
                ttl_seconds: input.ttl_seconds,
            },
        )
        .await;
    let created = match result {
        Ok(value) => value,
        Err(error) if error.is_transport_error() => {
            let mut unknown = record.clone();
            unknown.phase = "unknown".into();
            unknown.last_observation = Some("transport failure after submission attempt".into());
            let _ = state.update_port_forward_create(&record, &unknown);
            return Err(Failure::new("PORT_FORWARD_SUBMISSION_UNKNOWN"));
        }
        Err(error) => return Err(map_api_error(error)),
    };
    let mut settled = record.clone();
    settled.phase = "created".into();
    settled.forward_id = Some(created.forward.id.clone());
    settled.last_observation = Some(created.forward.status.clone());
    let _ = state.update_port_forward_create(&record, &settled);
    Ok(
        json!({"schema_version": 1, "request_id": caller_request_id, "context": input.expected_context,
        "forward": forward_json(&created.forward), "node_wireguard_ip": created.node_wireguard_ip,
        "ssh_user": created.ssh_user, "ssh_port": created.ssh_port}),
    )
}

async fn stop(request: &Request) -> Result<Value, Failure> {
    let input: Stop = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || !valid_context(&input.expected_context)
        || !uuid(&input.forward_id)
        || (!input.expected_session_id.is_empty() && !uuid(&input.expected_session_id))
        || (!input.expected_node_id.is_empty() && !uuid(&input.expected_node_id))
    {
        return Err(Failure::new("invalid_params"));
    }
    let (_paths, server, token, device_id, _) =
        authenticated(Some(&input.expected_context)).await?;
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    let target = exact_forward(
        &client,
        &token,
        &device_id,
        &input.forward_id,
        &input.expected_session_id,
        &input.expected_node_id,
    )
    .await?;
    let stopped = client
        .stop_port_forward(&token, &target.id)
        .await
        .map_err(Failure::api)?;
    Ok(
        json!({"schema_version": 1, "request_id": input.forward_id, "context": input.expected_context, "forward": forward_json(&stopped)}),
    )
}

async fn reconnect(request: &Request) -> Result<Value, Failure> {
    let input: Reconnect = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.schema_version != 1
        || !valid_context(&input.expected_context)
        || !uuid(&input.forward_id)
        || (!input.expected_session_id.is_empty() && !uuid(&input.expected_session_id))
        || (!input.expected_node_id.is_empty() && !uuid(&input.expected_node_id))
    {
        return Err(Failure::new("invalid_params"));
    }
    let (_paths, server, token, device_id, _) =
        authenticated(Some(&input.expected_context)).await?;
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    let target = exact_forward(
        &client,
        &token,
        &device_id,
        &input.forward_id,
        &input.expected_session_id,
        &input.expected_node_id,
    )
    .await?;
    if matches!(target.status.as_str(), "stopped" | "expired" | "revoked") {
        return Err(Failure::new("PORT_FORWARD_REQUEST_SETTLED"));
    }
    let connection = client
        .create_port_forward_connection(&token, &target.id)
        .await
        .map_err(|error| {
            if error.is_transport_error() {
                Failure::new("PORT_FORWARD_RECONNECT_UNKNOWN")
            } else {
                Failure::api(error)
            }
        })?;
    Ok(json!({
        "schema_version": 1,
        "request_id": input.forward_id,
        "context": input.expected_context,
        "forward": forward_json(&target),
        "node_wireguard_ip": connection.node_wireguard_ip,
        "ssh_user": connection.ssh_user,
        "ssh_port": connection.ssh_port,
    }))
}

async fn exact_forward(
    client: &ApiClient,
    token: &str,
    device_id: &str,
    forward_id: &str,
    session_id: &str,
    node_id: &str,
) -> Result<PortForwardData, Failure> {
    let forwards = client
        .list_port_forwards(token)
        .await
        .map_err(Failure::api)?;
    forwards
        .into_iter()
        .find(|forward| {
            forward.id == forward_id
                && forward.device_id == device_id
                && (session_id.is_empty() || forward.session_id == session_id)
                && (node_id.is_empty() || forward.node_id == node_id)
        })
        .ok_or_else(|| Failure::new("forward_binding_changed"))
}

async fn authenticated(
    expected: Option<&Context>,
) -> Result<(AppPaths, String, String, String, Context), Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if expected.is_some_and(|value| paths.home() != value.home) {
        return Err(Failure::new("configuration_changed"));
    }
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let expected_device = expected.and_then(|value| value.active_device_id.as_deref());
    if expected.is_some_and(|value| value.server_url.as_deref() != Some(server.as_str()))
        || expected_device.is_some_and(|value| config.active_device_id.as_deref() != Some(value))
    {
        return Err(Failure::new("configuration_changed"));
    }
    let (_device, device_id, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?;
    if expected_device.is_some_and(|value| device_id != value) {
        return Err(Failure::new("configuration_changed"));
    }
    let context = Context {
        home: paths.home().to_path_buf(),
        server_url: Some(server.clone()),
        active_device_id: Some(device_id.clone()),
    };
    Ok((paths, server, token, device_id, context))
}

fn forward_json(forward: &PortForwardData) -> Value {
    json!({
        "id": forward.id, "session_id": forward.session_id,
        "node_id": forward.node_id, "remote_port": forward.remote_port,
        "requested_local_port": forward.requested_local_port, "client_instance_id": forward.client_instance_id,
        "caller_request_id": forward.caller_request_id, "status": forward.status,
        "bytes_up": forward.bytes_up, "bytes_down": forward.bytes_down,
        "connection_count": forward.connection_count, "last_connected_at": forward.last_connected_at,
        "lease_expires_at": forward.lease_expires_at, "expires_at": forward.expires_at,
        "stopped_at": forward.stopped_at, "stop_reason": forward.stop_reason,
        "created_at": forward.created_at, "updated_at": forward.updated_at
    })
}

fn same_identity(left: &PortForwardCreateRecord, right: &PortForwardCreateRecord) -> bool {
    left.home == right.home
        && left.server_url == right.server_url
        && left.user_id == right.user_id
        && left.request_id == right.request_id
        && left.session_id == right.session_id
        && left.node_id == right.node_id
        && left.runtime_backend == right.runtime_backend
        && left.remote_port == right.remote_port
        && left.local_port == right.local_port
        && left.client_instance_id == right.client_instance_id
        && left.ttl_seconds == right.ttl_seconds
}

fn valid_context(context: &Context) -> bool {
    context.home.is_absolute()
        && context
            .server_url
            .as_deref()
            .is_some_and(|v| v.starts_with("http://") || v.starts_with("https://"))
        && context.active_device_id.as_deref().is_some_and(uuid)
}
fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}
fn valid_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok() && value.len() == 36
}
fn uuid(value: &str) -> bool {
    crate::api::runtime_recovery::canonical_uuid(value)
}

fn map_api_error(error: crate::api::ApiError) -> Failure {
    let code = error.code().map(str::to_owned);
    if let Some(code) = code {
        return Failure::new(match code.as_str() {
            "PORT_FORWARD_REQUEST_CONFLICT" => "PORT_FORWARD_REQUEST_CONFLICT",
            "PORT_FORWARD_REQUEST_DEVICE_MISMATCH" => "PORT_FORWARD_REQUEST_DEVICE_MISMATCH",
            "PORT_FORWARD_REQUEST_SETTLED" => "PORT_FORWARD_REQUEST_SETTLED",
            _ => "server_rejected",
        });
    }
    Failure::api(error)
}
