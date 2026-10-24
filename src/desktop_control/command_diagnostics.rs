//! Structured projections for the human `status`, `doctor`, `deps status` and
//! `ssh check` commands.
//!
//! These methods deliberately do not parse terminal output.  Read operations
//! reuse the bounded diagnostic reader, while repair operations reuse the
//! existing local setup services and return their typed receipts.

use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use super::{diagnostics, Failure, Request};
use crate::api::ApiClient;
use crate::auth;
use crate::config::{AppPaths, Config};
use crate::setup;

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusOptions {
    #[serde(default)]
    online: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DoctorOptions {
    #[serde(default = "default_true")]
    online: bool,
    #[serde(default = "default_true")]
    deep_check: bool,
    #[serde(default = "default_true")]
    verify_versions: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RepairOptions {
    #[serde(default)]
    confirmed: bool,
    expected_home: String,
    #[serde(default = "default_true")]
    online: bool,
    #[serde(default = "default_true")]
    deep_check: bool,
    #[serde(default = "default_true")]
    verify_versions: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DepsOptions {
    #[serde(default = "default_true")]
    verify_versions: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SshOptions {
    #[serde(default)]
    session_id: Option<String>,
    #[serde(default)]
    expected_server_url: Option<String>,
    #[serde(default)]
    expected_device_id: Option<String>,
}

fn default_true() -> bool {
    true
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        "status.inspect" => status(request).await,
        "doctor.inspect" => doctor_inspect(request).await,
        "doctor.repair" => doctor_repair(request).await,
        "deps.inspect" => deps_inspect(request).await,
        "deps.repair" => deps_repair(request).await,
        "ssh.inspect" => ssh_inspect(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn status(request: &Request) -> Result<Value, Failure> {
    let options: StatusOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let report = diagnostics::inspect_flags(options.online, false, false, false).await?;
    let mut result = decorate(report, "status.inspect")?;
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).ok();
    let server_status = check_status(&result, "server_connection");
    let remote_device = if !options.online {
        json!({"status":"not_checked"})
    } else {
        match (
            config.as_ref(),
            config.as_ref().and_then(|c| c.server_url.as_deref()),
        ) {
            (None, _) => json!({"status":"unknown"}),
            (_, None) => json!({"status":"missing"}),
            (Some(config), Some(_)) if config.active_device_id.is_none() => {
                json!({"status":"missing"})
            }
            (Some(_config), Some(_))
                if !paths.home().is_dir()
                    || !paths.state_db_path().is_file()
                    || crate::local_state::LocalState::inspect_readonly(&paths).is_err() =>
            {
                json!({"status":"unknown"})
            }
            (Some(_config), Some(_)) => match auth::load_device_token(&paths).await {
                Ok((server_url, device_id, token)) => {
                    let client = match ApiClient::new(server_url) {
                        Ok(client) => client,
                        Err(_) => return Err(Failure::new("configuration_unavailable")),
                    };
                    match client.get_device(&token, &device_id).await {
                        Ok(device)
                            if Uuid::parse_str(&device.id).is_ok()
                                && bounded_identifier(&device.status) =>
                        {
                            let device_status = match device.status.as_str() {
                                "active" | "pending" | "revoked" | "disabled" => device.status,
                                _ => "unknown".to_string(),
                            };
                            json!({
                                "status":"observed",
                                "device_id": device.id,
                                "device_status": device_status,
                            })
                        }
                        Ok(_) => json!({"status":"unknown"}),
                        Err(error) => json!({
                            "status": api_observation_status(error.status_code()),
                        }),
                    }
                }
                Err(_) => json!({"status":"unknown"}),
            },
        }
    };
    let map = result
        .as_object_mut()
        .ok_or_else(|| Failure::new("configuration_unavailable"))?;
    map.insert(
        "remote".to_string(),
        json!({
            "server": server_status,
            "device": remote_device,
        }),
    );
    Ok(result)
}

async fn doctor_inspect(request: &Request) -> Result<Value, Failure> {
    let options: DoctorOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let report = diagnostics::inspect_flags(
        options.online,
        options.verify_versions,
        options.deep_check,
        false,
    )
    .await?;
    decorate(report, "doctor.inspect")
}

async fn doctor_repair(request: &Request) -> Result<Value, Failure> {
    let options: RepairOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let paths = checked_repair_paths(&options.expected_home, options.confirmed)?;
    let setup_report = setup::initialize(&paths).map_err(|_| Failure::new("repair_failed"))?;
    let report = diagnostics::inspect_flags(
        options.online,
        options.verify_versions,
        options.deep_check,
        false,
    )
    .await?;
    let mut result = decorate(report, "doctor.repair")?;
    result
        .as_object_mut()
        .expect("diagnostic report is an object")
        .insert(
            "setup".to_string(),
            serde_json::to_value(setup_report).unwrap_or_else(|_| json!({"complete":false})),
        );
    Ok(result)
}

async fn deps_inspect(request: &Request) -> Result<Value, Failure> {
    let options: DepsOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let report = diagnostics::inspect_flags(false, options.verify_versions, false, true).await?;
    decorate(report, "deps.inspect")
}

async fn deps_repair(request: &Request) -> Result<Value, Failure> {
    let options: RepairOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let paths = checked_repair_paths(&options.expected_home, options.confirmed)?;
    setup::initialize_dependencies(&paths).map_err(|_| Failure::new("repair_failed"))?;
    let report = diagnostics::inspect_flags(false, options.verify_versions, false, true).await?;
    let mut result = decorate(report, "deps.repair")?;
    result
        .as_object_mut()
        .expect("diagnostic report is an object")
        .insert("repair".to_string(), json!({"complete": true}));
    Ok(result)
}

async fn ssh_inspect(request: &Request) -> Result<Value, Failure> {
    let options: SshOptions = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    // Validate the optional remote scope before spawning even the local SSH
    // probe.  A malformed session request must have no process or credential
    // side effects.
    let remote_scope = match options.session_id {
        None => {
            if options.expected_server_url.is_some() || options.expected_device_id.is_some() {
                return Err(Failure::new("invalid_params"));
            }
            None
        }
        Some(raw_session) => {
            let session_id =
                Uuid::parse_str(&raw_session).map_err(|_| Failure::new("invalid_params"))?;
            let expected_server = options
                .expected_server_url
                .filter(|value| {
                    !value.is_empty()
                        && value.len() <= 2048
                        && value.chars().all(|c| !c.is_control())
                })
                .ok_or_else(|| Failure::new("invalid_params"))?;
            let expected_device = options
                .expected_device_id
                .filter(|value| Uuid::parse_str(value).is_ok())
                .ok_or_else(|| Failure::new("invalid_params"))?;
            Some((session_id, expected_server, expected_device))
        }
    };
    let version = crate::ssh::check_ssh_available().map_err(|_| Failure::new("ssh_unavailable"))?;
    let version = bounded_text(&version).ok_or_else(|| Failure::new("ssh_unavailable"))?;
    let mut result = json!({
        "schema_version": 1,
        "operation": "ssh.inspect",
        "home": AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?.home().to_string_lossy(),
        "platform": std::env::consts::OS,
        "ssh": {"status":"available", "version":version},
        "authorization": {"status":"not_requested"},
    });
    let Some((session_id, expected_server, expected_device)) = remote_scope else {
        return Ok(result);
    };
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url.as_deref() != Some(expected_server.as_str())
        || config.active_device_id.as_deref() != Some(expected_device.as_str())
    {
        return Err(Failure::new("context_mismatch"));
    }
    let (server_url, device_id, token) = auth::load_device_token(&paths)
        .await
        .map_err(|_| Failure::new("authentication_required"))?;
    if server_url != expected_server || device_id != expected_device {
        return Err(Failure::new("context_mismatch"));
    }
    let client =
        ApiClient::new(server_url).map_err(|_| Failure::new("configuration_unavailable"))?;
    let attach = client
        .attach_session(&token, &session_id.to_string())
        .await
        .map_err(Failure::api)?;
    if Uuid::parse_str(&attach.session_id).ok() != Some(session_id)
        || Uuid::parse_str(&attach.node_id).is_err()
        || !bounded_identifier(&attach.authorization_task_id)
    {
        return Err(Failure::new("server_unavailable"));
    }
    let authorization = json!({
        "status": match attach.authorization_task_status.as_str() {
            "succeeded" | "pending" | "running" | "failed" | "cancelled" | "expired" => attach.authorization_task_status,
            _ => "unknown".to_string(),
        },
        "session_id": attach.session_id,
        "node_id": attach.node_id,
        "authorization_task_id": attach.authorization_task_id,
        "expires_in": attach.expires_in,
    });
    result
        .as_object_mut()
        .expect("ssh result is an object")
        .insert("authorization".to_string(), authorization);
    Ok(result)
}

fn checked_repair_paths(expected_home: &str, confirmed: bool) -> Result<AppPaths, Failure> {
    if !confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let selected = setup::absolute_home(&paths).map_err(|_| Failure::new("invalid_params"))?;
    let expected = std::path::Path::new(expected_home);
    if expected_home.is_empty()
        || expected_home.len() > 4096
        || expected_home
            .chars()
            .any(|character| character.is_control())
        || !expected.is_absolute()
        || expected.to_str().is_none()
        || expected
            .components()
            .any(|part| matches!(part, std::path::Component::ParentDir))
        || setup::absolute_home(
            &AppPaths::new(Some(expected.to_path_buf()))
                .map_err(|_| Failure::new("invalid_params"))?,
        )
        .map_err(|_| Failure::new("invalid_params"))?
            != selected
    {
        return Err(Failure::new("context_mismatch"));
    }
    Ok(paths)
}

fn decorate(mut report: Value, operation: &'static str) -> Result<Value, Failure> {
    let object = report
        .as_object_mut()
        .ok_or_else(|| Failure::new("configuration_unavailable"))?;
    object.insert("schema_version".to_string(), json!(1));
    object.insert("operation".to_string(), json!(operation));
    Ok(report)
}

fn check_status(report: &Value, id: &str) -> &'static str {
    report["checks"]
        .as_array()
        .and_then(|checks| checks.iter().find(|check| check["id"] == id))
        .and_then(|check| check["status"].as_str())
        .map(|status| match status {
            "reachable" => "reachable",
            "inaccessible" => "inaccessible",
            "unavailable" => "unavailable",
            "missing" => "missing",
            "invalid" => "invalid",
            _ => "not_checked",
        })
        .unwrap_or("unknown")
}

fn api_observation_status(status: Option<u16>) -> &'static str {
    match status {
        Some(401 | 403) => "inaccessible",
        Some(404) => "missing",
        Some(400..=499) => "invalid",
        _ => "unavailable",
    }
}

fn bounded_text(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty() && value.len() <= 512 && value.chars().all(|c| !c.is_control()))
        .then(|| value.to_string())
}

fn bounded_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_:/".contains(&byte))
}
