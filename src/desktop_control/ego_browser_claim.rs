//! Exact candidate selection and full-trust ego-browser claim for desktop.
//!
//! The desktop receives only bounded candidate metadata.  A claim is always
//! reviewed against a fresh candidate fingerprint and the local admission
//! state; the control request closes admission before invoking the verified
//! Device Client.  Device-client failures after that point are unknown and
//! must not be retried automatically.

use std::{
    ffi::OsString,
    fs,
    path::{Component, Path, PathBuf},
    process::Stdio,
    time::{SystemTime, UNIX_EPOCH},
};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_defaults::Context,
    api::{ApiClient, EgoBrowserBindingCandidateData},
    auth,
    config::{AppPaths, Config},
    local_state::LocalState,
    platform,
};

use tokio::{
    process::Command as ProcessCommand,
    time::{timeout, Duration},
};

use super::{Failure, Request};

const CANDIDATES: &str = "ego_browser.candidates";
const PLAN: &str = "ego_browser.claim.plan";
const CONTROL: &str = "ego_browser.claim.control";
const MAX_ITEMS: usize = 128;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CandidatesInput {
    expected_context: Context,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInput {
    expected_context: Context,
    tool_session_id: String,
    candidate_fingerprint: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInput {
    confirmed: bool,
    expected_context: Context,
    tool_session_id: String,
    candidate_fingerprint: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        CANDIDATES => candidates(request).await,
        PLAN => plan(request).await,
        CONTROL => control(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn candidates(request: &Request) -> Result<Value, Failure> {
    let input: CandidatesInput = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    let (paths, server, token, client, active) = context(input.expected_context).await?;
    let items = list_candidates(&client, &token).await?;
    Ok(json!({
        "schema_version": 1,
        "operation": CANDIDATES,
        "context": context_json(&paths, &server, active),
        "items": items.into_iter().map(candidate_json).collect::<Vec<_>>(),
    }))
}

async fn plan(request: &Request) -> Result<Value, Failure> {
    let input: PlanInput = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    validate_selection(&input.tool_session_id, &input.candidate_fingerprint)?;
    let (paths, server, token, client, active) = context(input.expected_context).await?;
    ensure_claim_ready(&paths, &client, &token).await?;
    let candidate = find_candidate(
        &client,
        &token,
        &input.tool_session_id,
        &input.candidate_fingerprint,
    )
    .await?;
    Ok(json!({
        "schema_version": 1,
        "operation": PLAN,
        "context": context_json(&paths, &server, active),
        "candidate": candidate_json(candidate),
        "candidate_fingerprint": input.candidate_fingerprint,
        "local_admission": "ready",
        "requires_confirmation": true,
        "allowed": true,
    }))
}

async fn control(request: &Request) -> Result<Value, Failure> {
    let input: ControlInput = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed {
        return Err(Failure::new("confirmation_required"));
    }
    validate_selection(&input.tool_session_id, &input.candidate_fingerprint)?;
    let (paths, server, token, client, active) = context(input.expected_context).await?;
    ensure_claim_ready(&paths, &client, &token).await?;
    let candidate = find_candidate(
        &client,
        &token,
        &input.tool_session_id,
        &input.candidate_fingerprint,
    )
    .await?;

    // Admission is closed before handing control to the Device Client.  Any
    // process error after this point may have followed a successful claim.
    close_local_admission(&paths).map_err(|_| Failure::new("ego_browser_claim_outcome_unknown"))?;
    let run = run_device_client_at(
        &paths,
        [
            std::ffi::OsString::from("claim"),
            std::ffi::OsString::from(input.tool_session_id.clone()),
            std::ffi::OsString::from("--confirm"),
        ],
    )
    .await;
    if run.is_err() {
        return Err(Failure::new("ego_browser_claim_outcome_unknown"));
    }
    if local_admission_state(&paths)
        .map_err(|_| Failure::new("ego_browser_claim_outcome_unknown"))?
        != "open"
    {
        return Err(Failure::new("ego_browser_claim_outcome_unknown"));
    }
    Ok(json!({
        "operation_id": request.request_id,
        "schema_version": 1,
        "operation": CONTROL,
        "context": context_json(&paths, &server, active),
        "candidate": candidate_json(candidate),
        "candidate_fingerprint": input.candidate_fingerprint,
        "status": "claim_submitted",
        "local_admission": "open",
    }))
}

async fn context(
    input: Context,
) -> Result<(AppPaths, String, String, ApiClient, Option<String>), Failure> {
    if !valid_home(&input.home)
        || input.server_url.as_ref().is_none_or(|value| {
            value.is_empty() || value.len() > 8192 || value.chars().any(char::is_control)
        })
        || input
            .active_device_id
            .as_ref()
            .is_some_and(|value| !valid_id(value))
    {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != input.home {
        return Err(Failure::new("configuration_changed"));
    }
    let config = Config::load(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url != input.server_url || config.active_device_id != input.active_device_id {
        return Err(Failure::new("configuration_changed"));
    }
    let server = input
        .server_url
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    Ok((paths, server, token, client, input.active_device_id))
}

async fn list_candidates(
    client: &ApiClient,
    token: &str,
) -> Result<Vec<EgoBrowserBindingCandidateData>, Failure> {
    let items = client
        .list_ego_browser_candidates(token)
        .await
        .map_err(Failure::api)?;
    if items.len() > MAX_ITEMS || items.iter().any(|item| !valid_candidate(item)) {
        return Err(Failure::new("server_unavailable"));
    }
    Ok(items)
}

async fn find_candidate(
    client: &ApiClient,
    token: &str,
    session: &str,
    fingerprint: &str,
) -> Result<EgoBrowserBindingCandidateData, Failure> {
    let items = list_candidates(client, token).await?;
    let Some(candidate) = items
        .into_iter()
        .find(|item| item.tool_session_id == session)
    else {
        return Err(Failure::new("ego_browser_candidate_stale"));
    };
    if !candidate.controllable
        || candidate.binding_id.is_some()
        || candidate.current_ego_browser_device_id.is_some()
        || candidate_fingerprint(&candidate) != fingerprint
    {
        return Err(Failure::new("ego_browser_candidate_stale"));
    }
    Ok(candidate)
}

async fn ensure_claim_ready(
    paths: &AppPaths,
    client: &ApiClient,
    token: &str,
) -> Result<(), Failure> {
    let state =
        local_admission_state(paths).map_err(|_| Failure::new("local_admission_unknown"))?;
    if state != "ready" {
        return Err(Failure::new(if state == "open" {
            "local_binding_active"
        } else {
            "local_admission_disabled"
        }));
    }
    if !managed_bridge_installation_exists(paths) {
        return Err(Failure::new("ego_browser_bridge_unavailable"));
    }
    let policy = client
        .ego_browser_policy(token)
        .await
        .map_err(Failure::api)?;
    if !policy.execution_is_admitted() {
        return Err(Failure::new("ego_browser_execution_disabled"));
    }
    Ok(())
}

fn validate_selection(session: &str, fingerprint: &str) -> Result<(), Failure> {
    if !valid_id(session)
        || fingerprint.is_empty()
        || fingerprint.len() > 2048
        || fingerprint.chars().any(char::is_control)
    {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn candidate_json(item: EgoBrowserBindingCandidateData) -> Value {
    json!({
        "tool_session_id": item.tool_session_id,
        "tool_type": item.tool_type,
        "tool_account_id": item.tool_account_id,
        "workspace_id": item.workspace_id,
        "project_key": item.project_key,
        "display_name": item.display_name,
        "status": item.status,
        "node_id": item.node_id,
        "runtime_backend": item.runtime_backend,
        "current_ego_browser_device_id": item.current_ego_browser_device_id,
        "current_ego_browser_device_name": item.current_ego_browser_device_name,
        "binding_id": item.binding_id,
        "controllable": item.controllable,
    })
}

fn candidate_fingerprint(item: &EgoBrowserBindingCandidateData) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        item.tool_session_id,
        item.tool_type,
        item.tool_account_id,
        item.workspace_id,
        item.node_id,
        item.status,
        item.runtime_backend,
        item.project_key,
        item.display_name,
        item.current_ego_browser_device_id.as_deref().unwrap_or(""),
        item.current_ego_browser_device_name
            .as_deref()
            .unwrap_or(""),
        item.binding_id.as_deref().unwrap_or(""),
        item.controllable
    )
}

fn valid_candidate(item: &EgoBrowserBindingCandidateData) -> bool {
    valid_id(&item.tool_session_id)
        && valid_id(&item.tool_type)
        && valid_id(&item.tool_account_id)
        && valid_id(&item.workspace_id)
        && valid_id(&item.project_key)
        && valid_text(&item.display_name, 256)
        && valid_text(&item.status, 64)
        && valid_id(&item.node_id)
        && valid_id(&item.runtime_backend)
        && item
            .current_ego_browser_device_id
            .as_deref()
            .is_none_or(valid_id)
        && item
            .current_ego_browser_device_name
            .as_deref()
            .is_none_or(|v| valid_text(v, 256))
        && item.binding_id.as_deref().is_none_or(valid_id)
}

fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn valid_text(value: &str, max: usize) -> bool {
    !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control)
}

fn context_json(paths: &AppPaths, server: &str, active: Option<String>) -> Value {
    json!({"home": paths.home(), "server_url": server, "active_device_id": active})
}

fn valid_home(path: &Path) -> bool {
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionRecord {
    version: u8,
    state: String,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_generation: Option<u64>,
    #[serde(default)]
    binding_id: Option<String>,
    #[serde(default)]
    binding_generation: Option<u64>,
    updated_at_unix: u64,
}

fn device_store_dir(paths: &AppPaths) -> PathBuf {
    if let Some(path) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME") {
        return PathBuf::from(path);
    }
    paths.home().join("ego-browser-device")
}

fn admission_path(paths: &AppPaths) -> PathBuf {
    device_store_dir(paths).join("ego-browser-local-admission.json")
}

fn local_admission_state(paths: &AppPaths) -> anyhow::Result<String> {
    let path = admission_path(paths);
    let bytes = match fs::symlink_metadata(&path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink()
                || !metadata.is_file()
                || metadata.len() > 16 * 1024
            {
                anyhow::bail!("ego-browser admission record is unsafe")
            }
            fs::read(&path)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok("unknown".into()),
        Err(error) => return Err(error.into()),
    };
    let record: AdmissionRecord = serde_json::from_slice(&bytes)?;
    if record.version != 1
        || record.updated_at_unix == 0
        || !matches!(record.state.as_str(), "closed" | "ready" | "open")
        || record
            .device_id
            .as_deref()
            .is_some_and(|value| !valid_id(value))
        || record
            .binding_id
            .as_deref()
            .is_some_and(|value| !valid_id(value))
        || record.device_generation.is_some_and(|value| value == 0)
        || record.binding_generation.is_some_and(|value| value == 0)
    {
        anyhow::bail!("invalid local admission record")
    }
    Ok(record.state)
}

fn close_local_admission(paths: &AppPaths) -> anyhow::Result<()> {
    let directory = device_store_dir(paths);
    fs::create_dir_all(&directory)?;
    let directory_metadata = fs::symlink_metadata(&directory)?;
    if directory_metadata.file_type().is_symlink() || !directory_metadata.is_dir() {
        anyhow::bail!("ego-browser Device store is not a directory")
    }
    platform::set_owner_only_permissions(&directory)?;
    let record = serde_json::json!({
        "version": 1,
        "state": "closed",
        "device_id": null,
        "device_generation": null,
        "binding_id": null,
        "binding_generation": null,
        "updated_at_unix": SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs().max(1),
    });
    let temp = directory.join(".ego-browser-local-admission.claim.tmp");
    fs::write(&temp, serde_json::to_vec(&record)?)?;
    platform::set_owner_only_permissions(&temp)?;
    fs::rename(temp, admission_path(paths))?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.set_kv("ego-browser-local-admission", "closed")?;
    Ok(())
}

fn managed_bridge_installation_exists(paths: &AppPaths) -> bool {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(home) = platform::user_home_dir() {
        roots.push(home.join("Library/Application Support/Agent Remote Ego Browser"));
    }
    roots.push(paths.home().join("ego-browser"));
    roots.iter().any(|root| {
        fs::symlink_metadata(root.join("current"))
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
    })
}

async fn run_device_client_at<const N: usize>(
    paths: &AppPaths,
    args: [OsString; N],
) -> anyhow::Result<()> {
    let executable = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE")
        .unwrap_or_else(|| OsString::from("ego-browser-device"));
    let output = timeout(
        Duration::from_secs(120),
        ProcessCommand::new(&executable)
            .args(args)
            .env("EGO_BROWSER_DEVICE_HOME", device_store_dir(paths))
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .output(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("ego-browser Device Client timed out"))??;
    if !output.status.success() {
        anyhow::bail!("device client exited unsuccessfully")
    }
    Ok(())
}
