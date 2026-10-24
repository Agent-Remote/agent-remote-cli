//! Exact, context-bound retry of an ended Skill deployment operation.
//!
//! A retry is never inferred from a terminal transcript.  The plan reads the
//! original operation, selects only its ended retryable targets and returns a
//! bounded fingerprint.  The control call re-reads the operation, compares
//! that fingerprint, and submits a deterministic idempotency key.  Transport
//! failures after submission are reported as unknown so the desktop cannot
//! silently create a second retry.

use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::{
    account_defaults::Context,
    api::{
        skill_retry::{SkillRetryRequest, SkillRetryTarget},
        skills::{SkillMutation, SkillResult, SkillTarget},
        ApiClient,
    },
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const PLAN: &str = "skills.retry.plan";
const CONTROL: &str = "skills.retry.control";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanInput {
    expected_context: Context,
    operation_id: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ControlInput {
    confirmed: bool,
    expected_context: Context,
    operation_id: String,
    expected_generation: i64,
    expected_plan_fingerprint: String,
}

#[derive(Clone, serde::Serialize)]
struct SelectedTarget {
    account_id: String,
    attempt_id: String,
    attempt_number: u64,
    plan_digest: String,
}

#[derive(Clone, serde::Serialize)]
struct RetrySelection {
    generation: i64,
    targets: Vec<SelectedTarget>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    match request.method.as_str() {
        PLAN => plan(request).await,
        CONTROL => control(request).await,
        _ => Err(Failure::new("unsupported_method")),
    }
}

async fn plan(request: &Request) -> Result<Value, Failure> {
    let input: PlanInput = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    validate_input(&input.expected_context, &input.operation_id)?;
    let (_paths, _config, token, client) = context(&input.expected_context).await?;
    let result = read_operation(&client, &token, &input.operation_id).await?;
    let selection = eligible_selection(&result, &input.operation_id)?;
    let fingerprint = fingerprint(&selection)?;
    Ok(json!({
        "schema_version": 1,
        "operation": PLAN,
        "context": input.expected_context,
        "operation_id": input.operation_id,
        "status": result.status,
        "retryable": result.retryable,
        "generation": selection.generation,
        "targets": selection.targets.iter().map(|target| json!({
            "account_id": target.account_id,
            "attempt_id": target.attempt_id,
            "attempt_number": target.attempt_number,
        })).collect::<Vec<_>>(),
        "target_count": selection.targets.len(),
        "plan_fingerprint": fingerprint,
        "requires_confirmation": true,
    }))
}

async fn control(request: &Request) -> Result<Value, Failure> {
    let input: ControlInput = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    validate_input(&input.expected_context, &input.operation_id)?;
    if !input.confirmed
        || input.expected_generation < 0
        || !hex_fingerprint(&input.expected_plan_fingerprint)
    {
        return Err(Failure::new("invalid_params"));
    }
    let (_paths, _config, token, client) = context(&input.expected_context).await?;
    let current = read_operation(&client, &token, &input.operation_id).await?;
    let selection = eligible_selection(&current, &input.operation_id)?;
    let fingerprint = fingerprint(&selection)?;
    if selection.generation != input.expected_generation
        || fingerprint != input.expected_plan_fingerprint
    {
        return Err(Failure::new("skill_retry_plan_changed"));
    }
    let payload = SkillRetryRequest {
        // The desktop request id is already bounded and validated by the
        // protocol. Prefixing it makes the key namespace explicit while
        // retaining idempotency across an uncertain transport outcome.
        idempotency_key: format!("desktop-retry-{}", request.request_id),
        expected_generation: selection.generation,
        targets: selection
            .targets
            .iter()
            .map(|target| SkillRetryTarget {
                account_id: target.account_id.clone(),
                attempt_id: target.attempt_id.clone(),
            })
            .collect(),
    };
    let result = client
        .retry_skill(&token, &input.operation_id, &payload)
        .await
        .map_err(retry_failure)?;
    validate_receipt(&result, &input.operation_id, &selection)?;
    let data = result
        .data
        .as_ref()
        .ok_or_else(|| Failure::new("skill_retry_outcome_unknown"))?;
    Ok(json!({
        "schema_version": 1,
        "operation": CONTROL,
        // The desktop-control envelope reserves operation_id for this
        // request. The source operation is carried separately so the stream
        // can enforce the usual request-id invariant.
        "operation_id": request.request_id,
        "source_operation_id": input.operation_id,
        "request_id": request.request_id,
        "context": input.expected_context,
        "status": result.status,
        "accepted": result.committed,
        "generation": data.generation,
        "target_count": data.targets.len(),
        "plan_fingerprint": input.expected_plan_fingerprint,
        "targets": data.targets.iter().filter_map(public_target).collect::<Vec<_>>(),
    }))
}

async fn context(expected: &Context) -> Result<(AppPaths, Config, String, ApiClient), Failure> {
    if !valid_context(expected) {
        return Err(Failure::new("invalid_params"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != Path::new(&expected.home) {
        return Err(Failure::new("configuration_changed"));
    }
    let config =
        Config::load_strict(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url != expected.server_url
        || config.active_device_id != expected.active_device_id
    {
        return Err(Failure::new("configuration_changed"));
    }
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client = ApiClient::new(server).map_err(|_| Failure::new("configuration_unavailable"))?;
    Ok((paths, config, token, client))
}

async fn read_operation(
    client: &ApiClient,
    token: &str,
    operation_id: &str,
) -> Result<SkillResult<SkillMutation>, Failure> {
    client
        .skill_status(token, operation_id)
        .await
        .map_err(Failure::api)
}

fn eligible_selection(
    result: &SkillResult<SkillMutation>,
    operation_id: &str,
) -> Result<RetrySelection, Failure> {
    if result.schema_version != 1
        || result.operation_id.as_deref() != Some(operation_id)
        || !result.committed
        || result.status != "failed"
        || !result.retryable
    {
        return Err(Failure::new("skill_retry_not_eligible"));
    }
    let data = result
        .data
        .as_ref()
        .ok_or_else(|| Failure::new("skill_retry_not_eligible"))?;
    if data.replacement_id.is_some() || data.generation < 0 || data.targets.is_empty() {
        return Err(Failure::new("skill_retry_not_eligible"));
    }
    if data.targets.iter().any(|target| {
        matches!(
            target.readiness.as_str(),
            "pending" | "running" | "needs_resolution"
        )
    }) {
        return Err(Failure::new("skill_retry_not_eligible"));
    }
    let mut targets: Vec<SelectedTarget> =
        data.targets.iter().filter_map(selected_target).collect();
    if targets.is_empty()
        || targets.len() > 10_000
        || targets.iter().any(|target| target.account_id.is_empty())
    {
        return Err(Failure::new("skill_retry_not_eligible"));
    }
    targets.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    if targets
        .windows(2)
        .any(|pair| pair[0].account_id == pair[1].account_id)
    {
        return Err(Failure::new("skill_retry_not_eligible"));
    }
    Ok(RetrySelection {
        generation: data.generation,
        targets,
    })
}

fn selected_target(target: &SkillTarget) -> Option<SelectedTarget> {
    if target.retryable != Some(true) || target.readiness != "failed" || target.node_id.is_none() {
        return None;
    }
    Some(SelectedTarget {
        account_id: target.account_id.clone(),
        attempt_id: target.attempt_id.clone()?,
        attempt_number: target.attempt_number?,
        plan_digest: target.plan_digest.clone()?,
    })
}

fn fingerprint(selection: &RetrySelection) -> Result<String, Failure> {
    let bytes =
        serde_json::to_vec(selection).map_err(|_| Failure::new("skill_retry_outcome_unknown"))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn validate_receipt(
    result: &SkillResult<SkillMutation>,
    operation_id: &str,
    selection: &RetrySelection,
) -> Result<(), Failure> {
    if result.schema_version != 1
        || !result.committed
        || result.operation_id.as_deref() != Some(operation_id)
    {
        return Err(Failure::new("skill_retry_outcome_unknown"));
    }
    let data = result
        .data
        .as_ref()
        .ok_or_else(|| Failure::new("skill_retry_outcome_unknown"))?;
    if data.generation != selection.generation || data.targets.is_empty() {
        return Err(Failure::new("skill_retry_outcome_unknown"));
    }
    let mut seen = std::collections::BTreeSet::new();
    for selected in &selection.targets {
        let target = data
            .targets
            .iter()
            .find(|target| target.account_id == selected.account_id)
            .ok_or_else(|| Failure::new("skill_retry_outcome_unknown"))?;
        if !seen.insert(target.account_id.clone())
            || target.plan_digest.as_deref() != Some(selected.plan_digest.as_str())
            || target
                .attempt_number
                .is_none_or(|number| number <= selected.attempt_number)
            || target
                .attempt_id
                .as_deref()
                .is_none_or(|id| id == selected.attempt_id)
        {
            return Err(Failure::new("skill_retry_outcome_unknown"));
        }
    }
    Ok(())
}

fn public_target(target: &SkillTarget) -> Option<Value> {
    Some(json!({
        "account_id": target.account_id,
        "attempt_id": target.attempt_id,
        "attempt_number": target.attempt_number,
        "readiness": target.readiness,
        "retryable": target.retryable,
    }))
}

fn retry_failure(error: crate::api::ApiError) -> Failure {
    if error.status_code().is_none() {
        return Failure::new("skill_retry_outcome_unknown");
    }
    match error.status_code() {
        Some(400..=499) => Failure::new("skill_retry_rejected"),
        _ => Failure::api(error),
    }
}

fn validate_input(context: &Context, operation_id: &str) -> Result<(), Failure> {
    if !valid_context(context) || uuid::Uuid::parse_str(operation_id).is_err() {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn valid_context(context: &Context) -> bool {
    context.home.is_absolute()
        && !context
            .home
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
        && context.server_url.as_deref().is_some_and(|url| {
            (url.starts_with("http://") || url.starts_with("https://"))
                && url.len() <= 8192
                && !url.chars().any(char::is_control)
        })
        && context
            .active_device_id
            .as_deref()
            .is_none_or(super::valid_id)
}

fn hex_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
