use super::{Failure, Request};
use crate::{
    account_defaults::Context,
    config::AppPaths,
    sync_operations::{self, Target},
};
use serde::Deserialize;
use serde_json::Value;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_context: Context,
    local_path: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RecoveryRequest {
    confirmed: bool,
    expected_context: Context,
    expected_plan: sync_operations::recovery::Plan,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MutationRequest {
    confirmed: bool,
    expected_context: Context,
    expected_target: Target,
    dry_run: bool,
}
pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {biased;_=terminate.recv()=>Err(Failure::new(if matches!(request.method.as_str(), "sync.status" | "sync.recovery.preview"){"canceled"}else{"sync_outcome_unknown"})),result=inner(request)=>result}
    }
    #[cfg(not(unix))]
    inner(request).await
}
async fn inner(request: &Request) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if request.method == "sync.recovery.preview" {
        let input: StatusRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let value =
            sync_operations::recovery::preview(&paths, input.expected_context, &input.local_path)
                .await
                .map_err(failure)?;
        serde_json::to_value(value).map_err(|_| Failure::new("sync_response_invalid"))
    } else if request.method == "sync.recovery.apply" {
        let input: RecoveryRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.confirmed {
            return Err(Failure::new("confirmation_required"));
        }
        let receipt =
            sync_operations::recovery::apply(&paths, input.expected_context, input.expected_plan)
                .await
                .map_err(failure)?;
        let mut value =
            serde_json::to_value(receipt).map_err(|_| Failure::new("sync_outcome_unknown"))?;
        value["operation_id"] = Value::String(request.request_id.clone());
        Ok(value)
    } else if request.method == "sync.status" {
        let input: StatusRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let value = sync_operations::status(&paths, input.expected_context, &input.local_path)
            .await
            .map_err(failure)?;
        serde_json::to_value(value).map_err(|_| Failure::new("sync_response_invalid"))
    } else {
        let input: MutationRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.confirmed {
            return Err(Failure::new("confirmation_required"));
        }
        let receipt = sync_operations::mutate(
            &paths,
            input.expected_context,
            input.expected_target,
            &request.method,
            input.dry_run,
        )
        .await
        .map_err(failure)?;
        let mut value =
            serde_json::to_value(receipt).map_err(|_| Failure::new("sync_outcome_unknown"))?;
        value["operation_id"] = Value::String(request.request_id.clone());
        Ok(value)
    }
}
fn failure(error: sync_operations::Error) -> Failure {
    Failure {
        code: error.code,
        retryable: false,
        http_status: error.http_status,
    }
}
