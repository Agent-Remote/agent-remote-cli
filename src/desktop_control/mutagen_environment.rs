//! The global Mutagen environment is local-only and has a separate confirmation scope.
use super::{Failure, Request};
use crate::{config::AppPaths, mutagen_environment};
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewRequest {
    expected_home: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    confirmed: bool,
    expected_home: String,
    expected_fingerprint: String,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {
            biased;
            _ = terminate.recv() => Err(Failure::new(if request.method == "mutagen.environment.apply" { "sync_mutagen_environment_outcome_unknown" } else { "canceled" })),
            result = inner(request) => result,
        }
    }
    #[cfg(not(unix))]
    inner(request).await
}
async fn inner(request: &Request) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if request.method == "mutagen.environment.preview" {
        let input: PreviewRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        let plan = mutagen_environment::preview(&paths, &input.expected_home)
            .await
            .map_err(|e| Failure::new(e.code))?;
        serde_json::to_value(plan)
            .map_err(|_| Failure::new("sync_mutagen_environment_response_invalid"))
    } else {
        let input: ApplyRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.confirmed {
            return Err(Failure::new("confirmation_required"));
        }
        let receipt =
            mutagen_environment::apply(&paths, &input.expected_home, &input.expected_fingerprint)
                .await
                .map_err(|e| Failure::new(e.code))?;
        let mut value = serde_json::to_value(receipt)
            .map_err(|_| Failure::new("sync_mutagen_environment_outcome_unknown"))?;
        value["operation_id"] = Value::String(request.request_id.clone());
        value["home"] = Value::String(input.expected_home);
        value["method"] = Value::String(request.method.clone());
        Ok(value)
    }
}
