use super::{Failure, Request};
use crate::{
    config::AppPaths,
    runtime_recovery::{self, Action, Status, UserContext},
};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    expected_home: PathBuf,
    expected_server_url: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Inspect {
    expected_context: UserContext,
    account_id: String,
    original_task_id: String,
    action: Action,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Pending {
    expected_home: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Forget {
    confirmed: bool,
    expected_context: UserContext,
    account_id: String,
    request_id: String,
    expected_digest: String,
    #[serde(deserialize_with = "required_binding")]
    expected_binding: Option<crate::api::runtime_recovery::RecoveryBinding>,
}
fn required_binding<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<crate::api::runtime_recovery::RecoveryBinding>, D::Error> {
    Option::deserialize(d)
}
fn input<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, Failure> {
    serde_json::from_value(request.params.clone()).map_err(|_| Failure::new("invalid_params"))
}
fn output<T: serde::Serialize>(value: T) -> Result<Value, Failure> {
    serde_json::to_value(value).map_err(|_| Failure::new("runtime_recovery_response_invalid"))
}
fn error(value: runtime_recovery::Error) -> Failure {
    Failure {
        code: value.code,
        http_status: value.http_status,
        retryable: false,
    }
}
pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {biased;_=signal.recv()=>Err(Failure::new(if matches!(request.method.as_str(),"accounts.runtime_recovery.apply"|"accounts.runtime_recovery.forget"){"runtime_recovery_outcome_unknown"}else{"canceled"})),result=inner(request)=>result}
    }
    #[cfg(not(unix))]
    inner(request).await
}
async fn inner(request: &Request) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let mut value = match request.method.as_str() {
        "accounts.runtime_recovery.authority" => {
            let p: Authority = input(request)?;
            output(
                runtime_recovery::authority(&paths, &p.expected_home, &p.expected_server_url)
                    .await
                    .map_err(error)?,
            )?
        }
        "accounts.runtime_recovery.inspect" => {
            let p: Inspect = input(request)?;
            output(
                runtime_recovery::inspect(
                    &paths,
                    p.expected_context,
                    &p.account_id,
                    &p.original_task_id,
                    p.action,
                )
                .await
                .map_err(error)?,
            )?
        }
        "accounts.runtime_recovery.apply" => output(
            runtime_recovery::apply(&paths, input(request)?)
                .await
                .map_err(error)?,
        )?,
        "accounts.runtime_recovery.status" => output(
            runtime_recovery::status(&paths, input(request)?)
                .await
                .map_err(error)?,
        )?,
        "accounts.runtime_recovery.pending" => {
            let p: Pending = input(request)?;
            if p.expected_home != paths.home() {
                return Err(Failure::new("configuration_changed"));
            }
            output(runtime_recovery::pending(&paths).map_err(error)?)?
        }
        "accounts.runtime_recovery.forget" => {
            let p: Forget = input(request)?;
            if !p.confirmed {
                return Err(Failure::new("confirmation_required"));
            }
            output(
                runtime_recovery::forget(
                    &paths,
                    Status {
                        expected_context: p.expected_context,
                        account_id: p.account_id,
                        request_id: p.request_id,
                        expected_digest: Some(p.expected_digest),
                        expected_binding: p.expected_binding,
                    },
                )
                .await
                .map_err(error)?,
            )?
        }
        _ => return Err(Failure::new("unsupported_method")),
    };
    if matches!(
        request.method.as_str(),
        "accounts.runtime_recovery.apply" | "accounts.runtime_recovery.forget"
    ) {
        value["operation_id"] = Value::String(request.request_id.clone());
    }
    Ok(value)
}
