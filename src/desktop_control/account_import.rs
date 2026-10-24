use super::{Failure, Request};
use crate::{
    account_defaults::Context,
    account_import::{self, Selection},
    config::AppPaths,
};
use serde::Deserialize;
use serde_json::Value;
use std::path::PathBuf;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Discover {
    selection: Selection,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Prepare {
    expected_context: Context,
    account_id: String,
    selection: Selection,
    expected_source_home: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Validate {
    confirmed: bool,
    expected_context: Context,
    account_id: String,
    selection: Selection,
    expected_source_home: PathBuf,
    expected_include: Vec<String>,
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
    expected_context: Context,
    account_id: String,
    request_id: String,
    expected_digest: String,
    #[serde(deserialize_with = "crate::account_defaults::required_nullable")]
    expected_task_id: Option<String>,
}
fn input<T: serde::de::DeserializeOwned>(request: &Request) -> Result<T, Failure> {
    serde_json::from_value(request.params.clone()).map_err(|_| Failure::new("invalid_params"))
}
fn output<T: serde::Serialize>(value: T) -> Result<Value, Failure> {
    serde_json::to_value(value).map_err(|_| Failure::new("account_import_response_invalid"))
}
fn error(error: account_import::Error) -> Failure {
    Failure {
        code: error.code,
        http_status: error.http_status,
        retryable: false,
    }
}
pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    #[cfg(unix)]
    {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        tokio::select! {biased; _=signal.recv()=>Err(Failure::new(if matches!(request.method.as_str(),"accounts.import.apply"|"accounts.import.validate"|"accounts.import.forget"){"account_import_outcome_unknown"}else{"canceled"})),result=inner(request)=>result}
    }
    #[cfg(not(unix))]
    inner(request).await
}
async fn inner(request: &Request) -> Result<Value, Failure> {
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    let mut result = match request.method.as_str() {
        "accounts.import.discover" => {
            let p: Discover = input(request)?;
            output(account_import::discover(&p.selection).map_err(error)?)?
        }
        "accounts.import.prepare" => {
            let p: Prepare = input(request)?;
            output(
                account_import::prepare(
                    &paths,
                    p.expected_context,
                    &p.account_id,
                    p.selection,
                    p.expected_source_home,
                )
                .await
                .map_err(error)?,
            )?
        }
        "accounts.import.validate" => {
            let p: Validate = input(request)?;
            if !p.confirmed {
                return Err(Failure::new("confirmation_required"));
            }
            output(
                account_import::validate(
                    &paths,
                    p.expected_context,
                    &p.account_id,
                    p.selection,
                    p.expected_source_home,
                    p.expected_include,
                )
                .await
                .map_err(error)?,
            )?
        }
        "accounts.import.apply" => output(
            account_import::apply(&paths, input(request)?)
                .await
                .map_err(error)?,
        )?,
        "accounts.import.status" => output(
            account_import::status(&paths, input(request)?)
                .await
                .map_err(error)?,
        )?,
        "accounts.import.pending" => {
            let p: Pending = input(request)?;
            if p.expected_home != paths.home() {
                return Err(Failure::new("configuration_changed"));
            }
            output(account_import::pending(&paths).map_err(error)?)?
        }
        "accounts.import.forget" => {
            let p: Forget = input(request)?;
            if !p.confirmed {
                return Err(Failure::new("confirmation_required"));
            }
            output(
                account_import::forget(
                    &paths,
                    account_import::Status {
                        expected_context: p.expected_context,
                        account_id: p.account_id,
                        request_id: p.request_id,
                        expected_digest: p.expected_digest,
                        expected_task_id: p.expected_task_id,
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
        "accounts.import.apply" | "accounts.import.validate" | "accounts.import.forget"
    ) {
        result["operation_id"] = Value::String(request.request_id.clone());
    }
    Ok(result)
}
