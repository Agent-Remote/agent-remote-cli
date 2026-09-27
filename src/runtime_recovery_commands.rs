//! Explicit migration recovery with caller-retained request identities.

mod failure;

pub use failure::RecoveryContext;

use anyhow::{Context, Result};
use failure::RecoveryFailure;
use serde::Serialize;

use crate::api::runtime_recovery::{
    canonical_uuid, original_task_matches, RecoveryAction, RecoveryStatus, RuntimeRecovery,
};
use crate::api::ApiClient;
use crate::auth;
use crate::cli::{AccountRecoverRuntimeArgs, AccountRecoveryStatusArgs};
use crate::config::{AppPaths, Config};
use crate::terminal::Details;

/// Submit only an exact administrator-selected original migration and request key.
pub async fn submit(paths: AppPaths, args: AccountRecoverRuntimeArgs, json: bool) -> Result<()> {
    validate(&args.account_id, &args.request_id)?;
    if !original_task_matches(&args.account_id, &args.original_task) {
        return Err(RecoveryFailure::InvalidOriginalTask.into());
    }
    let (client, token) = authenticated(&paths)
        .await
        .map_err(|_| RecoveryFailure::Preparation)?;
    let result = client
        .recover_runtime(
            &token,
            &args.account_id,
            &args.original_task,
            &args.request_id,
            selected_action(&args),
        )
        .await;
    match result {
        Ok(data) => render(data, &args.request_id, json),
        Err(error) => Err(RecoveryFailure::submission(error.status_code()).into()),
    }
}

/// Read the original request without replaying account migration work.
pub async fn status(paths: AppPaths, args: AccountRecoveryStatusArgs, json: bool) -> Result<()> {
    validate(&args.account_id, &args.request_id)?;
    let (client, token) = authenticated(&paths)
        .await
        .map_err(|_| RecoveryFailure::Preparation)?;
    let data = client
        .runtime_recovery_status(&token, &args.account_id, &args.request_id)
        .await
        .map_err(|_| RecoveryFailure::StatusUnavailable)?;
    render(data, &args.request_id, json)
}

fn validate(account: &str, key: &str) -> Result<()> {
    if !canonical_uuid(account) || !canonical_uuid(key) {
        return Err(RecoveryFailure::InvalidIdentity.into());
    }
    Ok(())
}

async fn authenticated(paths: &AppPaths) -> Result<(ApiClient, String)> {
    let server = Config::load(paths)?
        .server_url
        .context("server URL is not configured; run agent-remote login first")?;
    let token = auth::load_user_token(paths, &server)
        .await?
        .context("an administrator user login is required; run agent-remote login first")?;
    Ok((ApiClient::new(server)?, token))
}

#[derive(Serialize)]
struct RecoveryOutput<'a> {
    schema_version: u8,
    request_id: &'a str,
    recovery: RuntimeRecovery,
    target_completion_confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    source_restoration_confirmed: Option<bool>,
}

fn render(data: RuntimeRecovery, key: &str, json: bool) -> Result<()> {
    let source = data.binding.action.is_some();
    let confirmed = data.status == RecoveryStatus::Succeeded;
    if json {
        println!(
            "{}",
            serde_json::to_string(&RecoveryOutput {
                schema_version: data.binding.version,
                request_id: key,
                recovery: data,
                target_completion_confirmed: confirmed && !source,
                source_restoration_confirmed: source.then_some(confirmed)
            })?
        );
        return Ok(());
    }
    Details::new()
        .field("Request ID", key)
        .field("Account", &data.binding.tool_account_id)
        .field("Original task", &data.binding.original_task_id)
        .field("Recovery task", &data.binding.task_id)
        .field("Status", data.status.as_str())
        .field(
            if source {
                "Source restoration confirmed"
            } else {
                "Target completion confirmed"
            },
            if confirmed { "yes" } else { "no" },
        )
        .render();
    Ok(())
}

fn selected_action(args: &AccountRecoverRuntimeArgs) -> Option<RecoveryAction> {
    if args.repair_source {
        Some(RecoveryAction::RepairSource)
    } else {
        args.verify_source.then_some(RecoveryAction::VerifySource)
    }
}
