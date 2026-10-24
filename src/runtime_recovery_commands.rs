//! Explicit migration recovery with caller-retained request identities.

mod failure;

pub use failure::RecoveryContext;

use anyhow::{Context, Result};
use failure::RecoveryFailure;
use serde::Serialize;

use crate::api::runtime_recovery::{
    canonical_uuid, original_task_matches, RecoveryAction, RecoveryStatus, RuntimeRecovery,
};
use crate::auth;
use crate::cli::{AccountRecoverRuntimeArgs, AccountRecoveryStatusArgs};
use crate::config::{AppPaths, Config};
use crate::runtime_recovery::{self as shared, Action, Apply, Status};
use crate::terminal::Details;

/// Submit only an exact administrator-selected original migration and request key.
pub async fn submit(paths: AppPaths, args: AccountRecoverRuntimeArgs, json: bool) -> Result<()> {
    validate(&args.account_id, &args.request_id)?;
    if !original_task_matches(&args.account_id, &args.original_task) {
        return Err(RecoveryFailure::InvalidOriginalTask.into());
    }
    let server = authenticated(&paths)
        .await
        .map_err(|_| RecoveryFailure::Preparation)?;
    let action = match selected_action(&args) {
        None => Action::VerifyTarget,
        Some(RecoveryAction::VerifySource) => Action::VerifySource,
        Some(RecoveryAction::RepairSource) => Action::RepairSource,
    };
    let stored = shared::pending(&paths)
        .map_err(|_| RecoveryFailure::Preparation)?
        .items
        .into_iter()
        .find(|r| r.request_id == args.request_id);
    if let Some(record) = stored {
        if record.account_id != args.account_id
            || record.original.task_id != args.original_task
            || record.action != action
        {
            return Err(RecoveryFailure::Preparation.into());
        }
        let value = shared::status(
            &paths,
            Status {
                expected_context: record.context,
                account_id: record.account_id,
                request_id: record.request_id,
                expected_digest: Some(record.digest),
                expected_binding: record.binding,
            },
        )
        .await
        .map_err(|_| RecoveryFailure::StatusUnavailable)?;
        return render(value.recovery, &args.request_id, json);
    }
    let context = shared::authority(&paths, paths.home(), &server)
        .await
        .map_err(|_| RecoveryFailure::Preparation)?
        .context;
    let plan = shared::inspect(
        &paths,
        context.clone(),
        &args.account_id,
        &args.original_task,
        action,
    )
    .await
    .map_err(|_| RecoveryFailure::Preparation)?;
    let value = shared::apply(
        &paths,
        Apply {
            confirmed: true,
            expected_context: context,
            account_id: args.account_id,
            original: plan.original,
            action,
            expected_digest: plan.digest,
            request_id: args.request_id.clone(),
        },
    )
    .await
    .map_err(|e| {
        if e.submitted {
            RecoveryFailure::submission(e.http_status)
        } else {
            RecoveryFailure::Preparation
        }
    })?;
    render(value.recovery, &args.request_id, json)
}

/// Read the original request without replaying account migration work.
pub async fn status(paths: AppPaths, args: AccountRecoveryStatusArgs, json: bool) -> Result<()> {
    validate(&args.account_id, &args.request_id)?;
    let stored = shared::pending(&paths)
        .map_err(|_| RecoveryFailure::Preparation)?
        .items
        .into_iter()
        .find(|r| r.request_id == args.request_id);
    if args.forget && stored.is_none() {
        return Err(RecoveryFailure::Preparation.into());
    }
    if args.forget && !args.yes && !confirm_forget()? {
        return Err(RecoveryFailure::Preparation.into());
    }
    // Keep legacy human authentication renewal; definite rejected receipt removal
    // is deliberately offline and needs no credential preparation.
    let offline = args.forget && stored.as_ref().is_some_and(|r| r.phase == "rejected");
    let server = if offline {
        None
    } else {
        Some(
            authenticated(&paths)
                .await
                .map_err(|_| RecoveryFailure::Preparation)?,
        )
    };
    let input = if let Some(record) = stored {
        if record.account_id != args.account_id {
            return Err(RecoveryFailure::Preparation.into());
        }
        Status {
            expected_context: record.context,
            account_id: record.account_id,
            request_id: record.request_id,
            expected_digest: Some(record.digest),
            expected_binding: record.binding,
        }
    } else {
        let server = server.ok_or(RecoveryFailure::Preparation)?;
        let context = shared::authority(&paths, paths.home(), &server)
            .await
            .map_err(|_| RecoveryFailure::Preparation)?
            .context;
        Status {
            expected_context: context,
            account_id: args.account_id,
            request_id: args.request_id.clone(),
            expected_digest: None,
            expected_binding: None,
        }
    };
    if args.forget {
        let result = shared::forget(&paths, input)
            .await
            .map_err(|_| RecoveryFailure::StatusUnavailable)?;
        if json {
            println!("{}", serde_json::to_string(&result)?);
        } else {
            crate::terminal::success_line(
                "Local recovery receipt removed; remote recovery is unchanged",
            );
        }
        return Ok(());
    }
    let value = shared::status(&paths, input)
        .await
        .map_err(|_| RecoveryFailure::StatusUnavailable)?;
    render(value.recovery, &args.request_id, json)
}

fn validate(account: &str, key: &str) -> Result<()> {
    if !canonical_uuid(account) || !canonical_uuid(key) {
        return Err(RecoveryFailure::InvalidIdentity.into());
    }
    Ok(())
}

async fn authenticated(paths: &AppPaths) -> Result<String> {
    let server = Config::load(paths)?
        .server_url
        .context("server URL is not configured; run agent-remote login first")?;
    auth::load_user_token(paths, &server)
        .await?
        .context("an administrator user login is required; run agent-remote login first")?;
    Ok(server)
}

fn confirm_forget() -> Result<bool> {
    use std::io::{BufRead, Read, Write};
    eprint!("Forget this settled local recovery receipt only? [y/N] ");
    std::io::stderr().flush()?;
    let mut value = String::new();
    std::io::stdin().lock().take(256).read_line(&mut value)?;
    Ok(matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
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
