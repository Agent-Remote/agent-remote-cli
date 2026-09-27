//! Explicit retry selects ended transient failures once, before durable acceptance.

use anyhow::{bail, Result};
use sha2::{Digest, Sha256};
use std::io::IsTerminal;

use crate::cli::skills::SkillRetryArgs;
use crate::config::AppPaths;
use crate::local_state::{skill_command_state, SkillCommandRecord};

use super::configuration::{self, Submission};
use super::context::ContextData;
use super::requests::Request;
use super::retry_plan::Saved;

pub(super) async fn run(paths: AppPaths, args: SkillRetryArgs, json: bool) -> Result<()> {
    configuration::run(paths.clone(), Box::pin(prepare(paths, args, json)), json).await
}

async fn prepare(paths: AppPaths, args: SkillRetryArgs, json: bool) -> Result<Option<Submission>> {
    if !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return super::mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to retry the original failed targets, or --dry-run to inspect them.",
            2,
            json,
        );
    }
    let context = ContextData::load(paths).await?;
    let digest = format!(
        "{:x}",
        Sha256::digest(format!("deployment_retry:{}", args.operation_id))
    );
    let lookup = (context.server.clone(), context.user.clone(), digest.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    let recovering = pending.is_some();
    let proposed = match pending {
        Some(record) => record,
        None => {
            let result = context
                .client
                .skill_status(&context.token, &args.operation_id)
                .await?;
            let plan = match Saved::from_operation(&result) {
                Ok(plan) => plan,
                Err(_) => return super::mutations::local_error("OPERATION_NOT_RETRYABLE",
                    "The original operation has no eligible ended failed attempts. Inspect its status and resolve conflicts or unsupported targets first.", 1, json),
            };
            SkillCommandRecord {
                server_url: context.server,
                user_id: context.user,
                intent_digest: digest,
                idempotency_key: plan.request.idempotency_key.clone(),
                request_json: serde_json::to_string(&plan)?,
            }
        }
    };
    let Request::Retry(plan) = Request::retained(&proposed)? else {
        bail!("retained command is not a deployment retry");
    };
    if plan.operation_id != args.operation_id {
        bail!("retained retry operation differs");
    }
    if args.options.dry_run {
        let result = serde_json::json!({"schema_version":1,"operation_id":args.operation_id,
            "status":"planned","committed":false,"retryable":false,"errors":[],
            "data":{"request":plan.request,"recovering_original_request":recovering}});
        super::output::display(move || {
            if json {
                super::print_json(&result)?;
            } else {
                eprintln!("{}", serde_json::to_string_pretty(&result)?);
            }
            Ok(())
        })
        .await?;
        return Ok(None);
    }
    if !args.options.yes && !super::confirmation::review(&plan).await? {
        return super::mutations::local_error(
            "CHANGE_CANCELLED",
            "No retry was submitted.",
            1,
            json,
        );
    }
    Ok(Some(Submission {
        client: context.client,
        token: context.token,
        record: proposed,
        recovering,
        options: args.options,
    }))
}
