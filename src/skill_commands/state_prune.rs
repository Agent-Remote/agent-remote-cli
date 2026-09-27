//! Complete prune review, single confirmation, and exact original-request recovery.

mod acceptance;
mod journal;
mod plan;
mod review;
mod spool;
mod status;
pub(super) use journal::saved;
pub(super) use status::display as display_status;

use std::cell::Cell;
use std::io::IsTerminal;

use anyhow::{Context, Result};
use serde_json::json;

use super::{context::ContextData, remote_result, state_mutations, SkillExit};
use crate::api::skill_state::PruneReceipt;
use crate::api::skills::SkillResult;
use crate::cli::skills::StatePruneArgs;
use crate::config::AppPaths;

pub(super) async fn run(paths: AppPaths, args: StatePruneArgs, json: bool) -> Result<()> {
    if !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return super::mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm prune, or --dry-run to inspect the complete loss list.",
            2,
            json,
        );
    }
    let interruption = tokio::signal::ctrl_c();
    tokio::pin!(interruption);
    let displaying = Cell::new(false);
    let work = async {
        let context = ContextData::load(paths).await?;
        let selection = args.selection.selector();
        let plan = plan::prepare(&context, &selection, args.all_unreferenced).await?;
        match plan {
            plan::Plan::Pending { record, saved } => {
                if args.options.dry_run {
                    let result = context
                        .client
                        .skill_prune_operation_by_key(
                            &context.token,
                            &saved.request.idempotency_key,
                        )
                        .await?;
                    if result.data.is_some() {
                        saved.validate_receipt(&result)?;
                        return Ok((context, None, Some(result), true));
                    }
                    if !state_mutations::not_found(&result) {
                        remote_result::data(result)?;
                    }
                    let view = envelope(
                        "unknown",
                        json!({"summary":saved.summary,"disclosure_rows":saved.total,"disclosure_available":false,"recovering_original_request":true,"idempotency_key":saved.request.idempotency_key,"message":"Original acceptance is not yet known. No new preview or command was submitted; this saved summary is not a reconstructed loss preview."}),
                    );
                    super::state_migrations::render(&view, 1, json)?;
                    return Ok((context, None, None, true));
                }
                Ok((context, Some(record), None, true))
            }
            plan::Plan::Fresh(review) => {
                let ready = review.summary.ready;
                let view = envelope(
                    "preview",
                    json!({"summary":review.summary,"disclosure_rows":review.total,"recovering_original_request":false}),
                );
                review
                    .spool
                    .display(view, args.options.dry_run && json, &displaying)
                    .await?;
                if args.options.dry_run {
                    if !ready {
                        return Err(SkillExit(1).into());
                    }
                    return Ok((context, None, None, false));
                }
                if !ready {
                    return Err(remote_result::failure(
                        "CONTENT_REFERENCED",
                        "The complete prune plan is blocked; nothing was submitted.",
                        Some(selection.account_id),
                    ));
                }
                if !args.options.yes && !super::confirmation::confirm("Permanently retire the selected recovery history and compact the displayed views?").await? {
                    return Err(remote_result::failure("CHANGE_CANCELLED", "No prune command was submitted.", None));
                }
                let record = plan::record(
                    &context,
                    selection,
                    review.summary,
                    review.total,
                    review
                        .confirmation
                        .context("complete prune confirmation missing")?,
                )?;
                Ok((context, Some(record), None, false))
            }
        }
    };
    let (context, record, recovered, recovering) = tokio::select! {
        result = work => result?,
        signal = &mut interruption => {
            signal?;
            if displaying.get() {
                return Err(SkillExit(130).into());
            }
            let error = remote_result::failure("SKILL_INTERRUPTED", "Prune review interrupted. This invocation submitted no cleanup; any saved original request remains queryable.", None);
            super::print_failure(&error, json);
            return Err(SkillExit(130).into());
        }
    };
    if let Some(result) = recovered {
        return render(&result, 0, json);
    }
    let Some(record) = record else {
        return Ok(());
    };
    // Logical cleanup is synchronous; a receipt never claims the separate disk worker has finished.
    let (result, code) =
        acceptance::execute(&context, record, recovering, &mut interruption).await?;
    render(&result, code, json)
}

pub(super) fn envelope(status: &str, data: serde_json::Value) -> SkillResult<serde_json::Value> {
    SkillResult {
        schema_version: 1,
        operation_id: None,
        status: status.to_owned(),
        committed: false,
        retryable: false,
        data: Some(data),
        errors: vec![],
    }
}

pub(super) fn render(result: &SkillResult<PruneReceipt>, code: i32, json: bool) -> Result<()> {
    if !json && result.committed {
        eprintln!("Logical cleanup accepted. Physical deletion may still be pending; use skill status to inspect its progress.");
    }
    super::state_migrations::render(result, code, json)
}
