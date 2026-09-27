//! Confirm explicit version migration once and preserve original receipts through recovery.

mod acceptance;
mod journal;
mod plan;
pub(super) use journal::saved;

use super::{context::ContextData, remote_result, SkillExit};
use crate::api::skill_state::{MigrationReceipt, MigrationSelector, MigrationView};
use crate::api::skills::SkillResult;
use crate::cli::skills::StateMigrateArgs;
use crate::config::AppPaths;
use anyhow::{Context, Result};
use std::io::IsTerminal;

pub(super) async fn run(paths: AppPaths, args: StateMigrateArgs, json: bool) -> Result<()> {
    if args.from_revision == args.to_revision {
        return super::mutations::local_error(
            "INVALID_REQUEST",
            "Migration requires two different revisions.",
            2,
            json,
        );
    }
    if !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return super::mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm this migration, or --dry-run to inspect it.",
            2,
            json,
        );
    }
    let work = async {
        let context = ContextData::load(paths).await?;
        let selection = MigrationSelector {
            account_id: args.account_id,
            skill: args.skill,
            from_revision: args.from_revision,
            to_revision: args.to_revision,
        };
        let plan = plan::prepare(&context, selection, args.options.dry_run).await?;
        if !args.options.dry_run && !args.options.yes && !plan.recovering {
            let reviewed = plan.saved.reviewed.clone();
            super::output::review(move || show(&reviewed)).await?;
            let question = if plan.saved.reviewed.status == "conflicted" {
                "Retain this migration conflict and its complete comparison for resolution?"
            } else {
                "Publish this migration to the target branch for new sessions?"
            };
            if !super::confirmation::confirm(question).await? {
                return Err(remote_result::failure(
                    "CHANGE_CANCELLED",
                    "No migration was submitted.",
                    None,
                ));
            }
        }
        Ok::<_, anyhow::Error>((context, plan))
    };
    let (context, plan) = tokio::select! {
        biased;
        signal = super::interruption::cancelled() => {
            signal?;
            return super::interruption::report("Migration planning interrupted. This invocation submitted no migration; any retained original request remains queryable.", None, json).await;
        }
        result = work => result?,
    };
    if let Some(result) = plan.recovered {
        return super::output::finish(json, move || render(&result, exit_code(&result), json))
            .await;
    }
    if args.options.dry_run {
        let preview = plan.preview.context("migration preview unavailable")?;
        let code = if preview.status == "conflicted" { 1 } else { 0 };
        return super::output::finish(json, move || render(&preview, code, json)).await;
    }
    // Synchronous publication has no deployment queue; waiting flags do not invent one.
    let (result, code) = acceptance::execute(&context, plan.record, plan.recovering).await?;
    super::output::finish(json, move || render(&result, code, json)).await
}

fn receipt(result: SkillResult<MigrationView>) -> SkillResult<MigrationReceipt> {
    SkillResult {
        schema_version: result.schema_version,
        operation_id: result.operation_id,
        status: result.status,
        committed: result.committed,
        retryable: result.retryable,
        errors: result.errors,
        data: result.data.map(|view| MigrationReceipt {
            current_status: view.status.clone(),
            result: view,
            replacement_id: None,
            superseded_reason: None,
        }),
    }
}

pub(super) fn exit_code(result: &SkillResult<MigrationReceipt>) -> i32 {
    if result.committed
        && result.data.is_some()
        && result.status == "ready"
        && result.errors.is_empty()
    {
        0
    } else {
        1
    }
}

pub(super) fn render<T: serde::Serialize>(
    result: &SkillResult<T>,
    code: i32,
    json: bool,
) -> Result<()> {
    if json {
        super::print_json(result)?;
    } else {
        super::render_summary(result);
        show(result)?;
        if result.status == "conflicted" {
            eprintln!(
                "Migration conflicts require resolution; no target checkpoint was published."
            );
        }
        if result.status == "superseded" {
            eprintln!("The original migration was superseded. Inspect its replacement before starting another migration.");
        }
    }
    if code == 0 {
        Ok(())
    } else {
        Err(SkillExit(code).into())
    }
}
fn show(value: &impl serde::Serialize) -> Result<()> {
    for line in serde_json::to_string_pretty(value)?.lines() {
        eprintln!("{}", super::safe(line));
    }
    Ok(())
}
