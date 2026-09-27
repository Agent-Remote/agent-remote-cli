//! Explicit updates and independent batch transactions with one machine-readable result.

use super::{
    acceptance,
    context::ContextData,
    mutations, remote_result,
    requests::Request,
    update_plan::{self, Plan},
    update_result::{self, Row},
    update_source, upload,
};
use crate::api::skills::SkillResult;
use crate::cli::skills::SkillUpdateArgs;
use crate::config::AppPaths;
use crate::local_state::skill_command_state;
use crate::skills::git_source::GitReference;
use anyhow::{Context, Result};
use serde_json::json;
use std::collections::BTreeSet;
use std::io::IsTerminal;

pub(super) async fn run(paths: AppPaths, args: SkillUpdateArgs, json_mode: bool) -> Result<()> {
    if let Err(error) = GitReference::parse(args.reference.as_deref()) {
        let (result, code) = update_result::failed(error);
        return update_result::display(result, code, json_mode).await;
    }
    if !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm updates, or --dry-run to inspect them.",
            2,
            json_mode,
        );
    }
    let context = match update_result::interruptible(ContextData::load(paths)).await {
        Ok(context) => context,
        Err(error) => {
            let (result, code) = update_result::failed(error);
            return update_result::display(result, code, json_mode).await;
        }
    };
    if let Some(identifier) = &args.skill {
        let result = async {
            let plan =
                update_result::interruptible(update_plan::prepare(&context, identifier, &args))
                    .await?;
            execute(&context, plan, &args).await
        }
        .await;
        let (result, code) = result.unwrap_or_else(update_result::failed);
        return update_result::display(result, code, json_mode).await;
    }
    batch(&context, &args, json_mode).await
}

async fn execute(
    context: &ContextData,
    plan: Plan,
    args: &SkillUpdateArgs,
) -> Result<(SkillResult<serde_json::Value>, i32)> {
    let preview = plan.preview();
    if args.options.dry_run {
        return Ok((update_result::envelope("planned", preview), 0));
    }
    let confirmed = if args.options.yes {
        true
    } else {
        update_result::interruptible(super::confirmation::review(&preview)).await?
    };
    if !confirmed {
        return Err(remote_result::failure(
            "CHANGE_CANCELLED",
            "This update was not submitted.",
            Some(plan.request.skill.clone()),
        ));
    }
    if !plan.content_retained {
        let package = plan
            .package
            .context("update plan is missing its captured package")?;
        update_result::interruptible(upload::package(
            &context.client,
            &context.token,
            &format!("upload-{}", plan.request.idempotency_key),
            package,
        ))
        .await?;
    }
    let (result, code) = acceptance::execute_result(
        context.paths.clone(),
        &context.client,
        &context.token,
        plan.record,
        plan.recovering,
        &args.options,
    )
    .await?;
    Ok((serde_json::from_value(serde_json::to_value(result)?)?, code))
}

async fn batch(context: &ContextData, args: &SkillUpdateArgs, json_mode: bool) -> Result<()> {
    let identity = (context.server.clone(), context.user.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_commands(&identity.0, &identity.1)
    })
    .await?;
    let mut rows = Vec::new();
    let mut processed = BTreeSet::new();
    // A lost automatic-update result must be recovered even if a later action removed/pinned it.
    for record in pending {
        if super::state_prune::saved(&record)?.is_some()
            || super::state_migrations::saved(&record)?.is_some()
            || super::state_mutations::saved(&record)?.is_some()
            || super::state_resolutions::saved(&record)?.is_some()
        {
            continue;
        }
        let Request::Update(request) = Request::retained(&record)? else {
            continue;
        };
        if request.stage || request.switch_tracking || request.item.source.kind != "git" {
            continue;
        }
        let id = request.skill.clone();
        let name = request.item.name.clone();
        let result = execute(context, Plan::retained(record)?, args)
            .await
            .unwrap_or_else(update_result::failed);
        let interrupted = result.1 == 130;
        rows.push(row(id.clone(), name, result));
        processed.insert(id);
        if interrupted {
            return update_result::display_batch(rows, args.options.dry_run, json_mode).await;
        }
    }
    let listing = update_result::interruptible(async {
        remote_result::data(
            context
                .client
                .list_skills(&context.token, None, None, false)
                .await?,
        )
    })
    .await;
    let library = match listing {
        Ok(library) => library,
        Err(error) => {
            rows.push(row(
                String::new(),
                "library".into(),
                update_result::failed(error),
            ));
            return update_result::display_batch(rows, args.options.dry_run, json_mode).await;
        }
    };
    for item in library.items.into_iter().filter(|item| !item.removed) {
        if !processed.insert(item.id.clone()) {
            continue;
        }
        let result = async {
            update_source::validate(&item)?;
            if let Some(reason) = update_source::skipped(&item) {
                return Ok((
                    update_result::envelope(
                        reason,
                        json!({"revision_id":item.default_revision_id}),
                    ),
                    0,
                ));
            }
            let plan =
                update_result::interruptible(update_plan::prepare(context, &item.id, args)).await?;
            execute(context, plan, args).await
        }
        .await
        .unwrap_or_else(update_result::failed);
        let interrupted = result.1 == 130;
        rows.push(row(item.id, item.name, result));
        if interrupted {
            break;
        }
    }
    update_result::display_batch(rows, args.options.dry_run, json_mode).await
}

fn row(
    skill_id: String,
    name: String,
    (result, exit_code): (SkillResult<serde_json::Value>, i32),
) -> Row {
    Row {
        skill_id,
        name,
        status: result.status.clone(),
        exit_code,
        result,
    }
}
