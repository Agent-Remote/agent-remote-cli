//! Confirmed reset/restore with immutable previews and independent state-receipt recovery.

mod acceptance;
mod journal;
mod plan;
mod render;

pub(super) use acceptance::not_found;
pub(super) use journal::saved;
pub(super) use render::render;

use super::{context::ContextData, mutations, remote_result};
use crate::api::skill_state::StateAction;
use crate::cli::skills::{SkillMutationOptions, StateScopeArgs};
use crate::config::AppPaths;
use anyhow::{Context, Result};
use std::io::IsTerminal;

pub(super) async fn run(
    paths: AppPaths,
    selection: StateScopeArgs,
    action: StateAction,
    checkpoint: Option<String>,
    options: SkillMutationOptions,
    json: bool,
) -> Result<()> {
    if !options.dry_run && !options.yes && !std::io::stdin().is_terminal() {
        return mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm this state change, or --dry-run to inspect it.",
            2,
            json,
        );
    }
    let work = async {
        let context = ContextData::load(paths).await?;
        let plan = plan::prepare(
            &context,
            selection.selector(),
            action,
            checkpoint,
            options.dry_run,
        )
        .await?;
        if !options.dry_run && !options.yes && !plan.recovering {
            let preview = plan
                .preview
                .as_ref()
                .and_then(|p| p.data.as_ref())
                .context("state preview missing")?
                .clone();
            let request = plan.saved.request.clone();
            super::output::review(move || {
                render::show_plan(&render::Preview {
                    request: &request,
                    preview: &preview,
                    recovering_original_request: false,
                })
            })
            .await?;
            if !super::confirmation::confirm("Publish this state change for new sessions?").await? {
                return Err(remote_result::failure(
                    "CHANGE_CANCELLED",
                    "No state command was submitted.",
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
            return super::interruption::report("State planning interrupted. This invocation submitted no state change; any retained original request remains queryable.", None, json).await;
        }
        result = work => result?,
    };
    if let Some(result) = plan.recovered_result {
        return super::output::finish(json, move || render(&result, 0, json)).await;
    }
    if options.dry_run {
        let mut preview_request = plan.saved.request.clone();
        preview_request.dry_run = true;
        return super::output::finish(json, move || {
            render::preview(
                &preview_request,
                plan.preview.as_ref().context("state preview unavailable")?,
                plan.recovering,
                json,
            )
        })
        .await;
    }
    // Publication is synchronous on the Server; no deployment queue is invented for these receipts.
    let (result, code) = acceptance::execute(&context, plan.record, plan.recovering).await?;
    super::output::finish(json, move || render(&result, code, json)).await
}
