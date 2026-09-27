//! One reviewed resolution choice, exact staged content and original-request recovery.

mod acceptance;
mod content;
mod journal;
mod plan;
mod preview;
mod source;

pub(super) use journal::saved;

use super::{context::ContextData, SkillExit};
use crate::api::skill_state::ResolutionOutcome;
use crate::api::skills::SkillResult;
use crate::cli::skills::StateResolveArgs;
use crate::config::AppPaths;
use crate::skills::state_snapshot::CaptureCancellation;
use anyhow::Result;
use std::io::IsTerminal;

pub(super) async fn run(paths: AppPaths, args: StateResolveArgs, json: bool) -> Result<()> {
    if !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return super::mutations::local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm this resolution choice, or --dry-run to inspect it.",
            2,
            json,
        );
    }
    let cancellation = CaptureCancellation::default();
    struct CancelOnDrop(CaptureCancellation);
    impl Drop for CancelOnDrop {
        fn drop(&mut self) {
            self.0.cancel();
        }
    }
    let _capture_guard = CancelOnDrop(cancellation.clone());
    let work = async {
        let context = ContextData::load(paths).await?;
        let plan = plan::prepare(&context, &args, &cancellation).await?;
        Ok::<_, anyhow::Error>((context, plan))
    };
    let (context, plan) = tokio::select! {
        biased;
        signal = super::interruption::cancelled() => {
            signal?;
            return super::interruption::report("Resolution planning interrupted; this invocation submitted no resolution choice. Any original retained request remains queryable.", Some(args.conflict), json).await;
        }
        result = work => result?,
    };
    match plan {
        plan::Plan::ReadOnly(result) => {
            super::output::finish(json, move || preview::render(&result, json)).await
        }
        plan::Plan::Recovered(result) => {
            super::output::finish(json, move || render(&result, exit_code(&result), json)).await
        }
        plan::Plan::Submit { record, recovering } => {
            let (result, code) = acceptance::execute(&context, record, recovering).await?;
            super::output::finish(json, move || render(&result, code, json)).await
        }
    }
}

pub(super) fn exit_code(result: &SkillResult<ResolutionOutcome>) -> i32 {
    if !result.committed
        || !result.errors.is_empty()
        || result.status == "pending"
        || result.status == "superseded"
    {
        1
    } else {
        0
    }
}

pub(super) fn render(result: &SkillResult<ResolutionOutcome>, code: i32, json: bool) -> Result<()> {
    if json {
        super::print_json(result)?;
    } else {
        super::render_summary(result);
        show(result)?;
        if result.status == "pending" {
            eprintln!("Choice saved. Other conflicts remain; no checkpoint was published.");
        }
        if result.status == "superseded" {
            eprintln!("The original comparison changed. Inspect the replacement before making a new choice.");
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
