//! Separate cancellable preparation from journaled configuration acceptance.

use anyhow::Result;

use crate::api::ApiClient;
use crate::cli::skills::SkillMutationOptions;
use crate::config::AppPaths;
use crate::local_state::SkillCommandRecord;

/// Only the async command owns this handoff; input/capture workers cannot submit it.
pub(super) struct Submission {
    pub client: ApiClient,
    pub token: String,
    pub record: SkillCommandRecord,
    pub recovering: bool,
    pub options: SkillMutationOptions,
}

pub(super) async fn run(
    paths: AppPaths,
    preparation: impl std::future::Future<Output = Result<Option<Submission>>>,
    json: bool,
) -> Result<()> {
    let submission = tokio::select! {
        biased;
        signal = crate::skill_commands::interruption::cancelled() => {
            signal?;
            // Human stderr may still be held by the detached prompt writer.
            if json && !super::interruption::result_started() {
                return super::mutations::local_error(
                    "SOURCE_INTERRUPTED",
                    "Preparation interrupted; no configuration request was submitted by this invocation. Earlier retained operations remain queryable; content uploads may remain staged or stored.",
                    130, true,
                );
            }
            return Err(super::SkillExit(130).into());
        }
        result = preparation => result?,
    };
    if let Some(submission) = submission {
        super::acceptance::execute(
            paths,
            &submission.client,
            &submission.token,
            submission.record,
            submission.recovering,
            &submission.options,
            json,
        )
        .await
    } else {
        Ok(())
    }
}
