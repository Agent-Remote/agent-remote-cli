//! Saved conflict identities and original provenance, independent of source-file acquisition.

use crate::api::skill_state::*;
use crate::skill_commands::{context::ContextData, remote_result};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "conflict", rename_all = "snake_case")]
pub(super) enum Source {
    Publication(Box<PublicationConflict>),
    Migration(Box<MigrationConflict>),
}
impl Source {
    pub(super) fn borrowed(&self) -> ResolutionPreviewSource<'_> {
        match self {
            Self::Publication(v) => ResolutionPreviewSource::Publication(v),
            Self::Migration(v) => ResolutionPreviewSource::Migration(v),
        }
    }
    pub(super) fn validate_outcome(&self, view: &ResolutionOutcome) -> Result<()> {
        if self.borrowed().target()? != view.target() {
            bail!("resolution changed the original conflict");
        }
        if let (Self::Migration(original), ResolutionOutcome::Migration { result, .. }) =
            (self, view)
        {
            if result.target_revision_id != original.live.target.revision_id {
                bail!("resolution changed the original target version");
            }
            if result
                .affected
                .first()
                .is_some_and(|branch| branch.name != original.summary.name)
            {
                bail!("resolution omitted the original target branch");
            }
            for branch in &result.affected {
                if branch.name == original.summary.name
                    && (branch.skill_id != original.summary.skill_id
                        || branch.state_id != original.summary.target_state_id
                        || branch.state_epoch != original.summary.target_epoch
                        || branch.revision_id != original.live.target.revision_id
                        || branch.installation_epoch != original.summary.installation_epoch
                        || branch.checkpoint_id != original.live.target.checkpoint_id)
                {
                    bail!("resolution changed the original target branch");
                }
            }
        }
        Ok(())
    }
}

pub(super) async fn load(
    context: &ContextData,
    id: &str,
) -> Result<(Source, i64, Vec<ResolutionChoice>)> {
    let publication = context
        .client
        .skill_publication_conflict(&context.token, id)
        .await?;
    let missing = publication.data.is_none()
        && publication.status == "failed"
        && !publication.committed
        && !publication.retryable
        && publication.operation_id.is_none()
        && publication.errors.len() == 1
        && publication.errors[0].code == "CONFLICT_NOT_FOUND";
    if !missing {
        let value = remote_result::data(publication)?;
        let revision = value.plan_revision;
        let choices = value.choices.clone();
        return Ok((Source::Publication(Box::new(value)), revision, choices));
    }
    let value = remote_result::data(
        context
            .client
            .skill_migration_conflict(&context.token, id)
            .await?,
    )?;
    let plan = remote_result::data(
        context
            .client
            .skill_migration_resolution_plan(&context.token, id)
            .await?,
    )?;
    Ok((
        Source::Migration(Box::new(value)),
        plan.revision,
        plan.choices,
    ))
}
