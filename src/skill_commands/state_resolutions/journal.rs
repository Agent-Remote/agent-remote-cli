//! Retain the exact accepted request and reviewed result; receipt comparison ignores only assigned IDs.

use crate::api::skill_state::*;
use crate::api::skills::SkillResult;
use crate::local_state::SkillCommandRecord;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    StateResolution,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::skill_commands) struct Saved {
    pub(super) command: Kind,
    pub target: ResolutionTarget,
    pub request: ResolutionRequest,
    pub prior_choices: Vec<ResolutionChoice>,
    pub reviewed: ResolutionOutcome,
    pub(super) source: super::source::Source,
}

impl Saved {
    pub fn validate_receipt(&self, result: &SkillResult<ResolutionOutcome>) -> Result<()> {
        let Some(view) = &result.data else {
            return Ok(());
        };
        self.source.validate_outcome(view)?;
        if view.target() != self.target
            || view.operation_id() != &result.operation_id
            || view.status() != result.status
            || !result.committed
        {
            bail!("resolution receipt identity differs");
        }
        if view.stale() {
            if view.status() != "superseded"
                || view.revision() != self.request.expected_revision
                || view.choices() != self.prior_choices
            {
                bail!("supersession unexpectedly changed the original plan");
            }
            if let (
                ResolutionOutcome::Migration { result: a, .. },
                ResolutionOutcome::Migration { result: b, .. },
            ) = (view, &self.reviewed)
            {
                if a.target_revision_id != b.target_revision_id {
                    bail!("supersession changed the original target version");
                }
            }
        } else if view.revision() != self.request.expected_revision + 1
            || review_form(view) != review_form(&self.reviewed)
        {
            bail!("accepted resolution differs from the reviewed candidate");
        }
        Ok(())
    }
}

pub(super) fn review_form(value: &ResolutionOutcome) -> ResolutionOutcome {
    let mut value = value.clone();
    match &mut value {
        ResolutionOutcome::Publication { result } => {
            result.status = "preview".to_owned();
            result.operation_id = None;
            result.plan_revision = 0;
            result.result_checkpoint_id = None;
        }
        ResolutionOutcome::Migration { result, current } => {
            *current = None;
            result.status = "preview".to_owned();
            result.operation_id = None;
            result.plan_revision = 0;
            result.result_checkpoint_id = None;
            result.result_directory_id = None;
            result.migration_sequence = None;
            for branch in &mut result.affected {
                branch.result_checkpoint_id = None;
            }
        }
    }
    value
}

pub(in crate::skill_commands) fn saved(record: &SkillCommandRecord) -> Result<Option<Saved>> {
    #[derive(Deserialize)]
    struct Tag {
        command: Option<String>,
    }
    let tag: Tag = serde_json::from_str(&record.request_json)?;
    if tag.command.as_deref() != Some("state_resolution") {
        return Ok(None);
    }
    let value: Saved = serde_json::from_str(&record.request_json)?;
    value.request.validate()?;
    value.source.validate_outcome(&value.reviewed)?;
    value
        .request
        .validate_preview(&value.target, &value.reviewed)?;
    if value.request.dry_run
        || value.request.idempotency_key != record.idempotency_key
        || value.target != value.reviewed.target()
        || value.reviewed.status() != "preview"
        || value.reviewed.operation_id().is_some()
        || value.reviewed.revision() != value.request.expected_revision
        || (!value.reviewed.stale()
            && value.reviewed.choices().last() != Some(&value.request.choice))
        || serde_json::to_string(&value)? != record.request_json
    {
        bail!("invalid retained resolution request");
    }
    Ok(Some(value))
}
