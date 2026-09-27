//! Metadata-only review and verified dry-run must agree before a real request is journaled.

use crate::api::skill_state::*;
use crate::api::skills::SkillResult;
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "verification", content = "preview", rename_all = "snake_case")]
pub(super) enum Review {
    Metadata(Box<SkillResult<ResolutionContentPreview>>),
    Verified(Box<SkillResult<ResolutionOutcome>>),
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Preview {
    pub source: super::source::Source,
    #[serde(flatten)]
    pub review: Review,
}

pub(super) fn render(value: &Preview, json: bool) -> Result<()> {
    if json {
        crate::skill_commands::print_json(&SkillResult {
            schema_version: 1,
            operation_id: None,
            status: "preview".to_owned(),
            committed: false,
            retryable: false,
            data: Some(value),
            errors: vec![],
        })?;
    } else {
        super::show(value)?;
        eprintln!("This review saves no choice. Metadata-only candidates still require content, authorization, quota and head checks.");
    }
    Ok(())
}

pub(super) fn verify_metadata(
    reviewed: &ResolutionContentPreview,
    verified: &ResolutionOutcome,
) -> Result<()> {
    if reviewed.choices != verified.choices()
        || reviewed.result_tree_digest != *verified.digest()
        || verified.stale()
    {
        return Err(changed());
    }
    match verified {
        ResolutionOutcome::Publication { result } => {
            if reviewed.kind != ResolutionDomain::Publication
                || reviewed.candidate_complete != result.ready
                || reviewed.remaining != result.remaining
            {
                return Err(changed());
            }
        }
        ResolutionOutcome::Migration { result, .. } => {
            if reviewed.kind != ResolutionDomain::Migration
                || reviewed.candidate_complete != result.candidate_complete
                || reviewed.remaining != result.remaining
                || reviewed.unit != result.unit
                || reviewed.target_revision_id.as_ref() != Some(&result.target_revision_id)
                || reviewed.target_modified != result.target_modified
                || reviewed.target_changes != result.target_changes
                || reviewed.original_changes != result.original_changes
                || reviewed.changes != result.directory_changes
            {
                return Err(changed());
            }
        }
    }
    Ok(())
}

fn changed() -> anyhow::Error {
    crate::skill_commands::remote_result::failure("RESOLUTION_PREVIEW_CHANGED","The verified candidate differs from the reviewed content. No resolution choice was submitted; inspect the original conflict again.",None)
}
