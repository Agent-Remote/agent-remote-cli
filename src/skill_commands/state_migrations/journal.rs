//! Metadata-only migration journal binds exact versions, preconditions and reviewed content.

use crate::api::skill_state::{
    MigrationReceipt, MigrationRequest, MigrationSelector, MigrationView,
};
use crate::api::skills::SkillResult;
use crate::local_state::SkillCommandRecord;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum Kind {
    #[serde(rename = "state_migration")]
    Migration,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::skill_commands) struct Saved {
    pub(super) command: Kind,
    pub(super) selection: MigrationSelector,
    pub request: MigrationRequest,
    pub(super) reviewed: MigrationView,
}

impl Saved {
    pub(super) fn validate_view(&self, view: &MigrationView, committed: bool) -> Result<()> {
        view.validate(committed)?;
        let mut normalized = view.clone();
        normalized.operation_id = None;
        normalized.result_checkpoint_id = None;
        normalized.result_directory_id = None;
        normalized.migration_sequence = None;
        if serde_json::to_value(&normalized)? != serde_json::to_value(&self.reviewed)? {
            bail!("migration receipt differs from the confirmed original comparison");
        }
        Ok(())
    }

    pub fn validate_receipt(&self, result: &SkillResult<MigrationReceipt>) -> Result<()> {
        if let Some(receipt) = &result.data {
            self.validate_view(&receipt.result, true)?;
        }
        Ok(())
    }
}

pub(in crate::skill_commands) fn saved(record: &SkillCommandRecord) -> Result<Option<Saved>> {
    #[derive(Deserialize)]
    struct Tag {
        command: Option<String>,
    }
    let tag: Tag = serde_json::from_str(&record.request_json)?;
    if tag.command.as_deref() != Some("state_migration") {
        return Ok(None);
    }
    let saved: Saved = serde_json::from_str(&record.request_json)?;
    let r = &saved.request;
    r.validate()?;
    saved.reviewed.validate(false)?;
    if r.dry_run
        || r.idempotency_key != record.idempotency_key
        || r.selector.skill != r.expected.skill_id
        || r.selector.from_revision != r.expected.source.revision_id
        || r.selector.to_revision != r.expected.target.revision_id
        || saved.reviewed.before != r.expected
        || saved.selection.account_id != r.selector.account_id
        || (saved.selection.skill != r.expected.skill_id
            && saved.selection.skill != r.expected.name)
        || serde_json::to_string(&saved)? != record.request_json
        || super::plan::intent(&saved.selection)? != record.intent_digest
    {
        bail!("invalid retained migration request");
    }
    Ok(Some(saved))
}
