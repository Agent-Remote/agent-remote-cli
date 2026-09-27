//! Exact compact confirmation and review identity use the existing owner/origin-bound journal.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::api::skill_state::{PruneReceipt, PruneRequest, PruneSummary, StateSelector};
use crate::api::skills::SkillResult;
use crate::local_state::SkillCommandRecord;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) enum Kind {
    #[serde(rename = "state_prune")]
    Prune,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::skill_commands) struct Saved {
    pub(super) command: Kind,
    pub(super) selection: StateSelector,
    pub(super) all_unreferenced: bool,
    pub request: PruneRequest,
    pub(super) summary: PruneSummary,
    pub(super) total: u64,
}

pub(super) fn intent(selection: &StateSelector, early: bool) -> Result<String> {
    Ok(format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&("state_prune", selection, early))?)
    ))
}

impl Saved {
    pub fn validate_receipt(&self, value: &SkillResult<PruneReceipt>) -> Result<()> {
        self.request.validate_receipt(value)?;
        if let Some(receipt) = &value.data {
            if receipt.summary != self.summary || receipt.disclosure_rows != self.total {
                bail!("prune receipt differs from the confirmed original plan");
            }
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
    if tag.command.as_deref() != Some("state_prune") {
        return Ok(None);
    }
    let saved: Saved = serde_json::from_str(&record.request_json)?;
    saved.request.validate()?;
    saved.summary.validate()?;
    let binding = &saved.summary.binding;
    if !saved.summary.ready
        || saved.total > 10_000_000
        || saved.request.idempotency_key != record.idempotency_key
        || saved.selection.account_id != binding.selector.account_id
        || saved.selection.scope != binding.selector.scope
        || saved.all_unreferenced != binding.all_unreferenced
        || serde_json::to_string(&saved)? != record.request_json
        || intent(&saved.selection, saved.all_unreferenced)? != record.intent_digest
    {
        bail!("invalid retained prune request");
    }
    if let Some(source) = saved
        .selection
        .skill
        .as_ref()
        .filter(|s| uuid::Uuid::parse_str(s).is_ok())
    {
        if binding.selector.skill.as_ref() != Some(source) {
            bail!("retained prune source differs");
        }
    }
    Ok(Some(saved))
}
