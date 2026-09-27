//! Exact state requests and the preview's content identity in the shared metadata journal.

use crate::api::skill_state::{StateCommandRequest, StateCommandView};
use crate::api::skills::SkillResult;
use crate::local_state::SkillCommandRecord;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    State,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::skill_commands) struct Saved {
    pub(super) command: Kind,
    pub request: StateCommandRequest,
    pub preview_tree_digest: String,
}

impl Saved {
    pub fn validate_receipt(&self, result: &SkillResult<StateCommandView>) -> Result<()> {
        self.request.validate_receipt(result)?;
        if result
            .data
            .as_ref()
            .is_some_and(|view| view.result_tree_digest != self.preview_tree_digest)
        {
            bail!("state result differs from confirmed tree");
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
    if tag.command.as_deref() != Some("state") {
        return Ok(None);
    }
    let saved: Saved = serde_json::from_str(&record.request_json)?;
    saved.request.validate()?;
    if saved.request.dry_run
        || saved.request.idempotency_key != record.idempotency_key
        || saved.preview_tree_digest.len() != 64
        || !saved
            .preview_tree_digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || serde_json::to_string(&saved)? != record.request_json
    {
        bail!("invalid retained state request");
    }
    Ok(Some(saved))
}
