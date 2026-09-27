//! Prune metadata stays bounded per page; the exact command never embeds loss rows.

use super::StateSelector;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneBinding {
    pub selector: StateSelector,
    pub cutoff: String,
    pub all_unreferenced: bool,
    pub plan_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneSummary {
    pub binding: PruneBinding,
    pub ready: bool,
    pub history_losses: u64,
    pub groups: u64,
    pub blocked_histories: u64,
    pub compacted_directories: u64,
    pub compacted_items: u64,
    pub trees: u64,
    pub package_bytes: u64,
    pub state_bytes: u64,
    pub pending_file_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrunePreviewRequest {
    pub selector: StateSelector,
    pub all_unreferenced: bool,
    pub cursor: Option<String>,
    pub limit: u16,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrunePreviewPage {
    pub summary: PruneSummary,
    pub offset: u64,
    pub total: u64,
    pub rows: Vec<PruneDisclosure>,
    pub next_cursor: Option<String>,
    pub confirmation: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneRequest {
    pub idempotency_key: String,
    pub confirmation: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneReceipt {
    pub operation_id: String,
    pub idempotency_key: String,
    pub status: String,
    pub confirmation_fingerprint: String,
    pub summary: PruneSummary,
    pub disclosure_rows: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PruneReceiptPage {
    pub operation_id: String,
    pub offset: u64,
    pub total: u64,
    pub rows: Vec<PruneDisclosure>,
    pub next_offset: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneProgress {
    pub operation_id: String,
    pub pending_tasks: u64,
    pub completed_tasks: u64,
    pub pending_file_bytes: u64,
    pub deleted_file_bytes: u64,
    pub retrying_tasks: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PruneIdentity {
    pub kind: String,
    pub id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PruneDisclosure {
    History {
        history: PruneIdentity,
        retained: bool,
        selected: bool,
        group: Option<u64>,
        blockers: Vec<String>,
        dependency_blocked: bool,
        protected_by: Vec<String>,
        released_at: Option<String>,
        expires_at: Option<String>,
        archived: bool,
        content_digests: Vec<String>,
    },
    Dependency {
        consumer: PruneIdentity,
        dependency: PruneIdentity,
        relation: String,
    },
    Compaction {
        scope: String,
        checkpoint_id: String,
        state_id: Option<String>,
        epoch: Option<i64>,
        original_digest: String,
        result_digest: String,
        replacement_id: Option<String>,
    },
    Member {
        directory_id: String,
        checkpoint_id: String,
        state_id: String,
        name: String,
        action: String,
    },
}
