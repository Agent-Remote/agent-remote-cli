//! Explicit incremental migration wire types, separate from first-use preparation.

use super::{MergeConflict, MigrationPrecondition, StatePathDiff};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MigrationSelector {
    pub account_id: String,
    pub skill: String,
    pub from_revision: String,
    pub to_revision: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationRequest {
    pub selector: MigrationSelector,
    pub expected: MigrationPrecondition,
    pub idempotency_key: String,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationView {
    pub mode: String,
    pub operation_id: Option<String>,
    pub status: String,
    pub before: MigrationPrecondition,
    pub base_source: String,
    pub current_source: String,
    pub incoming_source: String,
    pub base_digest: String,
    pub current_digest: String,
    pub incoming_digest: String,
    pub result_tree_digest: Option<String>,
    pub result_checkpoint_id: Option<String>,
    pub result_directory_id: Option<String>,
    pub migration_sequence: Option<i64>,
    pub conflicts: Vec<MergeConflict>,
    pub changes: Option<Vec<StatePathDiff>>,
    pub directory_changes: Option<Vec<StatePathDiff>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MigrationReceipt {
    pub result: MigrationView,
    pub current_status: String,
    pub replacement_id: Option<String>,
    pub superseded_reason: Option<String>,
}
