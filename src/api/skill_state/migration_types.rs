//! Immutable original migration/preparation receipts, distinct from current conflict drift.

use super::{MergeConflict, StatePathDiff, StatePrecondition};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MigrationBranch {
    pub revision_id: String,
    pub state_id: Option<String>,
    pub state_epoch: Option<i64>,
    pub checkpoint_id: Option<String>,
    pub expired: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct MigrationPrecondition {
    pub account_id: String,
    pub skill_id: String,
    pub name: String,
    pub installation_epoch: i64,
    pub library_generation: i64,
    pub directory_epoch: i64,
    pub directory_checkpoint_id: String,
    pub source: MigrationBranch,
    pub target: MigrationBranch,
    pub last_migration_id: Option<String>,
    pub last_migrated_checkpoint_id: Option<String>,
    pub last_sequence: i64,
    pub source_has_unmigrated_checkpoint: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct IncrementalOriginal {
    pub before: MigrationPrecondition,
    pub changes: Option<Vec<StatePathDiff>>,
    pub directory_changes: Option<Vec<StatePathDiff>>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PreparationOriginal {
    pub before: StatePrecondition,
    pub source_revision_id: Option<String>,
    pub source_checkpoint_id: Option<String>,
    pub source_epoch: Option<i64>,
    pub target_state_id: Option<String>,
    pub warnings: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum MigrationOriginalKind {
    Incremental(Box<IncrementalOriginal>),
    Initial(PreparationOriginal),
    Forward(PreparationOriginal),
    Older(PreparationOriginal),
    Resume(PreparationOriginal),
}

impl MigrationOriginalKind {
    pub fn mode(&self) -> &'static str {
        match self {
            Self::Incremental(_) => "incremental",
            Self::Initial(_) => "initial",
            Self::Forward(_) => "forward",
            Self::Older(_) => "older",
            Self::Resume(_) => "resume",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationOriginal {
    #[serde(flatten)]
    pub kind: MigrationOriginalKind,
    pub operation_id: Option<String>,
    pub status: String,
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
}
