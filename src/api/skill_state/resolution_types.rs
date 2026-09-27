//! Exact resolution requests, native receipts and separately reported current migration status.

use super::{MergeConflict, ResolutionChoice, ResolutionTarget, StatePathDiff};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionRequest {
    pub idempotency_key: String,
    pub expected_revision: i64,
    pub choice: ResolutionChoice,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationResolutionPlan {
    pub migration_id: String,
    pub current_status: String,
    pub revision: i64,
    pub choices: Vec<ResolutionChoice>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct PublicationResolution {
    pub publication_id: String,
    pub operation_id: Option<String>,
    pub status: String,
    pub plan_revision: i64,
    pub ready: bool,
    pub choices: Vec<ResolutionChoice>,
    pub remaining: Vec<MergeConflict>,
    pub result_tree_digest: Option<String>,
    pub result_checkpoint_id: Option<String>,
    pub replacement_id: Option<String>,
    pub stale_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationResolutionBranch {
    pub name: String,
    pub state_id: String,
    pub skill_id: String,
    pub origin: String,
    pub revision_id: String,
    pub installation_epoch: i64,
    pub state_epoch: i64,
    pub checkpoint_id: Option<String>,
    pub result_checkpoint_id: Option<String>,
    pub changes: Vec<StatePathDiff>,
    pub original_changes: Vec<StatePathDiff>,
    pub modified: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationResolution {
    pub operation_kind: String,
    pub migration_id: String,
    pub operation_id: Option<String>,
    pub status: String,
    pub plan_revision: i64,
    pub choices: Vec<ResolutionChoice>,
    pub candidate_complete: bool,
    pub remaining: Vec<MergeConflict>,
    pub unit: Vec<String>,
    pub result_tree_digest: Option<String>,
    pub target_revision_id: String,
    pub target_modified: Option<bool>,
    pub target_changes: Option<Vec<StatePathDiff>>,
    pub original_changes: Option<Vec<StatePathDiff>>,
    pub directory_changes: Option<Vec<StatePathDiff>>,
    pub other_changed_roots: Vec<String>,
    pub replacement_id: Option<String>,
    pub stale_reasons: Vec<String>,
    pub recomputation_possible: bool,
    pub result_checkpoint_id: Option<String>,
    pub result_directory_id: Option<String>,
    pub migration_sequence: Option<i64>,
    pub affected: Vec<MigrationResolutionBranch>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationResolutionReceipt {
    pub result: MigrationResolution,
    pub current_status: String,
    pub replacement_id: Option<String>,
    pub superseded_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ResolutionOutcome {
    Publication {
        result: PublicationResolution,
    },
    Migration {
        result: Box<MigrationResolution>,
        current: Option<MigrationResolutionCurrent>,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MigrationResolutionCurrent {
    pub status: String,
    pub replacement_id: Option<String>,
    pub superseded_reason: Option<String>,
}

impl ResolutionOutcome {
    pub fn target(&self) -> ResolutionTarget {
        match self {
            Self::Publication { result } => ResolutionTarget {
                kind: super::ResolutionDomain::Publication,
                conflict_id: result.publication_id.clone(),
            },
            Self::Migration { result, .. } => ResolutionTarget {
                kind: super::ResolutionDomain::Migration,
                conflict_id: result.migration_id.clone(),
            },
        }
    }
    pub fn status(&self) -> &str {
        match self {
            Self::Publication { result } => &result.status,
            Self::Migration { result, .. } => &result.status,
        }
    }
    pub fn operation_id(&self) -> &Option<String> {
        match self {
            Self::Publication { result } => &result.operation_id,
            Self::Migration { result, .. } => &result.operation_id,
        }
    }
    pub fn choices(&self) -> &[ResolutionChoice] {
        match self {
            Self::Publication { result } => &result.choices,
            Self::Migration { result, .. } => &result.choices,
        }
    }
    pub fn revision(&self) -> i64 {
        match self {
            Self::Publication { result } => result.plan_revision,
            Self::Migration { result, .. } => result.plan_revision,
        }
    }
    pub fn digest(&self) -> &Option<String> {
        match self {
            Self::Publication { result } => &result.result_tree_digest,
            Self::Migration { result, .. } => &result.result_tree_digest,
        }
    }
    pub fn stale(&self) -> bool {
        match self {
            Self::Publication { result } => result.stale_reason.is_some(),
            Self::Migration { result, .. } => !result.stale_reasons.is_empty(),
        }
    }
}
