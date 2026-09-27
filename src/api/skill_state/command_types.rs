//! State publication requests and original immutable receipts, independent of library deployment.

use super::{StateOrigin, StatePathDiff, StateSelector};
use crate::api::skills::SkillResolvedRule;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateAction {
    Reset,
    Restore,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DirectoryMode {
    Legacy,
    Migrating,
    ManagedV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StateTarget {
    pub name: String,
    pub skill_id: String,
    pub origin: StateOrigin,
    pub revision_id: String,
    pub installation_epoch: i64,
    pub state_id: Option<String>,
    pub state_epoch: Option<i64>,
    pub head_checkpoint_id: Option<String>,
    pub expired: bool,
    pub rule: SkillResolvedRule,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StatePrecondition {
    pub library_generation: i64,
    pub directory_mode: DirectoryMode,
    pub directory_epoch: Option<i64>,
    pub directory_head_id: Option<String>,
    pub targets: Vec<StateTarget>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct CurrentState {
    pub selector: StateSelector,
    pub precondition: StatePrecondition,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StateCommandRequest {
    pub idempotency_key: String,
    pub action: StateAction,
    pub selector: StateSelector,
    pub expected: StatePrecondition,
    pub checkpoint_id: Option<String>,
    pub dry_run: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateBranchChanges {
    pub skill_id: String,
    pub state_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub baseline_available: bool,
    pub changes: Option<Vec<StatePathDiff>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateCommandStatus {
    Preview,
    Published,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct StateCommandView {
    pub operation_id: Option<String>,
    pub status: StateCommandStatus,
    pub action: StateAction,
    pub before: CurrentState,
    pub result_tree_digest: String,
    pub result_checkpoint_id: Option<String>,
    pub changes: Vec<StatePathDiff>,
    pub branch_changes: Vec<StateBranchChanges>,
    pub affected: Vec<StateTarget>,
    pub directory_epoch_advances: bool,
    pub superseded_conflicts: u64,
}
