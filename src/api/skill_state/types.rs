//! Exact state query wire types; pending bytes remain distinct from checkpoints.

use serde::{Deserialize, Serialize};

use crate::skills::manifest::{Entry, Manifest};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum StateScope {
    Item,
    AccountDirectory,
}

impl StateScope {
    pub(super) fn wire(self) -> &'static str {
        match self {
            Self::Item => "item",
            Self::AccountDirectory => "account-directory",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StateSelector {
    pub account_id: String,
    pub scope: StateScope,
    pub skill: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StateOrigin {
    UserLibrary,
    AccountLocal,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointStorage {
    Server,
    Expired,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Checkpoint {
    pub id: String,
    pub account_id: String,
    pub scope: StateScope,
    pub state_id: Option<String>,
    pub skill_id: Option<String>,
    pub origin: Option<StateOrigin>,
    pub revision_id: Option<String>,
    pub installation_epoch: Option<i64>,
    pub state_epoch: Option<i64>,
    pub directory_epoch: Option<i64>,
    pub backing_directory_id: Option<String>,
    pub current_state_epoch: Option<i64>,
    pub current_directory_epoch: Option<i64>,
    pub subtree_prefix: String,
    pub parent_id: Option<String>,
    pub content_digest: String,
    pub retained: bool,
    pub is_head: bool,
    pub invalid_skill_format: bool,
    pub source_session_reference_id: Option<String>,
    pub finalization_id: Option<String>,
    pub finalization_status: Option<String>,
    pub storage_location: CheckpointStorage,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<crate::api::skill_diagnostics::StorageView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<crate::api::skill_diagnostics::HistoryDiagnostic>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckpointPage {
    pub items: Vec<Checkpoint>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PendingFinalization {
    pub id: String,
    pub snapshot_id: String,
    pub session_reference_id: String,
    pub node_id: String,
    pub incoming_digest: String,
    pub status: String,
    pub storage_location: String,
    pub exportable_from_server: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PendingPage {
    pub items: Vec<PendingFinalization>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckpointMember {
    pub entry_name: String,
    pub state_id: String,
    pub checkpoint_id: String,
    pub skill_id: String,
    pub origin: StateOrigin,
    pub revision_id: String,
    pub installation_epoch: i64,
    pub state_epoch: Option<i64>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct MemberPage {
    pub checkpoint_id: String,
    pub items: Vec<CheckpointMember>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct CheckpointTree {
    pub checkpoint_id: String,
    pub source_tree_digest: String,
    pub tree_digest: String,
    pub subtree_prefix: String,
    pub dependency_roots: Vec<String>,
    pub locally_removed: bool,
    pub manifest: Manifest,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StateBaseline {
    PackageRevision,
    LocalInitialRevision,
    DirectoryCheckpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct StatePathDiff {
    pub path: String,
    pub base: Option<Entry>,
    pub current: Option<Entry>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CheckpointDiff {
    pub checkpoint_id: String,
    pub base_kind: StateBaseline,
    pub base_reference_id: String,
    pub base_tree_digest: String,
    pub current_tree_digest: String,
    pub items: Vec<StatePathDiff>,
    pub next_cursor: Option<String>,
}
