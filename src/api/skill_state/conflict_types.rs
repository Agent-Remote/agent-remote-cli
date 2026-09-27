//! Separate publication and migration identities with explicit saved input provenance.

use super::{StateScope, StateSelector};
use crate::skills::manifest::Entry;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConflictPage<T> {
    pub items: Vec<T>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConflictHistory {
    pub selector: StateSelector,
    pub publications: ConflictPage<PublicationConflictSummary>,
    pub migrations: ConflictPage<MigrationConflictSummary>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationConflictSummary {
    pub id: String,
    pub account_id: String,
    pub finalization_id: String,
    pub attempt: i64,
    pub scope: StateScope,
    pub status: String,
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationInput {
    pub source: String,
    pub reference_id: String,
    pub tree_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConflictBranch {
    pub state_id: String,
    pub entry_name: String,
    pub state_epoch: i64,
    pub checkpoint_id: Option<String>,
    pub revision_id: String,
    pub changed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct MergeConflict {
    pub path: String,
    pub reason: String,
    pub unit: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolutionChoice {
    pub path: Option<String>,
    pub unit: Vec<String>,
    pub r#use: Option<String>,
    pub file_tree_digest: Option<String>,
    pub directory_tree_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationConflict {
    #[serde(flatten)]
    pub summary: PublicationConflictSummary,
    pub session_reference_id: String,
    pub replacement_id: Option<String>,
    pub base: PublicationInput,
    pub current: PublicationInput,
    pub incoming: PublicationInput,
    pub branches: Vec<ConflictBranch>,
    pub conflicts: Vec<MergeConflict>,
    pub plan_revision: i64,
    pub choices: Vec<ResolutionChoice>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationConflictSummary {
    pub id: String,
    pub account_id: String,
    pub skill_id: String,
    pub installation_epoch: i64,
    pub name: String,
    pub mode: String,
    pub status: String,
    pub source_state_id: Option<String>,
    pub source_epoch: Option<i64>,
    pub target_state_id: String,
    pub target_epoch: i64,
    pub directory_epoch: i64,
    pub created_at: String,
    pub recomputed_from_id: Option<String>,
    pub replacement_id: Option<String>,
    pub superseded_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationInput {
    pub source: String,
    pub revision_id: Option<String>,
    pub checkpoint_id: Option<String>,
    pub tree_digest: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationLiveBranch {
    pub state_id: String,
    pub revision_id: String,
    pub epoch: i64,
    pub checkpoint_id: Option<String>,
    pub expired: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationDrift {
    pub source: Option<MigrationLiveBranch>,
    pub target: MigrationLiveBranch,
    pub directory_mode: Option<super::DirectoryMode>,
    pub directory_epoch: Option<i64>,
    pub directory_checkpoint_id: Option<String>,
    pub library_generation: i64,
    pub installation_epoch: i64,
    pub installation_removed: bool,
    pub last_migration_id: Option<String>,
    pub source_head_advanced: bool,
    pub recomputation_reasons: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationConflict {
    #[serde(flatten)]
    pub summary: MigrationConflictSummary,
    pub original: super::migration_types::MigrationOriginal,
    pub base: MigrationInput,
    pub current: MigrationInput,
    pub incoming: MigrationInput,
    pub directory: MigrationInput,
    pub live: MigrationDrift,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ConflictPathDiff {
    pub path: String,
    pub base: Option<Entry>,
    pub current: Option<Entry>,
    pub incoming: Option<Entry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PublicationConflictDiff {
    pub publication_id: String,
    pub items: Vec<ConflictPathDiff>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MigrationConflictDiff {
    pub migration_id: String,
    pub comparison: String,
    pub items: Vec<ConflictPathDiff>,
    pub next_cursor: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ConflictComparison {
    Publication {
        conflict: Box<PublicationConflict>,
        diff: PublicationConflictDiff,
    },
    Migration {
        conflict: Box<MigrationConflict>,
        diff: MigrationConflictDiff,
    },
}
