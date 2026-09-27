//! Saved migration inputs remain tied to the original attempt even when live heads advance.

use super::{check, conflict_validation as common, migration_types::*, *};
use crate::api::{skills::invalid_skill_response, ApiError};
use base64::{engine::general_purpose::URL_SAFE, Engine};

pub(super) fn conflict(value: &MigrationConflict) -> Result<(), ApiError> {
    let summary = &value.summary;
    let original = &value.original;
    common::migration_summary(summary)?;
    check::require(
        original.operation_id.as_ref() == Some(&summary.id)
            && original.kind.mode() == summary.mode
            && ["ready", "conflicted"].contains(&original.status.as_str()),
    )?;
    for (side, label, digest) in [
        (&value.base, &original.base_source, &original.base_digest),
        (
            &value.current,
            &original.current_source,
            &original.current_digest,
        ),
        (
            &value.incoming,
            &original.incoming_source,
            &original.incoming_digest,
        ),
    ] {
        input(side)?;
        check::require(&side.source == label && side.tree_digest.as_ref() == Some(digest))?;
    }
    input(&value.directory)?;
    check::require(
        value.directory.source == "account_directory"
            && value.directory.revision_id.is_none()
            && value.directory.checkpoint_id.is_some(),
    )?;
    common::optional_digest(&original.result_tree_digest)?;
    for id in [
        &original.result_checkpoint_id,
        &original.result_directory_id,
    ] {
        common::optional_id(id)?;
    }
    common::conflicts(&original.conflicts)?;
    check::require(original.migration_sequence.is_none_or(|v| v >= 1))?;
    if original.status == "conflicted" {
        check::require(
            original.result_tree_digest.is_none()
                && original.result_checkpoint_id.is_none()
                && original.result_directory_id.is_none()
                && original.migration_sequence.is_none()
                && !original.conflicts.is_empty(),
        )?;
    }
    match &original.kind {
        MigrationOriginalKind::Incremental(saved) => {
            let before = &saved.before;
            check::require(
                before.account_id == summary.account_id
                    && before.skill_id == summary.skill_id
                    && before.name == summary.name
                    && before.installation_epoch == summary.installation_epoch
                    && before.directory_epoch == summary.directory_epoch
                    && before.source.state_id == summary.source_state_id
                    && before.source.state_epoch == summary.source_epoch
                    && before
                        .target
                        .state_id
                        .as_ref()
                        .is_none_or(|id| id == &summary.target_state_id)
                    && before
                        .target
                        .state_epoch
                        .is_none_or(|n| n == summary.target_epoch)
                    && before.library_generation >= 0
                    && before.last_sequence >= 0
                    && value.directory.checkpoint_id.as_ref()
                        == Some(&before.directory_checkpoint_id),
            )?;
            check::id(&before.directory_checkpoint_id)?;
            for side in [&before.source, &before.target] {
                branch(side)?;
            }
            for id in [
                &before.last_migration_id,
                &before.last_migrated_checkpoint_id,
            ] {
                common::optional_id(id)?;
            }
            check::require(
                ["old_original", "last_migrated"].contains(&original.base_source.as_str())
                    && ["target_original", "target_published"]
                        .contains(&original.current_source.as_str())
                    && original.incoming_source == "source_published",
            )?;
            for changes in [&saved.changes, &saved.directory_changes]
                .into_iter()
                .flatten()
            {
                super::command_validation::changes(changes)?;
            }
            saved_sides(
                value,
                Some(&before.source.revision_id),
                &before.target.revision_id,
                before.source.checkpoint_id.as_deref(),
                before.target.checkpoint_id.as_deref(),
                before.last_migrated_checkpoint_id.as_deref(),
            )?;
        }
        MigrationOriginalKind::Initial(saved)
        | MigrationOriginalKind::Forward(saved)
        | MigrationOriginalKind::Older(saved)
        | MigrationOriginalKind::Resume(saved) => {
            super::command_validation::current(&CurrentState {
                selector: StateSelector {
                    account_id: summary.account_id.clone(),
                    scope: StateScope::Item,
                    skill: Some(summary.skill_id.clone()),
                },
                precondition: saved.before.clone(),
            })?;
            let target = &saved.before.targets[0];
            check::require(
                target.name == summary.name
                    && target.installation_epoch == summary.installation_epoch
                    && saved.before.directory_epoch == Some(summary.directory_epoch)
                    && saved.before.directory_head_id == value.directory.checkpoint_id
                    && saved.target_state_id.as_ref() == Some(&summary.target_state_id)
                    && saved.source_epoch == summary.source_epoch,
            )?;
            for id in [
                &saved.source_revision_id,
                &saved.source_checkpoint_id,
                &saved.target_state_id,
            ] {
                common::optional_id(id)?;
            }
            check::require(
                ["old_original", "target_original", "existing_target"]
                    .contains(&original.base_source.as_str())
                    && [
                        "new_original",
                        "target_original",
                        "existing_target",
                        "target_published",
                    ]
                    .contains(&original.current_source.as_str())
                    && ["old_published", "target_original", "existing_target"]
                        .contains(&original.incoming_source.as_str()),
            )?;
            saved_sides(
                value,
                saved.source_revision_id.as_deref(),
                &target.revision_id,
                saved.source_checkpoint_id.as_deref(),
                target.head_checkpoint_id.as_deref(),
                None,
            )?;
        }
    }
    let live = &value.live;
    live_branch(&live.target)?;
    check::require(
        live.target.state_id == summary.target_state_id
            && live.source.as_ref().map(|b| &b.state_id) == summary.source_state_id.as_ref()
            && live.library_generation >= 0
            && live.installation_epoch >= 1
            && live.directory_epoch.is_none_or(|v| v >= 1),
    )?;
    if let Some(source) = &live.source {
        live_branch(source)?;
    }
    for id in [&live.directory_checkpoint_id, &live.last_migration_id] {
        common::optional_id(id)?;
    }
    Ok(())
}

fn saved_sides(
    value: &MigrationConflict,
    source_revision: Option<&str>,
    target_revision: &str,
    source_checkpoint: Option<&str>,
    target_checkpoint: Option<&str>,
    last_checkpoint: Option<&str>,
) -> Result<(), ApiError> {
    check::require(
        value.live.target.revision_id == target_revision
            && value.live.source.as_ref().map(|v| v.revision_id.as_str()) == source_revision,
    )?;
    for side in [&value.base, &value.current, &value.incoming] {
        let (revision, checkpoint) = match side.source.as_str() {
            "old_original" => (source_revision, None),
            "last_migrated" => (source_revision, last_checkpoint),
            "old_published" | "source_published" => (source_revision, source_checkpoint),
            "target_published" => (Some(target_revision), target_checkpoint),
            "existing_target" => (
                Some(target_revision),
                value.original.result_checkpoint_id.as_deref(),
            ),
            "new_original" | "target_original" => (Some(target_revision), None),
            _ => return Err(invalid_skill_response()),
        };
        check::require(
            side.revision_id.as_deref() == revision && side.checkpoint_id.as_deref() == checkpoint,
        )?;
    }
    Ok(())
}

fn input(value: &MigrationInput) -> Result<(), ApiError> {
    check::require(
        [
            "old_original",
            "new_original",
            "target_original",
            "last_migrated",
            "old_published",
            "source_published",
            "target_published",
            "existing_target",
            "account_directory",
        ]
        .contains(&value.source.as_str()),
    )?;
    common::optional_id(&value.revision_id)?;
    common::optional_id(&value.checkpoint_id)?;
    common::optional_digest(&value.tree_digest)
}
pub(super) fn branch(value: &MigrationBranch) -> Result<(), ApiError> {
    check::id(&value.revision_id)?;
    common::optional_id(&value.state_id)?;
    common::optional_id(&value.checkpoint_id)?;
    check::require(
        value.state_id.is_some() == value.state_epoch.is_some()
            && value.state_epoch.is_none_or(|v| v >= 1)
            && (value.state_id.is_some() || (value.checkpoint_id.is_none() && !value.expired)),
    )
}
fn live_branch(value: &MigrationLiveBranch) -> Result<(), ApiError> {
    check::id(&value.state_id)?;
    check::id(&value.revision_id)?;
    common::optional_id(&value.checkpoint_id)?;
    check::require(value.epoch >= 1)
}

pub(super) fn cursor(value: &str, conflict: &MigrationConflict) -> Result<String, ApiError> {
    check::require(!value.is_empty() && value.len() <= 16384)?;
    let bytes = URL_SAFE
        .decode(value)
        .map_err(|_| invalid_skill_response())?;
    let parts: [String; 5] =
        serde_json::from_slice(&bytes).map_err(|_| invalid_skill_response())?;
    check::require(
        parts[0] == conflict.summary.id
            && Some(&parts[1]) == conflict.base.tree_digest.as_ref()
            && Some(&parts[2]) == conflict.current.tree_digest.as_ref()
            && Some(&parts[3]) == conflict.incoming.tree_digest.as_ref(),
    )?;
    check::path(&parts[4])?;
    Ok(parts[4].clone())
}
