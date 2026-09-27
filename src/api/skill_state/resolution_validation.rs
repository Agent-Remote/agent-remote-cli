//! Validate native resolution status and full migration branch/diff identities before acceptance.

use super::{check, command_validation::changes, conflict_validation as common, *};
use crate::api::{skills::SkillResult, ApiError};

pub(super) fn outcome(
    result: &SkillResult<ResolutionOutcome>,
    target: Option<&ResolutionTarget>,
    request: Option<&ResolutionRequest>,
) -> Result<(), ApiError> {
    let Some(view) = &result.data else {
        return Ok(());
    };
    view.target().path()?;
    let preview = view.status() == "preview";
    let published = view.status() == "published";
    check::require(
        ["preview", "pending", "published", "superseded"].contains(&view.status())
            && result.status == view.status()
            && result.committed != preview
            && !result.retryable
            && result.errors.is_empty()
            && &result.operation_id == view.operation_id()
            && view.operation_id().is_some() != preview
            && view.revision() >= 0
            && (preview || (view.status() == "superseded") == view.stale())
            && target.is_none_or(|t| *t == view.target()),
    )?;
    common::optional_id(view.operation_id())?;
    common::optional_digest(view.digest())?;
    for choice in view.choices() {
        common::resolution_choice(choice)?;
    }
    if let Some(request) = request {
        let revision = request.expected_revision + i64::from(!preview && !view.stale());
        check::require(
            preview == request.dry_run
                && view.revision() == revision
                && (view.stale() || view.choices().last() == Some(&request.choice)),
        )?;
    } else {
        check::require(!preview)?;
    }
    match view {
        ResolutionOutcome::Publication { result: value } => {
            common::optional_id(&value.result_checkpoint_id)?;
            common::optional_id(&value.replacement_id)?;
            common::conflicts(&value.remaining)?;
            check::require(
                value.result_checkpoint_id.is_some() == published
                    && value.ready == value.result_tree_digest.is_some()
                    && (!published || (value.ready && value.remaining.is_empty()))
                    && (!value.ready || value.remaining.is_empty())
                    && (preview || value.ready == published)
                    && (!view.stale() || (!value.ready && !published)),
            )?;
        }
        ResolutionOutcome::Migration {
            result: value,
            current,
        } => {
            check::id(&value.target_revision_id)?;
            common::unit(&value.unit)?;
            common::unit(&value.other_changed_roots)?;
            common::conflicts(&value.remaining)?;
            for id in [
                &value.result_checkpoint_id,
                &value.result_directory_id,
                &value.replacement_id,
            ] {
                common::optional_id(id)?;
            }
            check::require(
                value.operation_kind == "migration_resolution"
                    && value.candidate_complete == value.result_tree_digest.is_some()
                    && value.candidate_complete == value.target_modified.is_some()
                    && value.candidate_complete == value.target_changes.is_some()
                    && value.candidate_complete == value.original_changes.is_some()
                    && value.candidate_complete == value.directory_changes.is_some()
                    && value.candidate_complete != value.affected.is_empty()
                    && value.result_checkpoint_id.is_some() == published
                    && value.result_directory_id.is_some() == published
                    && value.migration_sequence.is_none_or(|v| published && v >= 1)
                    && (!published || value.candidate_complete)
                    && (preview || value.candidate_complete == published)
                    && (!view.stale() || (!value.candidate_complete && value.affected.is_empty()))
                    && (!value.candidate_complete || value.remaining.is_empty()),
            )?;
            for diff in [
                &value.target_changes,
                &value.original_changes,
                &value.directory_changes,
            ]
            .into_iter()
            .flatten()
            {
                changes(diff)?;
            }
            if let (Some(modified), Some(diff)) = (value.target_modified, &value.original_changes) {
                check::require(modified != diff.is_empty())?;
            }
            if let Some(target) = value.affected.first() {
                check::require(
                    target.revision_id == value.target_revision_id
                        && Some(&target.changes) == value.target_changes.as_ref()
                        && Some(&target.original_changes) == value.original_changes.as_ref()
                        && Some(target.modified) == value.target_modified
                        && target.result_checkpoint_id == value.result_checkpoint_id,
                )?;
            }
            let mut names = std::collections::BTreeSet::new();
            let mut states = std::collections::BTreeSet::new();
            for branch in &value.affected {
                check::prefix(&branch.name)?;
                for id in [&branch.state_id, &branch.skill_id, &branch.revision_id] {
                    check::id(id)?;
                }
                common::optional_id(&branch.checkpoint_id)?;
                common::optional_id(&branch.result_checkpoint_id)?;
                changes(&branch.changes)?;
                changes(&branch.original_changes)?;
                check::require(
                    !branch.name.is_empty()
                        && names.insert(&branch.name)
                        && states.insert(&branch.state_id)
                        && ["user_library", "account_local"].contains(&branch.origin.as_str())
                        && branch.installation_epoch >= 1
                        && branch.state_epoch >= 1
                        && branch.result_checkpoint_id.is_some() == published
                        && branch.modified != branch.original_changes.is_empty(),
                )?;
            }
            if let Some(current) = current {
                common::optional_id(&current.replacement_id)?;
                check::require(
                    ["ready", "conflicted", "superseded"].contains(&current.status.as_str()),
                )?;
            }
        }
    }
    Ok(())
}
