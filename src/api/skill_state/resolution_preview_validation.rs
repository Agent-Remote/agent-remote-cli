//! Reject false publication authority, changed attempts and incomplete-candidate diff claims.

use super::{check, command_validation, conflict_validation as common, *};
use crate::api::ApiError;

pub(super) fn preview(
    view: &ResolutionContentPreview,
    target: &ResolutionTarget,
    request: &ResolutionPreviewRequest,
) -> Result<(), ApiError> {
    check::id(&view.account_id)?;
    check::digest(&view.current_tree_digest)?;
    check::digest(&view.directory_tree_digest)?;
    common::optional_digest(&view.result_tree_digest)?;
    common::optional_id(&view.target_revision_id)?;
    common::conflicts(&view.remaining)?;
    common::unit(&view.unit)?;
    check::require(
        view.kind == target.kind
            && view.conflict_id == target.conflict_id
            && view.plan_revision == request.expected_revision
            && Some(&view.proposed_tree_digest)
                == request
                    .choice
                    .file_tree_digest
                    .as_ref()
                    .or(request.choice.directory_tree_digest.as_ref())
            && view.metadata_only
            && !view.content_verified
            && !view.ready_to_publish
            && view.pending_checks
                == [
                    "custom_content",
                    "source_authorization",
                    "quota_admission",
                    "head_preconditions",
                ]
            && view.candidate_complete == view.result_tree_digest.is_some()
            && view.candidate_complete == view.changes.is_some()
            && view.candidate_complete == view.remaining.is_empty()
            && view.choices.last() == Some(&request.choice),
    )?;
    let mut choices = std::collections::BTreeSet::new();
    for choice in &view.choices {
        common::resolution_choice(choice)?;
        // Identical choices cannot occur twice; the Server replaces overlapping scopes in memory.
        check::require(choices.insert((
            &choice.path,
            &choice.unit,
            &choice.r#use,
            &choice.file_tree_digest,
            &choice.directory_tree_digest,
        )))?;
    }
    for changes in [&view.changes, &view.target_changes, &view.original_changes]
        .into_iter()
        .flatten()
    {
        command_validation::changes(changes)?;
    }
    match view.kind {
        ResolutionDomain::Publication => check::require(
            view.unit.is_empty()
                && view.target_revision_id.is_none()
                && view.target_modified.is_none()
                && view.target_changes.is_none()
                && view.original_changes.is_none(),
        )?,
        ResolutionDomain::Migration => {
            check::require(
                view.target_revision_id.is_some()
                    && view.candidate_complete == view.target_modified.is_some()
                    && view.candidate_complete == view.target_changes.is_some()
                    && view.candidate_complete == view.original_changes.is_some(),
            )?;
            if let (Some(modified), Some(changes)) = (view.target_modified, &view.original_changes)
            {
                check::require(modified != changes.is_empty())?;
            }
        }
    }
    Ok(())
}
