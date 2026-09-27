//! Validate read-only conflict provenance and independent metadata page boundaries.

use super::{check, *};
use crate::api::{skills::invalid_skill_response, ApiError};
use std::collections::BTreeSet;

pub(super) fn publication_summary(value: &PublicationConflictSummary) -> Result<(), ApiError> {
    for id in [&value.id, &value.account_id, &value.finalization_id] {
        check::id(id)?;
    }
    check::require(
        value.attempt >= 1
            && value.scope == StateScope::AccountDirectory
            && ["conflicted", "superseded", "published", "detached"]
                .contains(&value.status.as_str()),
    )
}

pub(super) fn publication(value: &PublicationConflict) -> Result<(), ApiError> {
    publication_summary(&value.summary)?;
    check::id(&value.session_reference_id)?;
    optional_id(&value.replacement_id)?;
    for (side, source) in [
        (&value.base, "session_snapshot"),
        (&value.current, "publication_comparison"),
        (&value.incoming, "finalization"),
    ] {
        check::require(side.source == source)?;
        check::id(&side.reference_id)?;
        optional_digest(&side.tree_digest)?;
    }
    check::require(
        value.current.reference_id == value.summary.id
            && value.incoming.reference_id == value.summary.finalization_id
            && value.plan_revision >= 0,
    )?;
    let mut previous = "";
    let mut branches = BTreeSet::new();
    for branch in &value.branches {
        check::prefix(&branch.entry_name)?;
        check::id(&branch.state_id)?;
        check::id(&branch.revision_id)?;
        optional_id(&branch.checkpoint_id)?;
        check::require(
            branch.entry_name.as_str() > previous
                && branch.state_epoch >= 1
                && branches.insert(&branch.state_id),
        )?;
        previous = &branch.entry_name;
    }
    conflicts(&value.conflicts)?;
    for choice in &value.choices {
        resolution_choice(choice)?;
    }
    Ok(())
}

pub(super) fn resolution_choice(choice: &ResolutionChoice) -> Result<(), ApiError> {
    unit(&choice.unit)?;
    if let Some(path) = &choice.path {
        check::path(path)?;
    }
    optional_digest(&choice.file_tree_digest)?;
    optional_digest(&choice.directory_tree_digest)?;
    check::require(
        [
            choice.r#use.is_some(),
            choice.file_tree_digest.is_some(),
            choice.directory_tree_digest.is_some(),
        ]
        .into_iter()
        .filter(|v| *v)
        .count()
            == 1
            && choice
                .r#use
                .as_deref()
                .is_none_or(|v| ["current", "incoming"].contains(&v))
            && (choice.path.is_none()
                || (choice.unit.is_empty() && choice.directory_tree_digest.is_none()))
            && (choice.file_tree_digest.is_none() || choice.path.is_some()),
    )?;
    Ok(())
}

pub(super) fn migration_summary(value: &MigrationConflictSummary) -> Result<(), ApiError> {
    for id in [
        &value.id,
        &value.account_id,
        &value.skill_id,
        &value.target_state_id,
    ] {
        check::id(id)?;
    }
    for id in [
        &value.source_state_id,
        &value.recomputed_from_id,
        &value.replacement_id,
    ] {
        optional_id(id)?;
    }
    check::prefix(&value.name)?;
    check::require(
        !value.name.is_empty()
            && value.installation_epoch >= 1
            && value.target_epoch >= 1
            && value.directory_epoch >= 1
            && value.source_epoch.is_none_or(|v| v >= 1)
            && value.source_state_id.is_some() == value.source_epoch.is_some()
            && ["initial", "forward", "older", "resume", "incremental"]
                .contains(&value.mode.as_str())
            && ["conflicted", "superseded", "ready"].contains(&value.status.as_str()),
    )
}

pub(super) fn conflicts(values: &[MergeConflict]) -> Result<(), ApiError> {
    for value in values {
        if value.path != "." {
            check::path(&value.path)?;
        }
        unit(&value.unit)?;
        check::require(
            [
                "changed_both",
                "opaque_divergence",
                "invalid_tree",
                "source_conflict",
            ]
            .contains(&value.reason.as_str()),
        )?;
    }
    Ok(())
}

pub(super) fn unit(values: &[String]) -> Result<(), ApiError> {
    let mut previous = "";
    for value in values {
        if value != "." {
            check::prefix(value)?;
        }
        check::require(value.as_str() > previous)?;
        previous = value;
    }
    Ok(())
}

pub(super) fn optional_id(value: &Option<String>) -> Result<(), ApiError> {
    if let Some(value) = value {
        check::id(value)?;
    }
    Ok(())
}
pub(super) fn optional_digest(value: &Option<String>) -> Result<(), ApiError> {
    if let Some(value) = value {
        check::digest(value)?;
    }
    Ok(())
}

pub(super) fn paths(
    items: &[ConflictPathDiff],
    limit: u16,
    after: Option<&str>,
    next: Option<&str>,
) -> Result<(), ApiError> {
    check::require(items.len() <= usize::from(limit))?;
    let mut previous = after.unwrap_or("");
    for item in items {
        check::path(&item.path)?;
        check::require(
            item.path.as_str() > previous
                && !(item.base == item.current && item.base == item.incoming),
        )?;
        for entry in [&item.base, &item.current, &item.incoming]
            .into_iter()
            .flatten()
        {
            entry.validate().map_err(|_| invalid_skill_response())?;
            check::require(entry.path == item.path)?;
        }
        previous = &item.path;
    }
    if let Some(next) = next {
        check::require(!items.is_empty() && next == previous && items.len() == usize::from(limit))?;
    }
    Ok(())
}
