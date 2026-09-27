//! State receipts must describe the original exact plan, never a new current head.

use super::{check, *};
use crate::api::{skills::invalid_skill_response, ApiError};
use std::collections::BTreeSet;

pub(super) fn current(value: &CurrentState) -> Result<(), ApiError> {
    check::selector(&value.selector)?;
    let expected = &value.precondition;
    check::require(
        expected.library_generation >= 0
            && expected.targets.len() <= 100_000
            && expected.directory_epoch.is_none_or(|n| n >= 1),
    )?;
    if let Some(id) = &expected.directory_head_id {
        check::id(id)?;
    }
    if value.selector.scope == StateScope::Item {
        check::require(expected.targets.len() == 1)?;
    }
    let mut previous = "";
    let mut sources = BTreeSet::new();
    let mut branches = BTreeSet::new();
    for target in &expected.targets {
        check::prefix(&target.name)?;
        check::require(
            target.name.as_str() > previous
                && target.name.len() <= 64
                && target.installation_epoch >= 1
                && target.state_epoch.is_none_or(|n| n >= 1)
                && target.state_id.is_some() == target.state_epoch.is_some()
                && (target.state_id.is_some()
                    || (!target.expired && target.head_checkpoint_id.is_none()))
                && target.rule.revision_id == target.revision_id
                && sources.insert(&target.skill_id),
        )?;
        for id in [&target.skill_id, &target.revision_id] {
            check::id(id)?;
        }
        if let Some(id) = &target.state_id {
            check::id(id)?;
            check::require(branches.insert(id))?;
        }
        if let Some(id) = &target.head_checkpoint_id {
            check::id(id)?;
        }
        previous = &target.name;
    }
    if let Some(skill) = &value.selector.skill {
        let target = &expected.targets[0];
        check::require(skill == &target.skill_id || skill == &target.name)?;
    }
    Ok(())
}

pub(super) fn request(value: &StateCommandRequest) -> Result<(), ApiError> {
    check::require(
        !value.idempotency_key.is_empty()
            && value.idempotency_key.len() <= 128
            && value.idempotency_key.bytes().all(|b| b.is_ascii_graphic())
            && (value.action == StateAction::Restore) == value.checkpoint_id.is_some(),
    )?;
    if let Some(id) = &value.checkpoint_id {
        check::id(id)?;
    }
    current(&CurrentState {
        selector: value.selector.clone(),
        precondition: value.expected.clone(),
    })
}

pub(super) fn result(
    value: &SkillResult<StateCommandView>,
    request: Option<&StateCommandRequest>,
) -> Result<(), ApiError> {
    let Some(view) = &value.data else {
        return Ok(());
    };
    current(&view.before)?;
    check::digest(&view.result_tree_digest)?;
    let preview = view.status == StateCommandStatus::Preview;
    check::require(
        value.errors.is_empty()
            && !value.retryable
            && value.status == if preview { "preview" } else { "published" }
            && value.committed != preview
            && value.operation_id == view.operation_id
            && view.operation_id.is_some() != preview
            && view.result_checkpoint_id.is_some() != preview
            && view.affected == view.before.precondition.targets
            && view.directory_epoch_advances
                == (view.before.selector.scope == StateScope::AccountDirectory)
            && view.branch_changes.len() == view.affected.len()
            && (!preview || view.superseded_conflicts == 0),
    )?;
    for id in [&view.operation_id, &view.result_checkpoint_id]
        .into_iter()
        .flatten()
    {
        check::id(id)?;
    }
    changes(&view.changes)?;
    for (branch, target) in view.branch_changes.iter().zip(&view.affected) {
        check::require(
            branch.skill_id == target.skill_id
                && branch.state_id == target.state_id
                && branch.checkpoint_id == target.head_checkpoint_id
                && branch.baseline_available == branch.changes.is_some()
                && (branch.baseline_available || branch.checkpoint_id.is_some()),
        )?;
        if let Some(items) = &branch.changes {
            changes(items)?;
            for item in items {
                check::require(
                    item.path == target.name || item.path.starts_with(&format!("{}/", target.name)),
                )?;
            }
        }
    }
    if let Some(request) = request {
        check::require(
            view.action == request.action
                && view.before.selector == request.selector
                && view.before.precondition == request.expected
                && preview == request.dry_run,
        )?;
    }
    Ok(())
}

pub(super) fn changes(items: &[StatePathDiff]) -> Result<(), ApiError> {
    check::require(items.len() <= 200_000)?;
    let mut previous = "";
    for item in items {
        check::path(&item.path)?;
        check::require(item.path.as_str() > previous && item.base != item.current)?;
        for entry in [&item.base, &item.current].into_iter().flatten() {
            entry.validate().map_err(|_| invalid_skill_response())?;
            check::require(entry.path == item.path)?;
        }
        previous = &item.path;
    }
    Ok(())
}
