//! Validate state identities and page boundaries before command code consumes them.

use std::collections::BTreeSet;

use super::*;
use crate::api::skills::invalid_skill_response;
use crate::api::ApiError;
use crate::skills::manifest::validate_path;

pub(super) fn require(condition: bool) -> Result<(), ApiError> {
    if condition {
        Ok(())
    } else {
        Err(invalid_skill_response())
    }
}

pub(super) fn id(value: &str) -> Result<(), ApiError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| invalid_skill_response())?;
    require(parsed.to_string() == value)
}

pub(super) fn digest(value: &str) -> Result<(), ApiError> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}

pub(super) fn path(value: &str) -> Result<(), ApiError> {
    validate_path(value).map_err(|_| invalid_skill_response())
}

pub(super) fn prefix(value: &str) -> Result<(), ApiError> {
    if !value.is_empty() {
        path(value)?;
        require(!value.contains('/'))?;
    }
    Ok(())
}

pub(super) fn query<T>(result: &SkillResult<T>, statuses: &[&str]) -> Result<(), ApiError> {
    if result.data.is_some() {
        require(
            statuses.contains(&result.status.as_str())
                && !result.committed
                && !result.retryable
                && result.operation_id.is_none()
                && result.errors.is_empty(),
        )?;
    }
    Ok(())
}

pub(super) fn selector(value: &StateSelector) -> Result<Vec<(&'static str, String)>, ApiError> {
    id(&value.account_id)?;
    require((value.scope == StateScope::Item) == value.skill.is_some())?;
    let mut query = vec![
        ("account_id", value.account_id.clone()),
        ("scope", value.scope.wire().to_owned()),
    ];
    if let Some(skill) = &value.skill {
        require(!skill.is_empty() && skill.len() <= 64)?;
        query.push(("skill", skill.clone()));
    }
    Ok(query)
}

pub(super) fn checkpoint(value: &Checkpoint) -> Result<(), ApiError> {
    id(&value.id)?;
    id(&value.account_id)?;
    if let Some(storage) = &value.storage {
        storage.validate()?;
    }
    if let Some(retention) = &value.retention {
        retention.validate(
            "checkpoint",
            &value.id,
            value.retained,
            value.storage.as_ref(),
        )?;
    }
    digest(&value.content_digest)?;
    prefix(&value.subtree_prefix)?;
    for value in [
        &value.state_id,
        &value.skill_id,
        &value.revision_id,
        &value.backing_directory_id,
        &value.parent_id,
        &value.source_session_reference_id,
        &value.finalization_id,
    ]
    .into_iter()
    .flatten()
    {
        id(value)?;
    }
    for epoch in [
        value.installation_epoch,
        value.state_epoch,
        value.directory_epoch,
        value.current_state_epoch,
        value.current_directory_epoch,
    ]
    .into_iter()
    .flatten()
    {
        require(epoch >= 1)?;
    }
    let item = value.scope == StateScope::Item;
    require(
        value.state_id.is_some() == item
            && value.skill_id.is_some() == item
            && value.origin.is_some() == item
            && value.revision_id.is_some() == item
            && value.installation_epoch.is_some() == item
            && (item
                || (value.subtree_prefix.is_empty()
                    && value.state_epoch.is_none()
                    && value.current_state_epoch.is_none()
                    && value.backing_directory_id.is_none()))
            && value.retained == (value.storage_location == CheckpointStorage::Server),
    )
}

pub(super) fn page<'a>(
    items: impl Iterator<Item = &'a str>,
    next: Option<&str>,
    cursor: Option<&str>,
    limit: u16,
) -> Result<(), ApiError> {
    let mut seen = BTreeSet::new();
    let mut last = None;
    for value in items {
        id(value)?;
        require(Some(value) != cursor && seen.insert(value))?;
        last = Some(value);
    }
    require(seen.len() <= usize::from(limit))?;
    if let Some(next) = next {
        id(next)?;
        require(Some(next) == last && Some(next) != cursor && seen.len() == usize::from(limit))?;
    }
    Ok(())
}

pub(super) fn diff(
    value: &CheckpointDiff,
    limit: u16,
    cursor: Option<&str>,
) -> Result<(), ApiError> {
    id(&value.checkpoint_id)?;
    id(&value.base_reference_id)?;
    digest(&value.base_tree_digest)?;
    digest(&value.current_tree_digest)?;
    require(value.items.len() <= usize::from(limit))?;
    let mut previous = cursor.unwrap_or("");
    for item in &value.items {
        path(&item.path)?;
        require(item.path.as_str() > previous && item.base != item.current)?;
        for entry in [&item.base, &item.current].into_iter().flatten() {
            entry.validate().map_err(|_| invalid_skill_response())?;
            require(entry.path == item.path)?;
        }
        previous = &item.path;
    }
    if let Some(next) = &value.next_cursor {
        require(
            !value.items.is_empty() && next == previous && value.items.len() == usize::from(limit),
        )?;
    }
    Ok(())
}
