//! Validate each bounded prune page and bind acceptance to its exact original command.

use super::{prune_types::*, validation as check, StateScope};
use crate::api::{skills::SkillResult, ApiError};
use sha2::{Digest, Sha256};

pub(super) const MAX_ROWS: u64 = 10_000_000;

pub(super) fn text(value: &str, max: usize) -> Result<(), ApiError> {
    check::require(!value.is_empty() && value.len() <= max && !value.chars().any(char::is_control))
}

pub(super) fn credential(value: &str) -> Result<(), ApiError> {
    text(value, 4096)?;
    check::require(value.is_ascii())
}

pub(super) fn key(value: &str) -> Result<(), ApiError> {
    check::require(
        !value.is_empty() && value.len() <= 128 && value.bytes().all(|b| b.is_ascii_graphic()),
    )
}

pub(super) fn summary(value: &PruneSummary) -> Result<(), ApiError> {
    check::selector(&value.binding.selector)?;
    if let Some(skill) = &value.binding.selector.skill {
        check::id(skill)?;
    }
    text(&value.binding.cutoff, 64)?;
    check::digest(&value.binding.plan_digest)?;
    check::require(
        value.groups <= value.history_losses && (value.groups == 0) == (value.history_losses == 0),
    )?;
    for count in [
        value.groups,
        value.history_losses,
        value.blocked_histories,
        value.compacted_directories,
        value.compacted_items,
        value.trees,
    ] {
        check::require(count <= MAX_ROWS)?;
    }
    Ok(())
}

fn identity(value: &PruneIdentity) -> Result<(), ApiError> {
    check::id(&value.id)?;
    check::require(matches!(
        value.kind.as_str(),
        "revision"
            | "local_revision"
            | "checkpoint"
            | "snapshot"
            | "finalization"
            | "publication"
            | "migration"
    ))
}

pub(super) fn row(value: &PruneDisclosure, accepted: bool) -> Result<(), ApiError> {
    match value {
        PruneDisclosure::History {
            history,
            retained,
            selected,
            group,
            blockers,
            dependency_blocked,
            protected_by,
            released_at,
            expires_at,
            content_digests,
            ..
        } => {
            identity(history)?;
            check::require(
                *selected == group.is_some() && group.is_none_or(|v| v > 0 && v <= MAX_ROWS),
            )?;
            check::require(
                !selected
                    || (*retained
                        && !dependency_blocked
                        && blockers.is_empty()
                        && protected_by.is_empty()),
            )?;
            check::require(
                blockers.len() <= 16 && protected_by.len() <= 16 && content_digests.len() <= 3,
            )?;
            for reason in blockers.iter().chain(protected_by) {
                text(reason, 128)?;
            }
            for date in [released_at, expires_at].into_iter().flatten() {
                text(date, 64)?;
            }
            for digest in content_digests {
                check::digest(digest)?;
            }
        }
        PruneDisclosure::Dependency {
            consumer,
            dependency,
            relation,
        } => {
            identity(consumer)?;
            identity(dependency)?;
            text(relation, 128)?;
        }
        PruneDisclosure::Compaction {
            scope,
            checkpoint_id,
            state_id,
            epoch,
            original_digest,
            result_digest,
            replacement_id,
        } => {
            check::id(checkpoint_id)?;
            check::require(
                matches!(scope.as_str(), "item" | "directory")
                    && (scope == "item") == state_id.is_some()
                    && epoch.is_none_or(|v| v > 0)
                    && replacement_id.is_some() == accepted,
            )?;
            for id in [state_id, replacement_id].into_iter().flatten() {
                check::id(id)?;
            }
            check::digest(original_digest)?;
            check::digest(result_digest)?;
        }
        PruneDisclosure::Member {
            directory_id,
            checkpoint_id,
            state_id,
            name,
            action,
        } => {
            for id in [directory_id, checkpoint_id, state_id] {
                check::id(id)?;
            }
            check::prefix(name)?;
            text(name, 64)?;
            check::require(matches!(action.as_str(), "removed" | "blocked"))?;
        }
    }
    Ok(())
}

pub(super) fn preview(
    value: &PrunePreviewPage,
    request: &PrunePreviewRequest,
) -> Result<(), ApiError> {
    summary(&value.summary)?;
    let binding = &value.summary.binding;
    check::require(
        binding.selector.account_id == request.selector.account_id
            && binding.selector.scope == request.selector.scope
            && binding.all_unreferenced == request.all_unreferenced,
    )?;
    if request.cursor.is_some()
        || request
            .selector
            .skill
            .as_ref()
            .is_some_and(|s| uuid::Uuid::parse_str(s).is_ok())
    {
        check::require(binding.selector == request.selector)?;
    }
    if request.selector.scope == StateScope::AccountDirectory {
        check::require(binding.selector.skill.is_none())?;
    }
    let end = page(value.offset, value.total, &value.rows, request.limit, false)?;
    check::require(request.cursor.is_some() == (value.offset > 0))?;
    if end < value.total {
        credential(
            value
                .next_cursor
                .as_deref()
                .ok_or_else(crate::api::skills::invalid_skill_response)?,
        )?;
        check::require(value.confirmation.is_none() && value.next_cursor != request.cursor)?;
    } else {
        check::require(
            value.next_cursor.is_none() && value.confirmation.is_some() == value.summary.ready,
        )?;
        if let Some(token) = &value.confirmation {
            credential(token)?;
        }
    }
    Ok(())
}

pub(super) fn page(
    offset: u64,
    total: u64,
    rows: &[PruneDisclosure],
    limit: u16,
    accepted: bool,
) -> Result<u64, ApiError> {
    check::require(total <= MAX_ROWS && offset <= total && (1..=100).contains(&limit))?;
    check::require(rows.len() == (total - offset).min(u64::from(limit)) as usize)?;
    for value in rows {
        row(value, accepted)?;
    }
    Ok(offset + rows.len() as u64)
}

pub(super) fn accepted<T>(value: &SkillResult<T>, operation: &str) -> Result<(), ApiError> {
    check::id(operation)?;
    check::require(
        value.committed
            && value.status == "accepted"
            && !value.retryable
            && value.errors.is_empty()
            && value.operation_id.as_deref() == Some(operation),
    )
}

pub(super) fn receipt(value: &SkillResult<PruneReceipt>) -> Result<(), ApiError> {
    if let Some(receipt) = &value.data {
        accepted(value, &receipt.operation_id)?;
        summary(&receipt.summary)?;
        key(&receipt.idempotency_key)?;
        check::digest(&receipt.confirmation_fingerprint)?;
        check::require(
            receipt.status == "accepted"
                && receipt.summary.ready
                && receipt.disclosure_rows <= MAX_ROWS,
        )?;
    }
    Ok(())
}

impl PruneSummary {
    pub fn validate(&self) -> Result<(), ApiError> {
        summary(self)
    }
}

impl PruneRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        key(&self.idempotency_key)?;
        credential(&self.confirmation)
    }

    pub fn validate_receipt(&self, value: &SkillResult<PruneReceipt>) -> Result<(), ApiError> {
        receipt(value)?;
        if let Some(receipt) = &value.data {
            check::require(
                receipt.idempotency_key == self.idempotency_key
                    && receipt.confirmation_fingerprint
                        == format!("{:x}", Sha256::digest(self.confirmation.as_bytes())),
            )?;
        }
        Ok(())
    }
}
