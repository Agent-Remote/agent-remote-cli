//! Validate original migration identities and complete results independently of live status.

use super::{check, conflict_validation as common, *};
use crate::api::ApiError;

pub(super) fn selector(s: &MigrationSelector) -> Result<(), ApiError> {
    check::id(&s.account_id)?;
    for value in [&s.skill, &s.from_revision, &s.to_revision] {
        check::require(
            !value.is_empty() && value.len() <= 64 && !value.chars().any(char::is_control),
        )?;
    }
    check::require(s.from_revision != s.to_revision)
}

pub(super) fn current(p: &MigrationPrecondition) -> Result<(), ApiError> {
    for id in [&p.account_id, &p.skill_id, &p.directory_checkpoint_id] {
        check::id(id)?;
    }
    check::prefix(&p.name)?;
    for branch in [&p.source, &p.target] {
        super::migration_validation::branch(branch)?;
    }
    common::optional_id(&p.last_migration_id)?;
    common::optional_id(&p.last_migrated_checkpoint_id)?;
    check::require(
        !p.name.is_empty()
            && p.name.len() <= 64
            && p.installation_epoch >= 1
            && p.library_generation >= 0
            && p.directory_epoch >= 1
            && p.source.revision_id != p.target.revision_id
            && p.source.state_id.is_some()
            && p.source.checkpoint_id.is_some()
            && (p.target.state_id.is_none() || p.target.state_id != p.source.state_id)
            && p.last_sequence >= 0
            && p.last_migration_id.is_some() == (p.last_sequence > 0)
            && p.last_migration_id.is_some() == p.last_migrated_checkpoint_id.is_some()
            && p.source_has_unmigrated_checkpoint
                == (p.last_migrated_checkpoint_id != p.source.checkpoint_id),
    )
}

pub(super) fn selection(s: &MigrationSelector, p: &MigrationPrecondition) -> Result<(), ApiError> {
    selector(s)?;
    current(p)?;
    check::require(s.account_id == p.account_id && (s.skill == p.skill_id || s.skill == p.name))?;
    for (selected, resolved) in [
        (&s.from_revision, &p.source.revision_id),
        (&s.to_revision, &p.target.revision_id),
    ] {
        if uuid::Uuid::parse_str(selected).is_ok() {
            check::require(selected == resolved)?;
        }
    }
    Ok(())
}

pub(super) fn request(r: &MigrationRequest) -> Result<(), ApiError> {
    selection(&r.selector, &r.expected)?;
    check::require(
        !r.idempotency_key.is_empty()
            && r.idempotency_key.len() <= 128
            && r.idempotency_key.bytes().all(|b| b.is_ascii_graphic()),
    )
}

pub(super) fn view(v: &MigrationView, committed: bool) -> Result<(), ApiError> {
    current(&v.before)?;
    let p = &v.before;
    check::require(
        v.mode == "incremental"
            && ["ready", "conflicted"].contains(&v.status.as_str())
            && v.operation_id.is_some() == committed
            && !p.source.expired
            && !p.target.expired
            && v.base_source
                == if p.last_migrated_checkpoint_id.is_some() {
                    "last_migrated"
                } else {
                    "old_original"
                }
            && v.current_source
                == if p.target.checkpoint_id.is_some() {
                    "target_published"
                } else {
                    "target_original"
                }
            && v.incoming_source == "source_published",
    )?;
    for id in [
        &v.operation_id,
        &v.result_checkpoint_id,
        &v.result_directory_id,
    ] {
        common::optional_id(id)?;
    }
    for digest in [&v.base_digest, &v.current_digest, &v.incoming_digest] {
        check::digest(digest)?;
    }
    common::optional_digest(&v.result_tree_digest)?;
    common::conflicts(&v.conflicts)?;
    let ready = v.status == "ready";
    check::require(
        v.conflicts.is_empty() == ready
            && v.result_tree_digest.is_some() == ready
            && v.changes.is_some() == ready
            && v.directory_changes.is_some() == ready
            && v.result_checkpoint_id.is_some() == (committed && ready)
            && v.result_directory_id.is_some() == (committed && ready)
            && v.migration_sequence.is_some() == (committed && ready),
    )?;
    if ready && !p.source_has_unmigrated_checkpoint && p.target.checkpoint_id.is_some() {
        check::require(
            v.changes.as_ref().is_some_and(Vec::is_empty)
                && v.directory_changes.as_ref().is_some_and(Vec::is_empty)
                && (!committed
                    || (v.result_checkpoint_id == p.target.checkpoint_id
                        && v.result_directory_id.as_ref() == Some(&p.directory_checkpoint_id))),
        )?;
    }
    if let Some(sequence) = v.migration_sequence {
        check::require(p.last_sequence.checked_add(1) == Some(sequence))?;
    }
    for changes in [&v.changes, &v.directory_changes].into_iter().flatten() {
        super::command_validation::changes(changes)?;
    }
    if let Some(changes) = &v.changes {
        for diff in changes {
            check::require(diff.path == p.name || diff.path.starts_with(&format!("{}/", p.name)))?;
        }
    }
    Ok(())
}

pub(super) fn receipt(r: &SkillResult<MigrationReceipt>) -> Result<(), ApiError> {
    let Some(data) = &r.data else {
        return Ok(());
    };
    view(&data.result, true)?;
    common::optional_id(&data.replacement_id)?;
    check::require(
        r.committed
            && !r.retryable
            && r.errors.is_empty()
            && r.operation_id == data.result.operation_id
            && r.status == data.current_status
            && ["ready", "conflicted", "superseded"].contains(&r.status.as_str())
            && (r.status == "superseded"
                || (data.replacement_id.is_none() && data.superseded_reason.is_none())),
    )
}
