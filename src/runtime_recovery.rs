//! Shared reviewed administrator recovery and public original-key retention.
mod authority;
mod receipt;
mod types;
use crate::{
    api::{reviewed_recovery, runtime_recovery::original_task_matches, ApiError},
    config::AppPaths,
    local_state::LocalState,
};
pub use authority::{authority, valid_context};
pub use receipt::valid_binding;
pub use types::*;

fn local_error(_: impl std::fmt::Display) -> Error {
    Error::new("runtime_recovery_registry_unavailable")
}
fn submission_error(error: &ApiError) -> Error {
    let status = error.status_code();
    let code = if status == Some(409)
        && error.code() == Some("RUNTIME_MIGRATION_RECOVERY_REVIEW_CHANGED")
    {
        "runtime_recovery_review_changed"
    } else if status.is_some_and(|s| (400..500).contains(&s) && !matches!(s, 408 | 409 | 429)) {
        "runtime_recovery_rejected"
    } else {
        "runtime_recovery_outcome_unknown"
    };
    Error {
        code,
        http_status: status,
        submitted: true,
    }
}
/// Observe an exact migration without creating a task or claiming it is eligible.
pub async fn inspect(
    paths: &AppPaths,
    context: UserContext,
    account: &str,
    original: &str,
    action: Action,
) -> Result<Plan> {
    if !crate::api::runtime_recovery::canonical_uuid(account)
        || !original_task_matches(account, original)
    {
        return Err(Error::new("invalid_params"));
    }
    let access = authority::authorize(paths, &context).await?;
    let data = access
        .client
        .recovery_inspect(access.token.as_str(), account, original)
        .await
        .map_err(authority::read_error)?;
    authority::recheck(paths, &access).await?;
    if data.schema_version != 1
        || !data.original.valid(account)
        || data.original.task_id != original
        || !matches!(
            data.original_status.as_str(),
            "pending" | "leased" | "running" | "succeeded" | "failed" | "cancelled" | "expired"
        )
        || !matches!(
            data.account_status.as_str(),
            "binding_requested"
                | "binding_session_starting"
                | "binding_waiting_user_login"
                | "binding_verifying"
                | "active"
                | "expired"
                | "disabled"
                | "failed"
                | "node_unavailable"
                | "migrating"
        )
    {
        return Err(Error::new("runtime_recovery_response_invalid"));
    }
    Ok(Plan {
        digest: digest(&context, account, &data.original, action)?,
        context,
        account_id: account.into(),
        original: data.original,
        action,
        original_status: data.original_status,
        account_status: data.account_status,
    })
}
/// Read public caller keys only, including when configuration or login is unavailable.
pub fn pending(paths: &AppPaths) -> Result<Pending> {
    Ok(Pending {
        home: paths.home().into(),
        items: LocalState::runtime_recovery_records(paths).map_err(local_error)?,
    })
}
fn record(paths: &AppPaths, key: &str) -> Result<Option<Record>> {
    Ok(pending(paths)?
        .items
        .into_iter()
        .find(|r| r.request_id == key))
}

/// Reserve original intent before one POST; ambiguous acceptance is never replayed.
pub async fn apply(paths: &AppPaths, input: Apply) -> Result<Receipt> {
    if !input.confirmed {
        return Err(Error::new("confirmation_required"));
    }
    if !valid_context(&input.expected_context)
        || !input.original.valid(&input.account_id)
        || !crate::api::runtime_recovery::canonical_uuid(&input.request_id)
    {
        return Err(Error::new("invalid_params"));
    }
    if digest(
        &input.expected_context,
        &input.account_id,
        &input.original,
        input.action,
    )? != input.expected_digest
    {
        return Err(Error::new("runtime_recovery_review_changed"));
    }
    let authority = authority::write(paths, &input.expected_context).await?;
    let access = &authority.access;
    let original = Record {
        context: input.expected_context.clone(),
        account_id: input.account_id.clone(),
        request_id: input.request_id.clone(),
        digest: input.expected_digest.clone(),
        original: input.original.clone(),
        action: input.action,
        binding: None,
        phase: "unknown".into(),
        rejection_code: None,
    };
    {
        let state = LocalState::open(paths).map_err(local_error)?;
        state.init_schema().map_err(local_error)?;
        if !state
            .reserve_runtime_recovery(&original)
            .map_err(local_error)?
        {
            return Err(Error::new("runtime_recovery_pending"));
        }
    }
    let response = access
        .client
        .recovery_apply(
            access.token.as_str(),
            &input.account_id,
            &reviewed_recovery::Request {
                schema_version: 1,
                request_id: &input.request_id,
                action: input.action,
                expected_original: &input.original,
            },
        )
        .await;
    let status_input = Status {
        expected_context: input.expected_context,
        account_id: input.account_id,
        request_id: input.request_id,
        expected_digest: Some(input.expected_digest),
        expected_binding: None,
    };
    match response {
        Ok(data) => {
            let value =
                receipt::receipt(data, &status_input, Some(&original)).map_err(|_| Error {
                    code: "runtime_recovery_outcome_unknown",
                    http_status: None,
                    submitted: true,
                })?;
            let mut next = original.clone();
            next.binding = Some(value.recovery.binding.clone());
            next.phase = "accepted".into();
            update(paths, &original, &next)?;
            Ok(value)
        }
        Err(error) => {
            let failure = submission_error(&error);
            if failure.code != "runtime_recovery_outcome_unknown" {
                let mut next = original.clone();
                next.phase = "rejected".into();
                next.rejection_code = Some(failure.code.into());
                update(paths, &original, &next)?;
            }
            Err(failure)
        }
    }
}
fn update(paths: &AppPaths, original: &Record, next: &Record) -> Result<()> {
    let updated = (|| {
        let state = LocalState::open(paths)?;
        state.update_runtime_recovery(original, next)
    })();
    if !updated.unwrap_or(false) {
        return Err(Error {
            code: "runtime_recovery_outcome_unknown",
            http_status: None,
            submitted: true,
        });
    }
    Ok(())
}
/// Exact-key GET supports both retained intent and manually entered historical keys.
pub async fn status(paths: &AppPaths, input: Status) -> Result<Receipt> {
    receipt::validate_input(&input)?;
    let stored = record(paths, &input.request_id)?;
    receipt::match_record(&input, stored.as_ref())?;
    let access = authority::authorize(paths, &input.expected_context).await?;
    let data = access
        .client
        .recovery_request(access.token.as_str(), &input.account_id, &input.request_id)
        .await
        .map_err(authority::read_error)?;
    authority::recheck(paths, &access).await?;
    receipt::receipt(data, &input, stored.as_ref())
}
/// Forget only a known rejection or freshly proved exact terminal receipt.
pub async fn forget(paths: &AppPaths, input: Status) -> Result<Forgotten> {
    receipt::validate_input(&input)?;
    if paths.home() != input.expected_context.home {
        return Err(Error::new("configuration_changed"));
    }
    let original = record(paths, &input.request_id)?
        .ok_or_else(|| Error::new("runtime_recovery_receipt_changed"))?;
    receipt::match_record(&input, Some(&original))?;
    if original.phase == "rejected" {
        if input.expected_binding.is_some() {
            return Err(Error::new("runtime_recovery_receipt_changed"));
        }
    } else {
        let observed = status(paths, input.clone()).await?;
        if !receipt::terminal(observed.recovery.status) {
            return Err(Error::new("runtime_recovery_not_terminal"));
        }
    }
    let state = LocalState::open(paths).map_err(local_error)?;
    if !state
        .forget_runtime_recovery(&original)
        .map_err(local_error)?
    {
        return Err(Error::new("runtime_recovery_receipt_changed"));
    }
    Ok(Forgotten {
        context: original.context,
        account_id: original.account_id,
        request_id: original.request_id,
        digest: original.digest,
        forgotten: true,
    })
}

#[cfg(test)]
#[path = "../tests/unit/src/runtime_recovery.rs"]
mod tests;
