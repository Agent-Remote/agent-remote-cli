use super::*;
use crate::api::{
    reviewed_recovery,
    runtime_recovery::{RecoveryBinding, RecoveryStatus, RuntimeRecovery},
};

pub fn valid_binding(
    binding: &RecoveryBinding,
    account: &str,
    key: &str,
    original: Option<(&Original, Action)>,
) -> bool {
    let data = RuntimeRecovery {
        binding: binding.clone(),
        status: RecoveryStatus::Pending,
    };
    data.validate(
        account,
        key,
        original.map(|(o, _)| o.task_id.as_str()),
        original.and_then(|(_, a)| a.legacy()),
    )
    .is_ok()
        && original.is_none_or(|(o, _)| o.matches(binding))
}
pub(super) fn receipt(
    data: reviewed_recovery::Receipt,
    input: &Status,
    record: Option<&Record>,
) -> Result<Receipt> {
    if data.schema_version != 1
        || data.request_id != input.request_id
        || data.action.legacy() != data.binding.action
        || !valid_binding(
            &data.binding,
            &input.account_id,
            &input.request_id,
            record.map(|r| (&r.original, r.action)),
        )
        || input
            .expected_binding
            .as_ref()
            .is_some_and(|b| b != &data.binding)
    {
        return Err(Error::new("runtime_recovery_response_invalid"));
    }
    let succeeded = data.status == RecoveryStatus::Succeeded;
    Ok(Receipt {
        context: input.expected_context.clone(),
        account_id: input.account_id.clone(),
        request_id: input.request_id.clone(),
        digest: record.map(|r| r.digest.clone()),
        target_completion_confirmed: succeeded && data.action == Action::VerifyTarget,
        source_restoration_confirmed: succeeded && data.action != Action::VerifyTarget,
        recovery: RuntimeRecovery {
            binding: data.binding,
            status: data.status,
        },
    })
}
pub(super) fn validate_input(input: &Status) -> Result<()> {
    if !valid_context(&input.expected_context)
        || !crate::api::runtime_recovery::canonical_uuid(&input.account_id)
        || !crate::api::runtime_recovery::canonical_uuid(&input.request_id)
        || input
            .expected_digest
            .as_ref()
            .is_some_and(|d| !crate::account_import::valid_digest(d))
        || input
            .expected_binding
            .as_ref()
            .is_some_and(|b| !valid_binding(b, &input.account_id, &input.request_id, None))
    {
        return Err(Error::new("invalid_params"));
    }
    Ok(())
}
pub(super) fn match_record(input: &Status, record: Option<&Record>) -> Result<()> {
    validate_input(input)?;
    match record {
        None if input.expected_digest.is_none() => Ok(()),
        Some(r)
            if r.context == input.expected_context
                && r.account_id == input.account_id
                && input.expected_digest.as_ref() == Some(&r.digest)
                && r.binding
                    .as_ref()
                    .is_none_or(|b| input.expected_binding.as_ref() == Some(b))
                && input.expected_binding.as_ref().is_none_or(|b| {
                    valid_binding(
                        b,
                        &r.account_id,
                        &r.request_id,
                        Some((&r.original, r.action)),
                    )
                }) =>
        {
            Ok(())
        }
        _ => Err(Error::new("runtime_recovery_receipt_changed")),
    }
}
pub(super) fn terminal(status: RecoveryStatus) -> bool {
    matches!(
        status,
        RecoveryStatus::Succeeded
            | RecoveryStatus::Failed
            | RecoveryStatus::Cancelled
            | RecoveryStatus::Expired
    )
}
