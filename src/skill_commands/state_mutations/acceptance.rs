//! State publication acceptance never reselects heads after uncertain submission.

use super::journal::{saved, Saved};
use crate::api::skill_state::StateCommandView;
use crate::api::skills::{SkillError, SkillResult};
use crate::api::ApiError;
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skill_commands::{acceptance::retryable_transport, context::ContextData};
use anyhow::{bail, Context, Result};
use std::collections::BTreeMap;
use tokio::time::{sleep, Duration};

pub(super) async fn execute(
    context: &ContextData,
    proposed: SkillCommandRecord,
    recovering: bool,
) -> Result<(SkillResult<StateCommandView>, i32)> {
    let to_save = proposed.clone();
    let retained = skill_command_state(context.paths.clone(), move |state| {
        state.begin_skill_command(&to_save)
    })
    .await?;
    let request = saved(&retained)?.context("retained command is not a state request")?;
    let recovering = recovering || retained.idempotency_key != proposed.idempotency_key;
    let (submitted, interrupted) = tokio::select! {
        biased;
        signal = crate::skill_commands::interruption::cancelled() => { signal?; (Err(anyhow::anyhow!("state acceptance interrupted")), true) }
        result = submit(context, &request, recovering) => (result, false),
    };
    let mut result = match submitted {
        Ok(result) => result,
        Err(error) => return Ok(unknown(&request, &error, interrupted)),
    };
    let operation = result.operation_id.clone();
    if skill_command_state(context.paths.clone(), move |state| {
        state.receive_skill_command(&retained, operation.as_deref())
    })
    .await
    .is_err()
    {
        result.errors.push(SkillError {
            code: "LOCAL_RECEIPT_PENDING".to_owned(), message: "Server result is shown, but local receipt persistence failed. Repeat the same state command to recover it.".to_owned(),
            object_id: result.operation_id.clone(), details: Default::default(),
        });
    }
    let code = if result.committed && result.data.is_some() && result.errors.is_empty() {
        0
    } else {
        1
    };
    Ok((result, code))
}

async fn submit(
    context: &ContextData,
    saved: &Saved,
    mut recovering: bool,
) -> Result<SkillResult<StateCommandView>> {
    for attempt in 0..3 {
        if recovering {
            match context
                .client
                .skill_state_operation_by_key(&context.token, &saved.request.idempotency_key)
                .await
            {
                Ok(result) if result.data.is_some() => {
                    saved.validate_receipt(&result)?;
                    return Ok(result);
                }
                Ok(result) if not_found(&result) => {}
                Ok(_) => bail!("state receipt lookup was rejected"),
                Err(error) if retryable_transport(&error) && attempt < 2 => {
                    sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
        match context
            .client
            .change_skill_state(&context.token, &saved.request)
            .await
        {
            Ok(result) => {
                saved.validate_receipt(&result)?;
                return Ok(result);
            }
            Err(error) if retryable_transport(&error) && attempt < 2 => {
                recovering = true;
                sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("state acceptance could not be confirmed")
}

pub(in crate::skill_commands) fn not_found<T>(result: &SkillResult<T>) -> bool {
    result.data.is_none()
        && result.status == "failed"
        && !result.committed
        && !result.retryable
        && result.operation_id.is_none()
        && result.errors.len() == 1
        && result.errors[0].code == "OPERATION_NOT_FOUND"
}

fn unknown(
    saved: &Saved,
    error: &anyhow::Error,
    interrupted: bool,
) -> (SkillResult<StateCommandView>, i32) {
    let cause = error.downcast_ref::<ApiError>();
    let code = cause
        .and_then(ApiError::code)
        .filter(|code| {
            code.len() <= 80
                && code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
        .unwrap_or(if interrupted {
            "SKILL_INTERRUPTED"
        } else {
            "SKILL_RESULT_UNKNOWN"
        });
    (SkillResult { schema_version: 1, operation_id: None, status: "unknown".to_owned(), committed: false,
        retryable: cause.is_some_and(retryable_transport), data: None, errors: vec![SkillError {
            code: code.to_owned(), message: "State acceptance is unknown. Repeat this exact command or use skill status --last to recover the original result.".to_owned(),
            object_id: Some(saved.request.selector.account_id.clone()), details: BTreeMap::from([
                ("idempotency_key".to_owned(), serde_json::json!(saved.request.idempotency_key)),
                ("commit_state".to_owned(), serde_json::json!("unknown")),
            ]),
        }] }, if interrupted {130} else {1})
}
