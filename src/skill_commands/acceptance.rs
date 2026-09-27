//! Shared configuration acceptance, exact-request recovery, persistence and bounded waiting.

use super::requests::Request;
use super::{operation_exit, print_json, render_operation, SkillExit};
use crate::api::skills::{SkillError, SkillMutation, SkillResult};
use crate::api::{ApiClient, ApiError};
use crate::cli::skills::{SkillMutationOptions, SkillStatusArgs};
use crate::config::AppPaths;
use crate::local_state::{skill_command_state, SkillCommandRecord};
use anyhow::{bail, Result};
use std::collections::BTreeMap;
use std::time::Duration;
use tokio::time::{sleep, Instant};

pub(super) async fn execute(
    paths: AppPaths,
    client: &ApiClient,
    token: &str,
    proposed: SkillCommandRecord,
    recovering: bool,
    options: &SkillMutationOptions,
    json: bool,
) -> Result<()> {
    let (result, code) =
        execute_result(paths, client, token, proposed, recovering, options).await?;
    super::output::finish(json, move || render(&result, code, json)).await
}

fn render(result: &SkillResult<SkillMutation>, code: i32, json: bool) -> Result<()> {
    if code == 130 && !json {
        return Err(SkillExit(130).into());
    }
    if json {
        print_json(result)?;
    } else {
        render_operation(result);
        if result.status == "unknown" {
            if let Some(key) = result
                .errors
                .first()
                .and_then(|error| error.details.get("idempotency_key"))
                .and_then(|key| key.as_str())
            {
                eprintln!("Retained idempotency key: {key}");
            }
        }
    }
    if code == 3 {
        eprintln!(
            "Still pending; the remote operation continues. Query the original operation ID again."
        );
    }
    if code == 0 {
        Ok(())
    } else {
        Err(SkillExit(code).into())
    }
}

/// Return the original per-skill result so batch orchestration can emit exactly one envelope.
pub(super) async fn execute_result(
    paths: AppPaths,
    client: &ApiClient,
    token: &str,
    proposed: SkillCommandRecord,
    recovering: bool,
    options: &SkillMutationOptions,
) -> Result<(SkillResult<SkillMutation>, i32)> {
    let proposed_request = Request::retained(&proposed)?;
    let to_save = proposed.clone();
    let retained = skill_command_state(paths.clone(), move |state| {
        state.begin_skill_command(&to_save)
    })
    .await?;
    let request = Request::retained(&retained)?;
    if !request.same_intent_kind(&proposed_request) {
        bail!("retained request kind differs");
    }
    let recovered = recovering || retained.idempotency_key != proposed.idempotency_key;
    let (submitted, interrupted) = tokio::select! {
        biased;
        signal = crate::skill_commands::interruption::cancelled() => {
            signal?;
            (Err(anyhow::anyhow!("acceptance interrupted")), true)
        }
        result = submit(client, token, &request, recovered) => (result, false),
    };
    let mut result = match submitted {
        Ok(value) => value,
        Err(error) => {
            let cause = error.downcast_ref::<ApiError>();
            let retryable = cause.is_some_and(retryable_transport);
            let code = cause
                .and_then(ApiError::code)
                .filter(|code| {
                    code.len() <= 80
                        && code.bytes().all(|byte| {
                            byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_'
                        })
                })
                .unwrap_or(if interrupted {
                    "SKILL_INTERRUPTED"
                } else {
                    "SKILL_RESULT_UNKNOWN"
                });
            let result: SkillResult<SkillMutation> = SkillResult {
                schema_version: 1,
                operation_id: None,
                status: "unknown".to_owned(),
                committed: false,
                retryable,
                data: None,
                errors: vec![SkillError {
                    code: code.to_owned(),
                    message: "Acceptance could not be confirmed. Restore user login/connectivity, then repeat this command or use skill status --last.".to_owned(),
                    object_id: request.object_id(),
                    details: BTreeMap::from([
                        ("idempotency_key".to_owned(), serde_json::json!(request.key())),
                        ("commit_state".to_owned(), serde_json::json!("unknown")),
                    ]),
                }],
            };
            return Ok((result, if interrupted { 130 } else { 1 }));
        }
    };
    let to_acknowledge = retained.clone();
    let operation = result.operation_id.clone();
    if skill_command_state(paths.clone(), move |state| {
        state.receive_skill_command(&to_acknowledge, operation.as_deref())
    })
    .await
    .is_err()
    {
        result.errors.push(SkillError {
            code: "LOCAL_RECEIPT_PENDING".to_owned(),
            message: "Server result is shown, but local receipt persistence failed. Repeat the same command to recover it.".to_owned(),
            object_id: result.operation_id.clone(),
            details: Default::default(),
        });
    }
    if super::interruption::is_cancelled() {
        return Ok((result, 130));
    }
    let mut code = operation_exit(&result);
    if code == 3 && options.no_wait && result.committed {
        code = 0;
    } else if code == 3 {
        let args = SkillStatusArgs {
            storage: false,
            operation_id: result.operation_id.clone(),
            last: false,
            wait: true,
            timeout: options.timeout,
        };
        (result, code) = super::wait_status(
            client,
            token,
            &args,
            result,
            Instant::now() + Duration::from_secs(options.timeout),
        )
        .await?;
    }
    Ok((result, code))
}

async fn submit(
    client: &ApiClient,
    token: &str,
    request: &Request,
    mut recovering: bool,
) -> Result<SkillResult<SkillMutation>> {
    for attempt in 0..3 {
        if recovering {
            match request.lookup(client, token).await {
                Ok(result) if result.data.is_some() => {
                    request.validate_receipt(&result)?;
                    return Ok(result);
                }
                Ok(result)
                    if result.errors.len() == 1
                        && result.errors[0].code == "OPERATION_NOT_FOUND" => {}
                Ok(_) => bail!("original skill operation lookup was rejected"),
                Err(error) if retryable_transport(&error) && attempt < 2 => {
                    sleep(Duration::from_millis(200)).await;
                    continue;
                }
                Err(error) => return Err(error.into()),
            }
        }
        match request.send(client, token).await {
            Ok(result) => {
                request.validate_receipt(&result)?;
                return Ok(result);
            }
            Err(error) if retryable_transport(&error) && attempt < 2 => {
                recovering = true;
                sleep(Duration::from_millis(200)).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("skill acceptance could not be confirmed")
}

pub(super) fn retryable_transport(error: &ApiError) -> bool {
    error.code() != Some("INVALID_SKILL_RESPONSE")
        && error.status_code().is_none_or(|code| code >= 500)
}
