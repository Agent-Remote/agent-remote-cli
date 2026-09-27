//! Route original operation queries without conflating library deployment and state publication.

use super::{print_json, query_status, render_operation, state_mutations};
use crate::api::skills::SkillResult;
use crate::api::{ApiClient, ApiError};
use crate::cli::skills::SkillStatusArgs;
use crate::config::AppPaths;
use crate::local_state::skill_command_state;
use anyhow::{Context, Result};
use std::cell::Cell;
use tokio::time::{timeout_at, Duration, Instant};

pub(super) async fn run(
    paths: AppPaths,
    client: &ApiClient,
    token: &str,
    mut args: SkillStatusArgs,
    json: bool,
) -> Result<i32> {
    if args.storage {
        return super::diagnostics::status(client, token, json).await;
    }
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let mut key = None;
    if args.last {
        let user = client.skill_user_id(token).await?;
        let identity = client.skill_server_identity()?;
        let (record, operation) = skill_command_state(paths, move |state| {
            state.last_skill_command_record(&identity, &user)
        })
        .await?
        .context("no locally recorded skill operation for this user")?;
        if let Some(saved) = super::state_prune::saved(&record)? {
            args.operation_id = operation.clone();
            let result = state_query(
                client.skill_prune_operation_by_key(token, &record.idempotency_key),
                &args,
                deadline,
                json,
            )
            .await?;
            saved.validate_receipt(&result)?;
            if operation
                .as_ref()
                .is_some_and(|id| result.data.is_some() && result.operation_id.as_ref() != Some(id))
            {
                anyhow::bail!("prune operation differs from local receipt");
            }
            return prune_display(client, token, result, &args, deadline, json).await;
        }
        if let Some(saved) = super::state_migrations::saved(&record)? {
            args.operation_id = operation.clone();
            let result = state_query(
                client.skill_migration_operation_by_key(token, &record.idempotency_key),
                &args,
                deadline,
                json,
            )
            .await?;
            saved.validate_receipt(&result)?;
            if operation
                .as_ref()
                .is_some_and(|id| result.data.is_some() && result.operation_id.as_ref() != Some(id))
            {
                anyhow::bail!("migration operation differs from local receipt");
            }
            let code = super::state_migrations::exit_code(&result);
            super::state_migrations::render(&result, code, json)?;
            return Ok(code);
        }
        if let Some(saved) = super::state_resolutions::saved(&record)? {
            args.operation_id = operation.clone();
            let result = state_query(
                client.skill_resolution_operation_by_key(
                    token,
                    saved.target.kind,
                    &record.idempotency_key,
                ),
                &args,
                deadline,
                json,
            )
            .await?;
            saved.validate_receipt(&result)?;
            if operation
                .as_ref()
                .is_some_and(|id| result.data.is_some() && result.operation_id.as_ref() != Some(id))
            {
                anyhow::bail!("resolution operation differs from local receipt");
            }
            let code = super::state_resolutions::exit_code(&result);
            super::state_resolutions::render(&result, code, json)?;
            return Ok(code);
        }
        if let Some(saved) = state_mutations::saved(&record)? {
            args.operation_id = operation.clone();
            let result = state_query(
                client.skill_state_operation_by_key(token, &record.idempotency_key),
                &args,
                deadline,
                json,
            )
            .await?;
            saved.validate_receipt(&result)?;
            if operation
                .as_ref()
                .is_some_and(|id| result.data.is_some() && result.operation_id.as_ref() != Some(id))
            {
                anyhow::bail!("state operation differs from local receipt");
            }
            let code = if result.committed && result.errors.is_empty() {
                0
            } else {
                1
            };
            state_mutations::render(&result, code, json)?;
            return Ok(code);
        }
        if let Some(saved) = super::retry_plan::saved(&record)? {
            args.operation_id = Some(saved.operation_id.clone());
            if operation
                .as_ref()
                .is_some_and(|id| id != &saved.operation_id)
            {
                anyhow::bail!("retry operation differs from local receipt");
            }
            let result = state_query(
                client.skill_retry_by_key(token, &saved.operation_id, &record.idempotency_key),
                &args,
                deadline,
                json,
            )
            .await?;
            saved.validate_receipt(&result)?;
            let (result, code) = super::wait_status(client, token, &args, result, deadline).await?;
            if json {
                print_json(&result)?;
            } else {
                render_operation(&result);
            }
            return Ok(code);
        }
        args.operation_id = operation;
        key = Some(record.idempotency_key);
    }
    let (result, code) = query_status(client, token, &args, key.as_deref()).await?;
    if !args.last && state_mutations::not_found(&result) {
        let state = state_query(
            client.skill_state_operation(
                token,
                args.operation_id.as_deref().context("operation missing")?,
            ),
            &args,
            deadline,
            json,
        )
        .await?;
        if !state_mutations::not_found(&state) {
            let code = if state.committed && state.errors.is_empty() {
                0
            } else {
                1
            };
            state_mutations::render(&state, code, json)?;
            return Ok(code);
        }
        for domain in [
            crate::api::skill_state::ResolutionDomain::Publication,
            crate::api::skill_state::ResolutionDomain::Migration,
        ] {
            let receipt = state_query(
                client.skill_resolution_operation(
                    token,
                    domain,
                    args.operation_id.as_deref().context("operation missing")?,
                ),
                &args,
                deadline,
                json,
            )
            .await?;
            if !state_mutations::not_found(&receipt) {
                let code = super::state_resolutions::exit_code(&receipt);
                super::state_resolutions::render(&receipt, code, json)?;
                return Ok(code);
            }
        }
        let receipt = state_query(
            client.skill_migration_operation(
                token,
                args.operation_id.as_deref().context("operation missing")?,
            ),
            &args,
            deadline,
            json,
        )
        .await?;
        if !state_mutations::not_found(&receipt) {
            let code = super::state_migrations::exit_code(&receipt);
            super::state_migrations::render(&receipt, code, json)?;
            return Ok(code);
        }
        let receipt = state_query(
            client.skill_prune_operation(
                token,
                args.operation_id.as_deref().context("operation missing")?,
            ),
            &args,
            deadline,
            json,
        )
        .await?;
        if !state_mutations::not_found(&receipt) {
            return prune_display(client, token, receipt, &args, deadline, json).await;
        }
    }
    if json {
        print_json(&result)?;
    } else {
        render_operation(&result);
    }
    if code == 3 {
        eprintln!(
            "Still pending; the remote operation continues. Query the same operation ID again."
        );
    }
    Ok(code)
}

async fn prune_display(
    client: &ApiClient,
    token: &str,
    receipt: SkillResult<crate::api::skill_state::PruneReceipt>,
    args: &SkillStatusArgs,
    deadline: Instant,
    json: bool,
) -> Result<i32> {
    let displaying = Cell::new(false);
    let work = async {
        let display = super::state_prune::display_status(client, token, receipt, json, &displaying);
        if args.wait {
            timeout_at(deadline, display).await.map_err(|_| {
                if displaying.get() {
                    return super::SkillExit(1).into();
                }
                super::remote_result::failure(
                    "SKILL_STATUS_UNAVAILABLE",
                    "Prune details query timed out; query the same original operation again.",
                    args.operation_id.clone(),
                )
            })?
        } else {
            display.await
        }
    };
    tokio::select! {
        result = work => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            if displaying.get() {
                return Err(super::SkillExit(130).into());
            }
            let error = super::remote_result::failure("SKILL_INTERRUPTED", "Prune details query interrupted; cleanup and its original receipt remain unchanged.", args.operation_id.clone());
            super::print_failure(&error, json);
            Err(super::SkillExit(130).into())
        }
    }
}

async fn state_query<T>(
    request: impl std::future::Future<Output = Result<SkillResult<T>, ApiError>>,
    args: &SkillStatusArgs,
    deadline: Instant,
    json: bool,
) -> Result<SkillResult<T>> {
    let work = async {
        if args.wait {
            timeout_at(deadline, request)
                .await
                .map_err(|_| {
                    super::remote_result::failure(
                        "SKILL_STATUS_UNAVAILABLE",
                        "State receipt query timed out. Query the same original operation again.",
                        args.operation_id.clone(),
                    )
                })?
                .map_err(Into::into)
        } else {
            request.await.map_err(Into::into)
        }
    };
    tokio::select! {
        result = work => result,
        signal = tokio::signal::ctrl_c() => {
            signal?;
            let error = super::remote_result::failure("SKILL_INTERRUPTED", "State receipt query interrupted; the original remote operation is unchanged.", args.operation_id.clone());
            super::print_failure(&error,json);
            Err(super::SkillExit(130).into())
        }
    }
}
