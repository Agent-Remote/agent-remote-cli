//! Skill command orchestration and bounded operation waiting.

mod acceptance;
mod check;
mod configuration;
mod confirmation;
mod context;
mod diagnostics;
mod effective;
mod install;
mod install_source;
mod interruption;
mod mutations;
mod output;
mod remote_result;
mod requests;
mod retry;
mod retry_plan;
mod state;
mod state_migrations;
mod state_mutations;
mod state_prune;
mod state_resolutions;
mod status;
mod update_plan;
mod update_result;
mod update_source;
mod updates;
mod upload;

use std::fmt;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::Serialize;
use tokio::time::{sleep_until, timeout_at, Instant};

use crate::api::skills::{
    SkillDetails, SkillError, SkillInstallation, SkillLocal, SkillMutation, SkillResult,
};
use crate::api::{ApiClient, ApiError};
use crate::auth::{load_user_token, user_login_error};
use crate::cli::skills::{SkillCommand, SkillStatusArgs};
use crate::config::{AppPaths, Config};
use crate::terminal::{Details, Table};

/// An already-rendered skill result whose process exit code must be preserved.
#[derive(Debug)]
pub struct SkillExit(pub i32);
impl fmt::Display for SkillExit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "skill command exited with {}", self.0)
    }
}
impl std::error::Error for SkillExit {}

pub async fn run(paths: AppPaths, command: SkillCommand, json: bool) -> Result<()> {
    if let SkillCommand::State { command: state } = &command {
        use crate::cli::skills::SkillStateCommand;
        if !matches!(state, SkillStateCommand::Prune(_)) {
            return interruption::scope(Box::pin(run_command(paths, command, json))).await;
        }
    }
    if matches!(
        &command,
        SkillCommand::List(_)
            | SkillCommand::Info(_)
            | SkillCommand::Status(_)
            | SkillCommand::State { .. }
            | SkillCommand::Check(_)
    ) {
        run_command(paths, command, json).await
    } else {
        interruption::scope(Box::pin(run_command(paths, command, json))).await
    }
}

async fn run_command(paths: AppPaths, command: SkillCommand, json: bool) -> Result<()> {
    let _output = crate::terminal::suppress_output(json);
    if let SkillCommand::State { command } = command {
        return state::run(paths, command, json).await;
    }
    if let SkillCommand::Add(args) = command {
        return install::run(paths, args, json).await;
    }
    if let SkillCommand::Check(args) = command {
        return check::run(paths, args, json).await;
    }
    if let SkillCommand::Update(args) = command {
        return updates::run(paths, args, json).await;
    }
    if let SkillCommand::Retry(args) = command {
        return retry::run(paths, args, json).await;
    }
    if !matches!(
        &command,
        SkillCommand::List(_) | SkillCommand::Info(_) | SkillCommand::Status(_)
    ) {
        return mutations::run(paths, command, json).await;
    }
    let server = Config::load(&paths)?
        .server_url
        .context("server profile missing")?;
    let token = load_user_token(&paths, &server)
        .await?
        .ok_or_else(user_login_error)?;
    let client = ApiClient::new(server.clone())?;
    let code = match command {
        SkillCommand::List(args) if args.session.is_some() => {
            effective::session(&client, &token, &args, json).await?
        }
        SkillCommand::List(args) => {
            let result = client
                .list_skill_catalog(
                    &token,
                    args.tool.as_deref(),
                    args.account_id.as_deref(),
                    args.effective,
                    args.include_system,
                )
                .await?;
            if json {
                print_json(&result)?;
            } else {
                render_summary(&result);
                if let Some(library) = &result.data {
                    let mut table = Table::new([
                        "Skill",
                        "ID",
                        "Enabled",
                        "Revision",
                        "Included",
                        "Rule source",
                    ]);
                    for item in &library.items {
                        let rule = &item.effective;
                        table.row([
                            safe(&item.name),
                            safe(&item.id),
                            rule.as_ref()
                                .map_or(item.default_enabled, |r| r.enabled)
                                .to_string(),
                            safe(
                                rule.as_ref()
                                    .map_or(item.default_revision_id.as_str(), |r| &r.revision_id),
                            ),
                            rule.as_ref()
                                .map_or("not resolved".to_owned(), |r| r.included.to_string()),
                            rule.as_ref().map_or("user".to_owned(), |r| {
                                format!(
                                    "enabled: {}; revision: {}",
                                    safe(&r.enabled_source),
                                    safe(&r.revision_source)
                                )
                            }),
                        ]);
                    }
                    for item in &library.local_items {
                        table.row([
                            safe(&item.name),
                            safe(&item.id),
                            item.enabled.to_string(),
                            safe(&item.default_revision_id),
                            item.effective.included.to_string(),
                            format!("account local: {}", safe(&item.account_id)),
                        ]);
                    }
                    table.render();
                    effective::systems(&library.system_items);
                    for item in &library.items {
                        if let Some(state) = &item.account_state {
                            effective::account(&item.name, state);
                        }
                    }
                    for item in &library.local_items {
                        if let Some(state) = &item.account_state {
                            effective::account(&item.name, state);
                        }
                    }
                    eprintln!("Library generation {}. Rule resolution does not prove runtime deployment or model loading.", library.generation);
                }
            }
            query_exit(&result)
        }
        SkillCommand::Info(args) => {
            let result = client
                .skill_info(
                    &token,
                    &args.skill,
                    args.tool.as_deref(),
                    args.account_id.as_deref(),
                )
                .await?;
            if json {
                print_json(&result)?;
            } else {
                render_summary(&result);
                if let Some(item) = &result.data {
                    match item {
                        SkillDetails::Library(item) => render_installation(item),
                        SkillDetails::Local(item) => render_local(item),
                    }
                }
            }
            query_exit(&result)
        }
        SkillCommand::Status(args) => status::run(paths, &client, &token, args, json).await?,
        _ => anyhow::bail!("unsupported skill query"),
    };
    if code == 0 {
        Ok(())
    } else {
        Err(SkillExit(code).into())
    }
}

async fn query_status(
    client: &ApiClient,
    token: &str,
    args: &SkillStatusArgs,
    key: Option<&str>,
) -> Result<(SkillResult<SkillMutation>, i32)> {
    let deadline = Instant::now() + Duration::from_secs(args.timeout);
    let query = async {
        match args.operation_id.as_deref() {
            Some(id) => client
                .skill_status(token, id)
                .await
                .map_err(anyhow::Error::from),
            None => client
                .skill_operation_by_key(token, key.context("skill recovery key is missing")?)
                .await
                .map_err(anyhow::Error::from),
        }
    };
    let result = if args.wait {
        timeout_at(deadline, query)
            .await
            .context("initial status request timed out")??
    } else {
        query.await?
    };
    wait_status(client, token, args, result, deadline).await
}

async fn wait_status(
    client: &ApiClient,
    token: &str,
    args: &SkillStatusArgs,
    mut result: SkillResult<SkillMutation>,
    deadline: Instant,
) -> Result<(SkillResult<SkillMutation>, i32)> {
    let operation_id = result.operation_id.clone();
    loop {
        let state = operation_exit(&result);
        if !args.wait || state != 3 {
            return Ok((result, if state == 3 { 0 } else { state }));
        }
        if Instant::now() >= deadline {
            return Ok((result, 3));
        }
        let next = (Instant::now() + Duration::from_secs(1)).min(deadline);
        tokio::select! {
            _ = sleep_until(next) => {},
            signal = crate::skill_commands::interruption::cancelled() => { signal?; return Ok((result, 130)); }
        }
        if Instant::now() >= deadline {
            return Ok((result, 3));
        }
        let original_id = operation_id
            .as_deref()
            .context("pending operation lacks an ID")?;
        let received = tokio::select! {
            received = timeout_at(deadline, client.skill_status(token, original_id)) => received,
            signal = crate::skill_commands::interruption::cancelled() => { signal?; return Ok((result, 130)); }
        };
        match received {
            Err(_) => return Ok((result, 3)),
            Ok(Ok(updated)) if updated.data.is_none() => {
                result.errors.extend(updated.errors);
                return Ok((result, 1));
            }
            Ok(Ok(updated)) => result = updated,
            Ok(Err(error))
                if error.code() != Some("INVALID_SKILL_RESPONSE")
                    && error.status_code().is_none_or(|code| code >= 500) => {}
            Ok(Err(error)) => {
                result.errors.push(SkillError {
                    code: error.code().unwrap_or("SKILL_QUERY_FAILED").to_owned(),
                    message:
                        "Status refresh failed; data contains the last observed operation state."
                            .to_owned(),
                    object_id: result.operation_id.clone(),
                    details: Default::default(),
                });
                return Ok((result, 1));
            }
        }
    }
}

fn query_exit<T>(result: &SkillResult<T>) -> i32 {
    if result.status == "ready" && result.errors.is_empty() && result.data.is_some() {
        0
    } else if result
        .errors
        .iter()
        .any(|error| error.code == "LOCAL_SKILL_SCOPE_REQUIRED")
    {
        2
    } else {
        1
    }
}

fn operation_exit(result: &SkillResult<SkillMutation>) -> i32 {
    let Some(data) = &result.data else {
        return 1;
    };
    if !matches!(
        result.status.as_str(),
        "failed"
            | "conflict"
            | "conflicted"
            | "needs_resolution"
            | "superseded"
            | "cancelled"
            | "pending"
            | "accepted"
            | "preparing"
            | "running"
            | "upload_pending"
            | "migration_pending"
            | "stored"
            | "ready"
            | "succeeded"
            | "completed"
            | "published"
    ) {
        return 1;
    }
    if !result.errors.is_empty()
        || data.replacement_id.is_some()
        || matches!(
            result.status.as_str(),
            "failed" | "conflict" | "conflicted" | "needs_resolution" | "superseded" | "cancelled"
        )
        || data.targets.iter().any(|target| {
            matches!(
                target.readiness.as_str(),
                "failed" | "unsupported" | "needs_resolution"
            )
        })
    {
        return 1;
    }
    if data
        .targets
        .iter()
        .any(|target| !matches!(target.readiness.as_str(), "pending" | "stored" | "ready"))
    {
        return 1;
    }
    if matches!(
        result.status.as_str(),
        "pending" | "accepted" | "preparing" | "running" | "upload_pending" | "migration_pending"
    ) || data
        .targets
        .iter()
        .any(|target| target.readiness == "pending")
    {
        return 3;
    }
    if result.committed
        && matches!(
            result.status.as_str(),
            "stored" | "ready" | "succeeded" | "completed" | "published"
        )
    {
        0
    } else {
        1
    }
}

fn print_json<T: Serialize>(value: &T) -> Result<()> {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}
fn safe(value: &str) -> String {
    value.chars().flat_map(char::escape_debug).collect()
}

fn render_summary<T>(result: &SkillResult<T>) {
    Details::new()
        .field("Status", safe(&result.status))
        .field("Committed", result.committed)
        .field("Retryable", result.retryable)
        .render();
    for error in &result.errors {
        eprintln!("{}: {}", safe(&error.code), safe(&error.message));
    }
}

fn render_local(item: &SkillLocal) {
    if let Some(state) = &item.account_state {
        effective::account(&item.name, state);
    }
    if let Some(storage) = &item.storage {
        diagnostics::storage(storage);
    }
    for revision in &item.revisions {
        if let Some(retention) = &revision.retention {
            diagnostics::retention(retention);
        }
    }
    Details::new()
        .field("Skill", safe(&item.name))
        .field("ID", safe(&item.id))
        .field("Source", "account_local")
        .field("Account", safe(&item.account_id))
        .field("Status", safe(&item.status))
        .field("Enabled", item.enabled)
        .field("Initial revision", safe(&item.default_revision_id))
        .field("Source checkpoint", safe(&item.source_checkpoint_id))
        .render();
    let mut revisions = Table::new([
        "Revision",
        "Number",
        "Retained",
        "Content digest",
        "Subtree",
    ]);
    for revision in &item.revisions {
        revisions.row([
            safe(&revision.id),
            revision.number.to_string(),
            revision.retained.to_string(),
            safe(&revision.content_digest),
            safe(&revision.subtree_prefix),
        ]);
    }
    revisions.render();
    eprintln!("Account-local configuration; this view does not prove runtime deployment or model loading.");
}

fn render_installation(item: &SkillInstallation) {
    if let Some(state) = &item.account_state {
        effective::account(&item.name, state);
    }
    if let Some(storage) = &item.storage {
        diagnostics::storage(storage);
    }
    for revision in &item.revisions {
        if let Some(retention) = &revision.retention {
            diagnostics::retention(retention);
        }
    }
    Details::new()
        .field("Skill", safe(&item.name))
        .field("ID", safe(&item.id))
        .field("Removed", item.removed)
        .field(
            "Source",
            format!(
                "{} {} {}",
                safe(&item.source.kind),
                safe(&item.source.locator),
                safe(&item.source.subpath)
            ),
        )
        .field("Default enabled", item.default_enabled)
        .field("Default revision", safe(&item.default_revision_id))
        .field("Epoch", item.epoch)
        .render();
    if let Some(rule) = &item.effective {
        Details::new()
            .field("Enabled", rule.enabled)
            .field("Enabled source", safe(&rule.enabled_source))
            .field("Revision", safe(&rule.revision_id))
            .field("Revision source", safe(&rule.revision_source))
            .field("Eligible", rule.eligible)
            .field("Included", rule.included)
            .field(
                "Exclusion",
                safe(rule.exclusion_reason.as_deref().unwrap_or("none")),
            )
            .render();
    }
    let mut revisions = Table::new([
        "Revision",
        "Number",
        "Retained",
        "Content digest",
        "Ref",
        "Commit",
    ]);
    for revision in &item.revisions {
        revisions.row([
            safe(&revision.id),
            revision.number.to_string(),
            revision.retained.to_string(),
            safe(&revision.content_digest),
            safe(&revision.provenance.r#ref),
            safe(&revision.provenance.commit),
        ]);
    }
    revisions.render();
    let mut overrides = Table::new(["Scope", "Enabled", "Pinned revision"]);
    for (tool, rule) in &item.tool_overrides {
        overrides.row([
            format!("tool:{}", safe(tool)),
            rule.enabled.map_or("inherit".to_owned(), |v| v.to_string()),
            safe(rule.revision_id.as_deref().unwrap_or("inherit")),
        ]);
    }
    for (account, rule) in &item.account_overrides {
        overrides.row([
            format!("account:{} ({})", safe(account), safe(&rule.tool_type)),
            rule.enabled.map_or("inherit".to_owned(), |v| v.to_string()),
            safe(rule.revision_id.as_deref().unwrap_or("inherit")),
        ]);
    }
    overrides.render();
    eprintln!("Library rules only; runtime checkpoints, project/plugin discovery and model loading are not established by this view.");
}

fn render_operation(result: &SkillResult<SkillMutation>) {
    render_summary(result);
    Details::new()
        .field(
            "Operation",
            safe(result.operation_id.as_deref().unwrap_or("none")),
        )
        .render();
    if let Some(data) = &result.data {
        Details::new()
            .field("Generation", data.generation)
            .field("Changed", data.changed)
            .field(
                "Replacement",
                safe(data.replacement_id.as_deref().unwrap_or("none")),
            )
            .render();
        let mut targets = Table::new([
            "Account",
            "Node",
            "Readiness",
            "Attempt",
            "Retryable",
            "Deploy on first use",
            "Error",
        ]);
        for target in &data.targets {
            targets.row([
                safe(&target.account_id),
                safe(target.node_id.as_deref().unwrap_or("none")),
                safe(&target.readiness),
                target
                    .attempt_number
                    .map_or_else(|| "unknown".to_owned(), |number| number.to_string()),
                target
                    .retryable
                    .map_or_else(|| "unknown".to_owned(), |value| value.to_string()),
                target.deploy_on_first_use.to_string(),
                safe(target.error_code.as_deref().unwrap_or("none")),
            ]);
        }
        targets.render();
        for warning in &data.warnings {
            eprintln!("{}", safe(warning));
        }
    }
}

/// Emit a bounded skill envelope for failures before a Server skill result is available.
pub fn print_failure(error: &anyhow::Error, json: bool) {
    if let Some(failure) = error.downcast_ref::<remote_result::Rejected>() {
        if json {
            println!("{}", serde_json::json!(failure.0));
        } else {
            render_summary(&failure.0);
        }
        return;
    }
    let code = error
        .downcast_ref::<ApiError>()
        .and_then(ApiError::code)
        .filter(|code| {
            code.len() <= 80
                && code
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
        })
        .unwrap_or("SKILL_QUERY_FAILED");
    let message =
        "Skill query failed. Check your user login, server configuration and connectivity.";
    if json {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"operation_id":null,"status":"failed","committed":false,"retryable":false,"data":null,"errors":[{"code":code,"message":message,"object_id":null,"details":{}}]})
        );
    } else {
        eprintln!("{code}: {message}");
    }
}
