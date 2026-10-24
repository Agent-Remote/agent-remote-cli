//! Shared local-source review and exact-key remote account configuration import.
mod receipt;
pub mod source;
mod types;
use crate::{
    account_defaults::Context,
    account_operations,
    api::{self, ApiError},
    config::AppPaths,
    local_state::{ImportRecord, LocalState},
};
pub use receipt::PublicReceipt;
use serde::Serialize;
use std::path::{Path, PathBuf};
pub use types::{
    valid_digest, valid_uuid, Discovery, Error, ManifestEntry, Plan, Result, Selection,
};

fn mapped(error: account_operations::Error) -> Error {
    Error {
        code: error.code,
        http_status: error.http_status,
    }
}
fn read_error(error: ApiError) -> Error {
    Error {
        code: match error.status_code() {
            Some(401) => "authentication_required",
            Some(403) => "permission_denied",
            _ => "account_import_status_unknown",
        },
        http_status: error.status_code(),
    }
}
fn submission_error(error: &ApiError) -> Error {
    Error {
        code: if error.status_code() == Some(409) && error.code() == Some("SKILL_MANAGER_OWNS_PATH")
        {
            "account_import_skills_managed"
        } else if matches!(error.status_code(), Some(400 | 401 | 403 | 404 | 422)) {
            "account_import_rejected"
        } else {
            "account_import_outcome_unknown"
        },
        http_status: error.status_code(),
    }
}
fn local_error(_: impl std::fmt::Display) -> Error {
    Error::new("account_import_journal_unavailable")
}
fn check(paths: &AppPaths, context: &Context, account: &str) -> Result<()> {
    if !valid_uuid(account) {
        return Err(Error::new("invalid_params"));
    }
    if paths.home() != context.home {
        return Err(Error::new("configuration_changed"));
    }
    let actual = crate::config::Config::load_strict(paths)
        .map_err(|_| Error::new("configuration_unavailable"))?;
    if actual.server_url != context.server_url
        || actual.active_device_id != context.active_device_id
    {
        return Err(Error::new("configuration_changed"));
    }
    Ok(())
}
pub fn source_home() -> Result<PathBuf> {
    crate::platform::user_home_dir().ok_or_else(|| Error::new("account_import_source_invalid"))
}
fn check_source(expected: &Path) -> Result<()> {
    if source_home()? != expected {
        return Err(Error::new("account_import_source_changed"));
    }
    Ok(())
}
pub fn discover(selection: &Selection) -> Result<Discovery> {
    source::discover_at(&source_home()?, selection)
}
fn plan(
    context: Context,
    account: &str,
    capture: source::Capture,
) -> Result<(Plan, Vec<api::ToolAccountConfigImportFile>)> {
    let mut value = Plan {
        context,
        account_id: account.into(),
        selection: capture.discovery.selection,
        source_home: capture.discovery.source_home,
        include: capture.discovery.include,
        exclude: capture.discovery.exclude,
        manifest: capture.manifest,
        total_bytes: capture.total_bytes,
        source_fingerprint: capture.fingerprint,
        intent_fingerprint: String::new(),
        digest: String::new(),
    };
    value.intent_fingerprint = receipt::plan_intent(&value)?;
    value.digest = types::hash(&serde_json::to_vec(&value).map_err(types::source_error)?);
    Ok((value, capture.files))
}
async fn capture(home: PathBuf, selection: Selection) -> Result<source::Capture> {
    tokio::task::spawn_blocking(move || source::capture(&home, &selection))
        .await
        .map_err(types::source_error)?
}
/// Reads source bytes locally; never loads credentials, writes state, or contacts Server.
pub async fn prepare(
    paths: &AppPaths,
    context: Context,
    account: &str,
    selection: Selection,
    home: PathBuf,
) -> Result<Plan> {
    check(paths, &context, account)?;
    check_source(&home)?;
    let result = plan(context.clone(), account, capture(home, selection).await?)?.0;
    check(paths, &context, account)?;
    Ok(result)
}
#[derive(Serialize)]
pub struct Validation {
    pub context: Context,
    pub account_id: String,
    pub selection: Selection,
    pub source_home: PathBuf,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub audit_written: bool,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
    pub warning_codes: Vec<String>,
}
/// Explicit Server policy validation writes an audit record, but reads/uploads no source bytes.
pub async fn validate(
    paths: &AppPaths,
    context: Context,
    account: &str,
    selection: Selection,
    home: PathBuf,
    expected_include: Vec<String>,
) -> Result<Validation> {
    check(paths, &context, account)?;
    check_source(&home)?;
    let discovery = source::discover_at(&home, &selection)?;
    if discovery.include != expected_include {
        return Err(Error::new("account_import_source_changed"));
    }
    let authority = account_operations::authorize(paths, &context)
        .await
        .map_err(mapped)?;
    let response = authority
        .client
        .create_tool_account_config_import(
            authority.token.token.as_str(),
            account,
            &api::ToolAccountConfigImportRequest {
                tool_type: selection.tool.clone(),
                source: "local_cli".into(),
                include: discovery.include.clone(),
                exclude: discovery.exclude.clone(),
                files: Vec::new(),
                include_resume_history: selection.include_resume_history,
                dry_run: true,
            },
        )
        .await
        .map_err(|e| submission_error(&e))?;
    let all: std::collections::BTreeSet<_> =
        response.accepted.iter().chain(&response.rejected).collect();
    let selected: std::collections::BTreeSet<_> = discovery.include.iter().collect();
    if response.tool_account_id != account
        || !response.dry_run
        || response.task_id.is_some()
        || response.account_remote_path.is_some()
        || response.imported_file_count.is_some_and(|n| n != 0)
        || response.warnings.len() > 64
        || all != selected
        || response.accepted.len() + response.rejected.len() != selected.len()
    {
        return Err(Error::new("account_import_outcome_unknown"));
    }
    // Legacy Server warning prose is untrusted. Fixed local risk categories cover the reviewed roots.
    let warning_codes = warnings(&discovery.include);
    Ok(Validation {
        context,
        account_id: account.into(),
        selection,
        source_home: home,
        include: discovery.include,
        exclude: discovery.exclude,
        audit_written: true,
        accepted: response.accepted,
        rejected: response.rejected,
        warning_codes,
    })
}
fn warnings(include: &[String]) -> Vec<String> {
    let mut result = Vec::new();
    if include
        .iter()
        .any(|v| ["~/.claude/plugins", "~/.claude/hooks"].contains(&v.as_str()))
    {
        result.push("CONFIG_IMPORT_EXECUTABLE_REVIEW_REQUIRED".into());
    }
    if include.iter().any(|v| v.ends_with(".md")) {
        result.push("CONFIG_IMPORT_CUSTOM_MARKDOWN_REVIEW_REQUIRED".into());
    }
    result
}
#[derive(Serialize)]
pub struct Pending {
    pub home: PathBuf,
    pub items: Vec<ImportRecord>,
}
/// Reads only existing local metadata, retaining the original context across configuration switches.
pub fn pending(paths: &AppPaths) -> Result<Pending> {
    let items = LocalState::account_import_records(paths).map_err(local_error)?;
    for item in &items {
        if item.context.home != paths.home()
            || !valid_uuid(&item.account_id)
            || !valid_uuid(&item.request_id)
            || !valid_digest(&item.digest)
            || !valid_digest(&item.intent_fingerprint)
            || item
                .task_id
                .as_ref()
                .is_some_and(|v| !receipt::valid_task(v, &item.account_id))
            || !matches!(
                item.phase.as_str(),
                "pending"
                    | "accepted"
                    | "rejected"
                    | "succeeded"
                    | "failed"
                    | "cancelled"
                    | "expired"
            )
        {
            return Err(local_error("invalid journal record"));
        }
    }
    Ok(Pending {
        home: paths.home().into(),
        items,
    })
}
fn persist(paths: &AppPaths, original: &ImportRecord, next: &ImportRecord) -> Result<()> {
    let state = LocalState::open(paths).map_err(local_error)?;
    if !state
        .update_account_import(original, next)
        .map_err(local_error)?
    {
        return Err(local_error("journal changed"));
    }
    Ok(())
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    pub confirmed: bool,
    pub expected_context: Context,
    pub account_id: String,
    pub selection: Selection,
    pub expected_source_home: PathBuf,
    pub expected_digest: String,
    pub request_id: String,
}
/// Durably reserve the original key before exactly one POST. Repeated local apply never replays it.
pub async fn apply(paths: &AppPaths, input: Apply) -> Result<PublicReceipt> {
    if !input.confirmed {
        return Err(Error::new("confirmation_required"));
    }
    if !valid_uuid(&input.request_id) || !valid_digest(&input.expected_digest) {
        return Err(Error::new("invalid_params"));
    }
    check(paths, &input.expected_context, &input.account_id)?;
    check_source(&input.expected_source_home)?;
    let (plan, files) = plan(
        input.expected_context.clone(),
        &input.account_id,
        capture(input.expected_source_home, input.selection).await?,
    )?;
    if plan.digest != input.expected_digest {
        return Err(Error::new("account_import_source_changed"));
    }
    if files.is_empty() {
        return Err(Error::new("account_import_empty"));
    }
    let authority = account_operations::authorize(paths, &input.expected_context)
        .await
        .map_err(mapped)?;
    let record = ImportRecord {
        context: input.expected_context,
        account_id: input.account_id,
        request_id: input.request_id,
        digest: input.expected_digest,
        intent_fingerprint: receipt::plan_intent(&plan)?,
        task_id: None,
        phase: "pending".into(),
    };
    // Credentials and configuration are locked; SQLite closes before the HTTP await.
    {
        let state = LocalState::open(paths).map_err(local_error)?;
        state.init_schema().map_err(local_error)?;
        if !state.reserve_account_import(&record).map_err(local_error)? {
            return Err(Error::new("account_import_recovery_required"));
        }
    }
    let request = api::account_import::Request {
        schema_version: 1,
        request_id: record.request_id.clone(),
        expected_intent_fingerprint: record.intent_fingerprint.clone(),
        tool_type: plan.selection.tool,
        source: "local_cli".into(),
        include: plan.include,
        exclude: plan.exclude,
        files,
        include_resume_history: plan.selection.include_resume_history,
        dry_run: false,
    };
    let response = match authority
        .client
        .submit_account_import(authority.token.token.as_str(), &record.account_id, &request)
        .await
    {
        Ok(response) => response,
        Err(error) => {
            let mapped = submission_error(&error);
            if matches!(
                mapped.code,
                "account_import_rejected" | "account_import_skills_managed"
            ) {
                let mut next = record.clone();
                next.phase = "rejected".into();
                persist(paths, &record, &next)
                    .map_err(|_| Error::new("account_import_outcome_unknown"))?;
            }
            return Err(mapped);
        }
    };
    receipt::validate(&response, &record)
        .map_err(|_| Error::new("account_import_outcome_unknown"))?;
    let mut next = record.clone();
    next.task_id = Some(response.task_id.clone());
    next.phase = "accepted".into();
    persist(paths, &record, &next).map_err(|_| Error::new("account_import_outcome_unknown"))?;
    let count = response.file_count;
    Ok(receipt::public(response, &next, "accepted", count))
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub expected_context: Context,
    pub account_id: String,
    pub request_id: String,
    pub expected_digest: String,
    #[serde(deserialize_with = "crate::account_defaults::required_nullable")]
    pub expected_task_id: Option<String>,
}
/// Recover only the original caller key and its exact immutable task, never latest-task guesses.
pub async fn status(paths: &AppPaths, input: Status) -> Result<PublicReceipt> {
    check(paths, &input.expected_context, &input.account_id)?;
    if !valid_uuid(&input.request_id)
        || !valid_digest(&input.expected_digest)
        || input
            .expected_task_id
            .as_ref()
            .is_some_and(|v| !receipt::valid_task(v, &input.account_id))
    {
        return Err(Error::new("invalid_params"));
    }
    let record = pending(paths)?
        .items
        .into_iter()
        .find(|r| r.request_id == input.request_id)
        .ok_or_else(|| Error::new("account_import_request_not_recorded"))?;
    if record.context != input.expected_context
        || record.account_id != input.account_id
        || record.digest != input.expected_digest
        || input
            .expected_task_id
            .as_ref()
            .is_some_and(|v| record.task_id.as_ref().is_some_and(|t| t != v))
    {
        return Err(Error::new("account_import_request_mismatch"));
    }
    let authority = account_operations::authorize(paths, &input.expected_context)
        .await
        .map_err(mapped)?;
    let response = authority
        .client
        .account_import_request(
            authority.token.token.as_str(),
            &record.account_id,
            &record.request_id,
        )
        .await
        .map_err(read_error)?;
    receipt::validate(&response, &record)?;
    if input
        .expected_task_id
        .as_ref()
        .is_some_and(|v| v != &response.task_id)
    {
        return Err(Error::new("account_import_response_invalid"));
    }
    let task = authority
        .client
        .get_tool_account_config_import_status(
            authority.token.token.as_str(),
            &record.account_id,
            &response.task_id,
        )
        .await
        .map_err(read_error)?;
    if task.task_id != response.task_id
        || !matches!(
            task.status.as_str(),
            "pending" | "leased" | "running" | "succeeded" | "failed" | "cancelled" | "expired"
        )
        || task.file_count > response.file_count
        || task.files_written.len() > response.manifest.len()
        || task.error.as_ref().is_some_and(|s| s.len() > 65536)
    {
        return Err(Error::new("account_import_response_invalid"));
    }
    if task.status == "succeeded" && task.file_count != response.file_count {
        return Err(Error::new("account_import_response_invalid"));
    }
    let mut next = record.clone();
    next.task_id = Some(response.task_id.clone());
    next.phase = if matches!(task.status.as_str(), "pending" | "leased" | "running") {
        "accepted".into()
    } else {
        task.status.clone()
    };
    Ok(receipt::public(
        response,
        &next,
        &task.status,
        task.file_count,
    ))
}

#[derive(Serialize)]
pub struct Forgotten {
    pub context: Context,
    pub account_id: String,
    pub request_id: String,
    pub digest: String,
    pub task_id: Option<String>,
    pub forgotten: bool,
}
/// Forget only after a fresh exact-key/task observation proves a terminal remote task.
pub async fn forget(paths: &AppPaths, input: Status) -> Result<Forgotten> {
    let record = pending(paths)?
        .items
        .into_iter()
        .find(|r| r.request_id == input.request_id)
        .ok_or_else(|| Error::new("account_import_request_not_recorded"))?;
    if record.context != input.expected_context
        || record.account_id != input.account_id
        || record.digest != input.expected_digest
        || input
            .expected_task_id
            .as_ref()
            .is_some_and(|v| record.task_id.as_ref().is_some_and(|stored| stored != v))
    {
        return Err(Error::new("account_import_request_mismatch"));
    }
    if record.phase == "rejected" && record.task_id.is_none() {
        if input.expected_task_id.is_some() {
            return Err(Error::new("account_import_request_mismatch"));
        }
        let state = LocalState::open(paths).map_err(local_error)?;
        if !state.forget_account_import(&record).map_err(local_error)? {
            return Err(Error::new("account_import_request_mismatch"));
        }
        return Ok(Forgotten {
            context: record.context,
            account_id: record.account_id,
            request_id: record.request_id,
            digest: record.digest,
            task_id: None,
            forgotten: true,
        });
    }
    let result = status(paths, input).await?;
    if !matches!(
        result.phase.as_str(),
        "succeeded" | "failed" | "cancelled" | "expired"
    ) {
        return Err(Error::new("account_import_not_settled"));
    }
    let state = LocalState::open(paths).map_err(local_error)?;
    if !state.forget_account_import(&record).map_err(local_error)? {
        return Err(Error::new("account_import_request_mismatch"));
    }
    Ok(Forgotten {
        context: result.context,
        account_id: result.account_id,
        request_id: result.request_id,
        digest: result.digest,
        task_id: Some(result.task_id),
        forgotten: true,
    })
}

#[cfg(test)]
#[path = "../tests/unit/src/account_import.rs"]
mod tests;
