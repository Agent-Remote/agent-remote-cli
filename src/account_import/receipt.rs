use super::{types::hash, Error, ManifestEntry, Plan, Result};
use crate::{api::account_import::Receipt, local_state::ImportRecord};
use serde::Serialize;
use serde_json::json;

pub(crate) fn intent(
    account: &str,
    tool: &str,
    include: &[String],
    exclude: &[String],
    history: bool,
    manifest: &[ManifestEntry],
) -> Result<String> {
    let value = json!({"schema_version":1,"tool_account_id":account,"tool_type":tool,"source":"local_cli","include":include,"exclude":exclude,"include_resume_history":history,"dry_run":false,"files":manifest});
    Ok(hash(&serde_json::to_vec(&value).map_err(|_| {
        Error::new("account_import_response_invalid")
    })?))
}
pub(crate) fn plan_intent(plan: &Plan) -> Result<String> {
    intent(
        &plan.account_id,
        &plan.selection.tool,
        &plan.include,
        &plan.exclude,
        plan.selection.include_resume_history,
        &plan.manifest,
    )
}
pub(crate) fn valid_task(task: &str, account: &str) -> bool {
    task.strip_prefix(&format!("import_tool_account_config:{account}:"))
        .is_some_and(super::valid_uuid)
}
pub(crate) fn warning(value: &str) -> bool {
    matches!(
        value,
        "CONFIG_IMPORT_EXECUTABLE_REVIEW_REQUIRED"
            | "CONFIG_IMPORT_CUSTOM_MARKDOWN_REVIEW_REQUIRED"
    )
}
pub(crate) fn validate(receipt: &Receipt, record: &ImportRecord) -> Result<()> {
    let invalid = || Error::new("account_import_response_invalid");
    if receipt.schema_version != 1
        || receipt.request_id != record.request_id
        || receipt.tool_account_id != record.account_id
        || receipt.tool_type != "claude"
        || receipt.source != "local_cli"
        || receipt.dry_run
        || receipt.intent_fingerprint != record.intent_fingerprint
        || !valid_task(&receipt.task_id, &record.account_id)
        || record
            .task_id
            .as_ref()
            .is_some_and(|v| v != &receipt.task_id)
        || receipt.accepted != receipt.include
        || !receipt.rejected.is_empty()
        || receipt.manifest.is_empty()
        || receipt.manifest.len() > super::source::MAX_ENTRIES
        || receipt.file_count as usize != receipt.manifest.len()
        || receipt.warnings.len() > 2
        || receipt.warnings.iter().any(|v| !warning(v))
        || receipt.account_remote_path.len() > 4096
        || receipt.account_remote_path.chars().any(char::is_control)
    {
        return Err(invalid());
    }
    let mut previous = "";
    let mut total = 0u64;
    for entry in &receipt.manifest {
        if entry.path.as_str() <= previous
            || !entry.path.starts_with("~/.claude/")
            || entry.path.len() > 1024
            || entry.path.chars().any(|c| c.is_control() || c == '\\')
            || entry
                .path
                .split('/')
                .any(|c| c.is_empty() || c == "." || c == "..")
            || !super::valid_digest(&entry.sha256)
            || entry.mode != 0o600
            || entry.size > super::source::MAX_FILE_BYTES
        {
            return Err(invalid());
        }
        previous = &entry.path;
        total += entry.size;
    }
    if total > super::source::MAX_TOTAL_BYTES
        || intent(
            &receipt.tool_account_id,
            &receipt.tool_type,
            &receipt.include,
            &receipt.exclude,
            receipt.include_resume_history,
            &receipt.manifest,
        )? != record.intent_fingerprint
    {
        return Err(invalid());
    }
    Ok(())
}
#[derive(Serialize)]
pub struct PublicReceipt {
    pub context: crate::account_defaults::Context,
    pub account_id: String,
    pub request_id: String,
    pub digest: String,
    pub intent_fingerprint: String,
    pub task_id: String,
    pub phase: String,
    pub accepted: bool,
    pub file_count: u32,
    pub warning_codes: Vec<String>,
}
pub(crate) fn public(
    receipt: Receipt,
    record: &ImportRecord,
    phase: &str,
    count: u32,
) -> PublicReceipt {
    PublicReceipt {
        context: record.context.clone(),
        account_id: record.account_id.clone(),
        request_id: record.request_id.clone(),
        digest: record.digest.clone(),
        intent_fingerprint: record.intent_fingerprint.clone(),
        task_id: receipt.task_id,
        phase: phase.into(),
        accepted: true,
        file_count: count,
        warning_codes: receipt.warnings,
    }
}
