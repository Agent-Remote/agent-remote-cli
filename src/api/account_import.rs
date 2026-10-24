//! Caller-key-bound configuration import acceptance; legacy dry-run remains separate.
use super::{ApiClient, ApiError, Envelope, ToolAccountConfigImportFile};
use crate::account_import::ManifestEntry;
use serde::{Deserialize, Serialize};

#[derive(Serialize)]
pub struct Request {
    pub schema_version: u8,
    pub request_id: String,
    pub expected_intent_fingerprint: String,
    pub tool_type: String,
    pub source: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub files: Vec<ToolAccountConfigImportFile>,
    pub include_resume_history: bool,
    pub dry_run: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u8,
    pub request_id: String,
    pub tool_account_id: String,
    pub tool_type: String,
    pub source: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub include_resume_history: bool,
    pub dry_run: bool,
    pub manifest: Vec<ManifestEntry>,
    pub intent_fingerprint: String,
    pub task_id: String,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
    pub warnings: Vec<String>,
    pub account_remote_path: String,
    pub file_count: u32,
}
impl ApiClient {
    pub async fn submit_account_import(
        &self,
        token: &str,
        account: &str,
        request: &Request,
    ) -> Result<Receipt, ApiError> {
        let response: Envelope<Receipt> = self
            .post(
                &format!("/api/v1/tool-accounts/{account}/config-import-requests"),
                Some(token),
                request,
            )
            .await?;
        Ok(response.data)
    }
    pub async fn account_import_request(
        &self,
        token: &str,
        account: &str,
        request_id: &str,
    ) -> Result<Receipt, ApiError> {
        let response: Envelope<Receipt> = self
            .get(
                &format!("/api/v1/tool-accounts/{account}/config-import-requests/{request_id}"),
                Some(token),
            )
            .await?;
        Ok(response.data)
    }
}
