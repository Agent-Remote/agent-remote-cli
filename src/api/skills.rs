//! Typed user-library queries and the stable skill result envelope.

use std::collections::BTreeMap;

use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use super::skill_diagnostics::{HistoryDiagnostic, StorageView};
use super::skill_effective::{AccountSkillView, SystemSkillView};
use super::{read_response_body_bounded, url_encode, ApiClient, ApiError};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SkillResult<T> {
    pub schema_version: u8,
    pub operation_id: Option<String>,
    pub status: String,
    pub committed: bool,
    pub retryable: bool,
    pub data: Option<T>,
    pub errors: Vec<SkillError>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SkillError {
    pub code: String,
    pub message: String,
    pub object_id: Option<String>,
    pub details: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillLibrary {
    pub generation: i64,
    pub items: Vec<SkillInstallation>,
    #[serde(default)]
    pub local_items: Vec<SkillLocal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_items: Vec<SystemSkillView>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillInstallation {
    pub id: String,
    pub name: String,
    pub epoch: i64,
    pub removed: bool,
    pub source: SkillSource,
    pub tracking: BTreeMap<String, serde_json::Value>,
    pub default_enabled: bool,
    pub default_revision_id: String,
    pub revisions: Vec<SkillRevision>,
    pub tool_overrides: BTreeMap<String, SkillRuleOverride>,
    pub account_overrides: BTreeMap<String, SkillAccountOverride>,
    pub effective: Option<SkillResolvedRule>,
    pub project_discovery: String,
    pub model_loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_state: Option<AccountSkillView>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum SkillDetails {
    Library(SkillInstallation),
    Local(SkillLocal),
}

impl SkillDetails {
    pub fn id(&self) -> &str {
        match self {
            Self::Library(item) => &item.id,
            Self::Local(item) => &item.id,
        }
    }
    pub fn name(&self) -> &str {
        match self {
            Self::Library(item) => &item.name,
            Self::Local(item) => &item.name,
        }
    }
    pub fn removed(&self) -> bool {
        match self {
            Self::Library(item) => item.removed,
            Self::Local(item) => item.status == "removed",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SkillLocalOrigin {
    AccountLocal,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillLocal {
    pub origin: SkillLocalOrigin,
    pub id: String,
    pub account_id: String,
    pub name: String,
    pub status: String,
    pub enabled: bool,
    pub default_revision_id: String,
    pub source_checkpoint_id: String,
    pub revisions: Vec<SkillLocalRevision>,
    pub effective: SkillResolvedRule,
    pub model_loaded: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage: Option<StorageView>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_state: Option<AccountSkillView>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillLocalRevision {
    pub id: String,
    pub number: i64,
    pub content_digest: String,
    pub retained: bool,
    pub subtree_prefix: String,
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<HistoryDiagnostic>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillSource {
    pub kind: String,
    pub locator: String,
    pub subpath: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillProvenance {
    pub ref_kind: String,
    pub r#ref: String,
    pub commit: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillRevision {
    pub id: String,
    pub number: i64,
    pub content_digest: String,
    pub provenance: SkillProvenance,
    pub retained: bool,
    pub metadata: BTreeMap<String, serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retention: Option<HistoryDiagnostic>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillRuleOverride {
    pub enabled: Option<bool>,
    pub revision_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillAccountOverride {
    pub enabled: Option<bool>,
    pub revision_id: Option<String>,
    pub tool_type: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillResolvedRule {
    pub enabled: bool,
    pub revision_id: String,
    pub enabled_source: String,
    pub revision_source: String,
    pub eligible: bool,
    pub included: bool,
    pub exclusion_reason: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillMutation {
    pub generation: i64,
    pub skill_ids: Vec<String>,
    pub revision_ids: Vec<String>,
    pub changed: bool,
    pub warnings: Vec<String>,
    pub targets: Vec<SkillTarget>,
    pub replacement_id: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SkillTarget {
    pub account_id: String,
    pub node_id: Option<String>,
    pub readiness: String,
    pub deploy_on_first_use: bool,
    pub error_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_number: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retryable: Option<bool>,
}

impl SkillTarget {
    pub(super) fn validate_attempt(&self) -> Result<(), ApiError> {
        let canonical =
            |id: &str| uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id);
        let valid = match (&self.attempt_id, self.attempt_number) {
            (None, None) => self.retryable != Some(true),
            (Some(id), Some(number)) => {
                canonical(id)
                    && canonical(&self.account_id)
                    && self.node_id.as_deref().is_none_or(canonical)
                    && number > 0
                    && self.plan_digest.as_ref().is_some_and(|digest| {
                        digest.len() == 64
                            && digest
                                .bytes()
                                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                    })
                    && (self.retryable != Some(true)
                        || self.readiness == "failed"
                            && matches!(
                                self.error_code.as_deref(),
                                Some(
                                    "NODE_UNAVAILABLE"
                                        | "TRANSFER_FAILED"
                                        | "QUOTA_EXCEEDED"
                                        | "DEPLOYMENT_INTERRUPTED"
                                )
                            ))
            }
            _ => false,
        };
        if !valid {
            return Err(invalid_skill_response());
        }
        Ok(())
    }
}

impl ApiClient {
    pub async fn list_skills(
        &self,
        token: &str,
        tool: Option<&str>,
        account: Option<&str>,
        effective: bool,
    ) -> Result<SkillResult<SkillLibrary>, ApiError> {
        self.list_skill_catalog(token, tool, account, effective, false)
            .await
    }

    pub async fn list_skill_catalog(
        &self,
        token: &str,
        tool: Option<&str>,
        account: Option<&str>,
        effective: bool,
        include_system: bool,
    ) -> Result<SkillResult<SkillLibrary>, ApiError> {
        let mut query = vec![("effective", effective.to_string())];
        if include_system {
            query.push(("include_system", "true".to_owned()));
        }
        skill_scope(&mut query, tool, account)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills"))
            .query(&query);
        let result: SkillResult<SkillLibrary> = self.send_skill_request(request, token).await?;
        if let Some(data) = &result.data {
            super::skill_effective::validate_library(data, account)?;
        }
        Ok(result)
    }

    pub async fn skill_info(
        &self,
        token: &str,
        identifier: &str,
        tool: Option<&str>,
        account: Option<&str>,
    ) -> Result<SkillResult<SkillDetails>, ApiError> {
        let mut query = Vec::new();
        skill_scope(&mut query, tool, account)?;
        let request = self
            .client
            .get(self.endpoint(&format!(
                "/api/v1/skills/installations/{}",
                url_encode(identifier)
            )))
            .query(&query);
        let result: SkillResult<SkillDetails> = self.send_skill_request(request, token).await?;
        if let Some(details) = &result.data {
            super::skill_diagnostics::details(details)?;
            super::skill_effective::validate_details(details, account)?;
        }
        Ok(result)
    }

    pub async fn skill_status(
        &self,
        token: &str,
        operation_id: &str,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let id = uuid::Uuid::parse_str(operation_id).map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/operations/{id}")));
        let result: SkillResult<SkillMutation> = self.send_skill_request(request, token).await?;
        if result.data.is_some() && result.operation_id.as_deref() != Some(id.to_string().as_str())
        {
            return Err(invalid_skill_response());
        }
        if let Some(data) = &result.data {
            for target in &data.targets {
                target.validate_attempt()?;
            }
        }
        Ok(result)
    }

    pub(super) async fn send_skill_request<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        token: &str,
    ) -> Result<SkillResult<T>, ApiError> {
        self.send_skill_request_bounded(request, token, super::MAX_API_RESPONSE_BYTES)
            .await
    }

    pub(super) async fn send_skill_request_bounded<T: DeserializeOwned>(
        &self,
        request: reqwest::RequestBuilder,
        token: &str,
        limit: usize,
    ) -> Result<SkillResult<T>, ApiError> {
        let response = request
            .bearer_auth(token)
            .send()
            .await
            .map_err(|_| ApiError {
                status: None,
                code: Some("SKILL_TRANSPORT_FAILED".to_owned()),
                message: "Skill request could not be completed.".to_owned(),
            })?;
        let status = response.status();
        let body = read_response_body_bounded(response, limit).await?;
        // Common authentication failures use the existing API envelope, not SkillResult.
        if !status.is_success() && serde_json::from_str::<super::ErrorEnvelope>(&body).is_ok() {
            let error = ApiError::from_error_response(status, body);
            return Err(ApiError {
                status: Some(status),
                code: error.code,
                message: "Skill request was rejected by the server.".to_owned(),
            });
        }
        let result: SkillResult<T> =
            serde_json::from_str(&body).map_err(|_| invalid_skill_response())?;
        if result.schema_version != 1
            || result.status.is_empty()
            || (!status.is_success()
                && (result.errors.is_empty()
                    || result.data.is_some()
                    || result.status != "failed"
                    || result.committed))
            || (status.is_success() && result.data.is_none())
            || result
                .operation_id
                .as_ref()
                .is_some_and(|id| uuid::Uuid::parse_str(id).is_err())
        {
            return Err(invalid_skill_response());
        }
        Ok(result)
    }
}

fn skill_scope(
    query: &mut Vec<(&str, String)>,
    tool: Option<&str>,
    account: Option<&str>,
) -> Result<(), ApiError> {
    if tool.is_some() && account.is_some() {
        return Err(invalid_skill_response());
    }
    if let Some(tool) = tool {
        query.push(("tool", tool.to_owned()));
    }
    if let Some(account) = account {
        let account = uuid::Uuid::parse_str(account).map_err(|_| invalid_skill_response())?;
        query.push(("account_id", account.to_string()));
    }
    Ok(())
}

pub(super) fn invalid_skill_response() -> ApiError {
    ApiError {
        status: Some(StatusCode::BAD_GATEWAY),
        code: Some("INVALID_SKILL_RESPONSE".to_owned()),
        message: "Server returned an invalid skill response.".to_owned(),
    }
}
