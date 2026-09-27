//! Exact library mutation payloads; durable retry identity belongs to the command layer.

use serde::{Deserialize, Serialize};

use super::skills::{SkillMutation, SkillProvenance, SkillResult, SkillSource};
use super::{ApiClient, ApiError, Envelope};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillScope {
    pub tools: Vec<String>,
    pub account_id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum SkillChange {
    Enable { scope: SkillScope },
    Disable { scope: SkillScope, all_scopes: bool },
    Pin { scope: SkillScope, revision: String },
    Unpin { scope: SkillScope },
    Inherit { scope: SkillScope, field: String },
    Remove,
    Rollback { revision: Option<String> },
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillMutationRequest {
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub skill: String,
    #[serde(flatten)]
    pub change: SkillChange,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillInstallItem {
    pub name: String,
    pub source: SkillSource,
    pub provenance: SkillProvenance,
    pub tree_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillAddCommand {
    Add,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillAddRequest {
    pub command: SkillAddCommand,
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub items: Vec<SkillInstallItem>,
    pub scope: SkillScope,
    pub scope_explicit: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SkillUpdateCommand {
    Update,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct SkillUpdateRequest {
    pub command: SkillUpdateCommand,
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub skill: String,
    pub item: SkillInstallItem,
    pub stage: bool,
    pub switch_tracking: bool,
}

impl SkillChange {
    pub fn scope(&self) -> Option<&SkillScope> {
        match self {
            Self::Enable { scope }
            | Self::Disable { scope, .. }
            | Self::Pin { scope, .. }
            | Self::Unpin { scope }
            | Self::Inherit { scope, .. } => Some(scope),
            _ => None,
        }
    }

    fn endpoint(&self) -> &'static str {
        match self {
            Self::Remove => "/api/v1/skills/removals",
            Self::Rollback { .. } => "/api/v1/skills/rollbacks",
            _ => "/api/v1/skills/rules",
        }
    }
}

impl ApiClient {
    /// Bind journal metadata to a normalized Server URL without persisting URL credentials.
    pub fn skill_server_identity(&self) -> anyhow::Result<String> {
        let url = reqwest::Url::parse(&self.base_url)?;
        if !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            anyhow::bail!("skill Server URL cannot contain credentials, query or fragment");
        }
        Ok(url.as_str().trim_end_matches('/').to_owned())
    }

    pub async fn skill_user_id(&self, token: &str) -> Result<String, ApiError> {
        #[derive(Deserialize)]
        struct UserIdentity {
            id: String,
        }
        let response: Envelope<UserIdentity> = self.get("/api/v1/users/me", Some(token)).await?;
        uuid::Uuid::parse_str(&response.data.id)
            .map(|id| id.to_string())
            .map_err(|_| super::skills::invalid_skill_response())
    }

    pub async fn change_skill(
        &self,
        token: &str,
        payload: &SkillMutationRequest,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let request = self
            .client
            .post(self.endpoint(payload.change.endpoint()))
            .json(payload);
        let result: SkillResult<SkillMutation> = self.send_skill_request(request, token).await?;
        validate_mutation_receipt(&result)?;
        Ok(result)
    }

    pub async fn install_skills(
        &self,
        token: &str,
        payload: &SkillAddRequest,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let request = self
            .client
            .post(self.endpoint("/api/v1/skills/installations"))
            .json(payload);
        let result: SkillResult<SkillMutation> = self.send_skill_request(request, token).await?;
        validate_mutation_receipt(&result)?;
        Ok(result)
    }

    pub async fn update_skill(
        &self,
        token: &str,
        payload: &SkillUpdateRequest,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let request = self
            .client
            .post(self.endpoint("/api/v1/skills/updates"))
            .json(payload);
        let result: SkillResult<SkillMutation> = self.send_skill_request(request, token).await?;
        validate_mutation_receipt(&result)?;
        Ok(result)
    }

    pub async fn skill_operation_by_key(
        &self,
        token: &str,
        key: &str,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/operations"))
            .query(&[("key", key)]);
        let result: SkillResult<SkillMutation> = self.send_skill_request(request, token).await?;
        validate_mutation_receipt(&result)?;
        Ok(result)
    }
}

pub(super) fn validate_mutation_receipt(
    result: &SkillResult<SkillMutation>,
) -> Result<(), ApiError> {
    if result.data.is_some() && (!result.committed || result.operation_id.is_none()) {
        return Err(super::skills::invalid_skill_response());
    }
    if let Some(data) = &result.data {
        for target in &data.targets {
            target.validate_attempt()?;
        }
    }
    Ok(())
}
