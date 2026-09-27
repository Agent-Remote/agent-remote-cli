//! Original-operation retry transport, independent of configuration mutation keys.

use serde::{Deserialize, Serialize};

use super::skills::{invalid_skill_response, SkillMutation, SkillResult};
use super::{ApiClient, ApiError};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillRetryTarget {
    pub account_id: String,
    pub attempt_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SkillRetryRequest {
    pub idempotency_key: String,
    pub expected_generation: i64,
    pub targets: Vec<SkillRetryTarget>,
}

impl ApiClient {
    pub async fn retry_skill(
        &self,
        token: &str,
        operation_id: &str,
        payload: &SkillRetryRequest,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let id = uuid::Uuid::parse_str(operation_id).map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .post(self.endpoint(&format!("/api/v1/skills/operations/{id}/retries")))
            .json(payload);
        let result = self.send_skill_request(request, token).await?;
        validate(&result, operation_id)?;
        Ok(result)
    }

    pub async fn skill_retry_by_key(
        &self,
        token: &str,
        operation_id: &str,
        key: &str,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        let id = uuid::Uuid::parse_str(operation_id).map_err(|_| invalid_skill_response())?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/operations/{id}/retries")))
            .query(&[("key", key)]);
        let result = self.send_skill_request(request, token).await?;
        validate(&result, operation_id)?;
        Ok(result)
    }
}

fn validate(result: &SkillResult<SkillMutation>, operation_id: &str) -> Result<(), ApiError> {
    super::skill_mutations::validate_mutation_receipt(result)?;
    if result.data.is_some() && result.operation_id.as_deref() != Some(operation_id) {
        return Err(invalid_skill_response());
    }
    Ok(())
}
