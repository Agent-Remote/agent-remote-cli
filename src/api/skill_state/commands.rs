//! State preview, conditional publication and original-key/ID queries.

use super::{check, command_validation as validate, *};
use crate::api::{skills::invalid_skill_response, ApiClient, ApiError};

const STATE_ENVELOPE_LIMIT: usize = 64 * 1024 * 1024;

impl StateCommandRequest {
    pub fn validate(&self) -> Result<(), ApiError> {
        validate::request(self)
    }
    pub fn validate_receipt(&self, result: &SkillResult<StateCommandView>) -> Result<(), ApiError> {
        validate::result(result, Some(self))
    }
}

impl ApiClient {
    pub async fn skill_current_state(
        &self,
        token: &str,
        selector: &StateSelector,
    ) -> Result<SkillResult<CurrentState>, ApiError> {
        let query = check::selector(selector)?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/current"))
            .query(&query);
        let result: SkillResult<CurrentState> = self
            .send_skill_request_bounded(request, token, STATE_ENVELOPE_LIMIT)
            .await?;
        check::query(&result, &["ready"])?;
        if let Some(current) = &result.data {
            validate::current(current)?;
            check::require(current.selector == *selector)?;
        }
        Ok(result)
    }

    pub async fn change_skill_state(
        &self,
        token: &str,
        request: &StateCommandRequest,
    ) -> Result<SkillResult<StateCommandView>, ApiError> {
        request.validate()?;
        let body = serde_json::to_vec(request).map_err(|_| invalid_skill_response())?;
        check::require(body.len() <= 4 * 1024 * 1024)?;
        let http = self
            .client
            .post(self.endpoint("/api/v1/skills/state/commands"))
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body);
        let result = self
            .send_skill_request_bounded(http, token, STATE_ENVELOPE_LIMIT)
            .await?;
        request.validate_receipt(&result)?;
        Ok(result)
    }

    pub async fn skill_state_operation_by_key(
        &self,
        token: &str,
        key: &str,
    ) -> Result<SkillResult<StateCommandView>, ApiError> {
        check::require(
            !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_graphic()),
        )?;
        let request = self
            .client
            .get(self.endpoint("/api/v1/skills/state/operations"))
            .query(&[("key", key)]);
        let result = self
            .send_skill_request_bounded(request, token, STATE_ENVELOPE_LIMIT)
            .await?;
        validate::result(&result, None)?;
        if result.data.is_some() {
            check::require(result.committed)?;
        }
        Ok(result)
    }

    pub async fn skill_state_operation(
        &self,
        token: &str,
        id: &str,
    ) -> Result<SkillResult<StateCommandView>, ApiError> {
        check::id(id)?;
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/state/operations/{id}")));
        let result = self
            .send_skill_request_bounded(request, token, STATE_ENVELOPE_LIMIT)
            .await?;
        validate::result(&result, None)?;
        if result.data.is_some() {
            check::require(result.committed && result.operation_id.as_deref() == Some(id))?;
        }
        Ok(result)
    }
}
