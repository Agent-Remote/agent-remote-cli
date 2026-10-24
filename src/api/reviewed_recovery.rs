//! Additive reviewed administrator recovery routes; no credential lifecycle writes.
use super::runtime_recovery::{RecoveryBinding, RecoveryStatus};
use super::{ApiClient, ApiError, Envelope};
use crate::runtime_recovery::{Action, Original};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authority {
    pub schema_version: u8,
    pub actor_user_id: String,
    pub admin: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inspection {
    pub schema_version: u8,
    pub original: Original,
    pub original_status: String,
    pub account_status: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub schema_version: u8,
    pub request_id: String,
    pub action: Action,
    pub binding: RecoveryBinding,
    pub status: RecoveryStatus,
}
#[derive(Serialize)]
pub struct Request<'a> {
    pub schema_version: u8,
    pub request_id: &'a str,
    pub action: Action,
    pub expected_original: &'a Original,
}
impl ApiClient {
    pub async fn recovery_authority(&self, token: &str) -> Result<Authority, ApiError> {
        let value: Envelope<Authority> = self
            .get("/api/v1/runtime-recovery/authority", Some(token))
            .await?;
        Ok(value.data)
    }
    pub async fn recovery_inspect(
        &self,
        token: &str,
        account: &str,
        original: &str,
    ) -> Result<Inspection, ApiError> {
        let path=format!("/api/v1/tool-accounts/{account}/runtime-migration/recovery-inspection?original_task_id={original}");
        let value: Envelope<Inspection> = self.get(&path, Some(token)).await?;
        Ok(value.data)
    }
    pub async fn recovery_apply(
        &self,
        token: &str,
        account: &str,
        request: &Request<'_>,
    ) -> Result<Receipt, ApiError> {
        let value: Envelope<Receipt> = self
            .post(
                &format!("/api/v1/tool-accounts/{account}/runtime-migration/recovery-requests"),
                Some(token),
                request,
            )
            .await?;
        Ok(value.data)
    }
    pub async fn recovery_request(
        &self,
        token: &str,
        account: &str,
        key: &str,
    ) -> Result<Receipt, ApiError> {
        let value: Envelope<Receipt> = self
            .get(
                &format!(
                    "/api/v1/tool-accounts/{account}/runtime-migration/recovery-requests/{key}"
                ),
                Some(token),
            )
            .await?;
        Ok(value.data)
    }
}
