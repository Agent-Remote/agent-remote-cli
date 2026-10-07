//! Administrator-only, original-task-bound passive backend migration recovery.

use super::{ApiClient, ApiError, Envelope};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryBinding {
    #[serde(
        default,
        deserialize_with = "deserialize_action",
        skip_serializing_if = "Option::is_none"
    )]
    pub action: Option<RecoveryAction>,
    pub version: u8,
    pub task_id: String,
    pub task_record_id: String,
    pub original_task_id: String,
    pub original_task_record_id: String,
    pub node_id: String,
    pub user_id: String,
    pub tool_account_id: String,
    pub tool_type: String,
    pub source_runtime_backend: String,
    pub target_runtime_backend: String,
}

/// An explicit source verification or independent interrupted permission repair.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryAction {
    VerifySource,
    RepairSource,
}

impl RecoveryAction {
    pub fn binding_version(self) -> u8 {
        match self {
            Self::VerifySource => 2,
            Self::RepairSource => 3,
        }
    }
}

fn deserialize_action<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<RecoveryAction>, D::Error> {
    // Absence selects legacy recovery; an explicit null must never downgrade authority.
    RecoveryAction::deserialize(deserializer).map(Some)
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    Pending,
    Leased,
    Running,
    Succeeded,
    Failed,
    Cancelled,
    Expired,
}

impl RecoveryStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Leased => "leased",
            Self::Running => "running",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeRecovery {
    pub binding: RecoveryBinding,
    pub status: RecoveryStatus,
}

#[derive(Serialize)]
struct RecoveryRequest<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    action: Option<RecoveryAction>,
    original_task_id: &'a str,
    request_id: &'a str,
}

pub fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| !id.is_nil() && id.to_string() == value)
}

pub fn original_task_matches(account: &str, original: &str) -> bool {
    original
        .strip_prefix(&format!("migrate_tool_account_runtime:{account}:"))
        .is_some_and(canonical_uuid)
}

impl RuntimeRecovery {
    fn validate(
        &self,
        account: &str,
        key: &str,
        original: Option<&str>,
        action: Option<RecoveryAction>,
    ) -> Result<(), ApiError> {
        let binding = &self.binding;
        if !canonical_uuid(account)
            || !canonical_uuid(key)
            || !matches!(
                (binding.version, binding.action),
                (1, None)
                    | (2, Some(RecoveryAction::VerifySource))
                    | (3, Some(RecoveryAction::RepairSource))
            )
            || (original.is_some() && binding.action != action)
            || binding.tool_type != "claude"
            || binding.tool_account_id != account
            || binding.task_id != format!("recover_tool_account_runtime:{account}:{key}")
            || !original_task_matches(account, &binding.original_task_id)
            || original.is_some_and(|id| id != binding.original_task_id)
            || binding.task_record_id == binding.original_task_record_id
            || [
                &binding.task_record_id,
                &binding.original_task_record_id,
                &binding.node_id,
                &binding.user_id,
            ]
            .into_iter()
            .any(|id| !canonical_uuid(id))
            || binding.source_runtime_backend == binding.target_runtime_backend
            || [
                &binding.source_runtime_backend,
                &binding.target_runtime_backend,
            ]
            .into_iter()
            .any(|backend| !matches!(backend.as_str(), "native" | "docker_sandbox"))
        {
            return Err(invalid_recovery());
        }
        Ok(())
    }
}

impl ApiClient {
    /// Submit an explicit caller-retained key; the Server preserves original task results.
    pub async fn recover_runtime(
        &self,
        token: &str,
        account: &str,
        original: &str,
        key: &str,
        action: Option<RecoveryAction>,
    ) -> Result<RuntimeRecovery, ApiError> {
        if !canonical_uuid(account)
            || !canonical_uuid(key)
            || !original_task_matches(account, original)
        {
            return Err(invalid_recovery());
        }
        let response: Envelope<RuntimeRecovery> = self
            .post(
                &format!("/api/v1/tool-accounts/{account}/runtime-migration/recover"),
                Some(token),
                &RecoveryRequest {
                    action,
                    original_task_id: original,
                    request_id: key,
                },
            )
            .await?;
        response
            .data
            .validate(account, key, Some(original), action)?;
        Ok(response.data)
    }

    /// Read one original recovery request without authorizing another inspection.
    pub async fn runtime_recovery_status(
        &self,
        token: &str,
        account: &str,
        key: &str,
    ) -> Result<RuntimeRecovery, ApiError> {
        if !canonical_uuid(account) || !canonical_uuid(key) {
            return Err(invalid_recovery());
        }
        let response: Envelope<RuntimeRecovery> = self
            .get(
                &format!("/api/v1/tool-accounts/{account}/runtime-migration/recover/{key}"),
                Some(token),
            )
            .await?;
        response.data.validate(account, key, None, None)?;
        Ok(response.data)
    }
}

fn invalid_recovery() -> ApiError {
    ApiError {
        status: None,
        code: Some("RUNTIME_RECOVERY_PROTOCOL_INVALID".into()),
        message: "Backend migration recovery identity is invalid.".into(),
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/api/runtime_recovery.rs"]
mod tests;
