use crate::api::runtime_recovery::{
    canonical_uuid, original_task_matches, RecoveryAction, RecoveryBinding, RuntimeRecovery,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UserContext {
    pub home: PathBuf,
    pub server_url: String,
    pub actor_user_id: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    VerifyTarget,
    VerifySource,
    RepairSource,
}
impl Action {
    pub fn legacy(self) -> Option<RecoveryAction> {
        match self {
            Self::VerifyTarget => None,
            Self::VerifySource => Some(RecoveryAction::VerifySource),
            Self::RepairSource => Some(RecoveryAction::RepairSource),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Original {
    pub task_id: String,
    pub task_record_id: String,
    pub user_id: String,
    pub tool_account_id: String,
    pub node_id: String,
    pub tool_type: String,
    pub source_runtime_backend: String,
    pub target_runtime_backend: String,
}
impl Original {
    pub fn valid(&self, account: &str) -> bool {
        canonical_uuid(account)
            && self.tool_account_id == account
            && original_task_matches(account, &self.task_id)
            && [&self.task_record_id, &self.user_id, &self.node_id]
                .into_iter()
                .all(|id| canonical_uuid(id))
            && self.tool_type == "claude"
            && self.source_runtime_backend != self.target_runtime_backend
            && [&self.source_runtime_backend, &self.target_runtime_backend]
                .into_iter()
                .all(|v| matches!(v.as_str(), "native" | "docker_sandbox"))
    }
    pub fn matches(&self, b: &RecoveryBinding) -> bool {
        self.task_id == b.original_task_id
            && self.task_record_id == b.original_task_record_id
            && self.user_id == b.user_id
            && self.node_id == b.node_id
            && self.tool_account_id == b.tool_account_id
            && self.tool_type == b.tool_type
            && self.source_runtime_backend == b.source_runtime_backend
            && self.target_runtime_backend == b.target_runtime_backend
    }
}

#[derive(Serialize)]
pub struct Authority {
    pub context: UserContext,
    pub admin: bool,
}
#[derive(Serialize)]
pub struct Plan {
    pub context: UserContext,
    pub account_id: String,
    pub original: Original,
    pub action: Action,
    pub original_status: String,
    pub account_status: String,
    pub digest: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Apply {
    pub confirmed: bool,
    pub expected_context: UserContext,
    pub account_id: String,
    pub original: Original,
    pub action: Action,
    pub expected_digest: String,
    pub request_id: String,
}
#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub expected_context: UserContext,
    pub account_id: String,
    pub request_id: String,
    #[serde(deserialize_with = "crate::account_defaults::required_nullable")]
    pub expected_digest: Option<String>,
    #[serde(deserialize_with = "required_binding")]
    pub expected_binding: Option<RecoveryBinding>,
}
#[derive(Serialize)]
pub struct Receipt {
    pub context: UserContext,
    pub account_id: String,
    pub request_id: String,
    pub digest: Option<String>,
    pub recovery: RuntimeRecovery,
    pub target_completion_confirmed: bool,
    pub source_restoration_confirmed: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub context: UserContext,
    pub account_id: String,
    pub request_id: String,
    pub digest: String,
    pub original: Original,
    pub action: Action,
    pub binding: Option<RecoveryBinding>,
    pub phase: String,
    pub rejection_code: Option<String>,
}
#[derive(Serialize)]
pub struct Pending {
    pub home: PathBuf,
    pub items: Vec<Record>,
}
#[derive(Serialize)]
pub struct Forgotten {
    pub context: UserContext,
    pub account_id: String,
    pub request_id: String,
    pub digest: String,
    pub forgotten: bool,
}

#[derive(Debug)]
pub struct Error {
    pub code: &'static str,
    pub http_status: Option<u16>,
    pub submitted: bool,
}
impl Error {
    pub fn new(code: &'static str) -> Self {
        Self {
            code,
            http_status: None,
            submitted: false,
        }
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.code)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

pub fn digest(
    context: &UserContext,
    account: &str,
    original: &Original,
    action: Action,
) -> Result<String> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&(1u8, context, account, original, action))
        .map_err(|_| Error::new("runtime_recovery_response_invalid"))?;
    Ok(format!("sha256:{:x}", Sha256::digest(bytes)))
}

fn required_binding<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<Option<RecoveryBinding>, D::Error> {
    Option::<RecoveryBinding>::deserialize(d)
}
