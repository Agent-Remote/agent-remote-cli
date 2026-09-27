//! Content-free recovery failures, separate from device admission diagnostics.

use std::fmt;

use serde::Serialize;

use crate::api::runtime_recovery::{canonical_uuid, original_task_matches, RecoveryAction};
use crate::cli::{AccountCommand, Command};

/// Retain only validated identities, including when preparation fails before dispatch.
pub struct RecoveryContext {
    account_id: Option<String>,
    request_id: Option<String>,
    original_task_id: Option<String>,
    submission: bool,
    action: Option<RecoveryAction>,
}

impl RecoveryContext {
    pub fn from_command(command: &Command) -> Option<Self> {
        let (account, key, original, action) = match command {
            Command::Account(AccountCommand::RecoverRuntime(args)) => (
                &args.account_id,
                &args.request_id,
                Some(args.original_task.as_str()),
                super::selected_action(args),
            ),
            Command::Account(AccountCommand::RecoveryStatus(args)) => {
                (&args.account_id, &args.request_id, None, None)
            }
            _ => return None,
        };
        Some(Self {
            account_id: canonical_uuid(account).then(|| account.clone()),
            request_id: canonical_uuid(key).then(|| key.clone()),
            original_task_id: original
                .filter(|task| canonical_uuid(account) && original_task_matches(account, task))
                .map(str::to_owned),
            submission: original.is_some(),
            action,
        })
    }

    pub fn print_failure(&self, error: &anyhow::Error, json: bool) {
        let failure = error
            .downcast_ref::<RecoveryFailure>()
            .copied()
            .unwrap_or(RecoveryFailure::Preparation);
        let next_command =
            self.account_id
                .as_ref()
                .zip(self.request_id.as_ref())
                .map(|(account, key)| {
                    format!("agent-remote account recovery-status {account} --request-id {key}")
                });
        if json {
            let mut value = serde_json::json!({
                "schema_version": 1,
                "account_id": self.account_id,
                "request_id": self.request_id,
                "original_task_id": self.original_task_id,
                "recovery": null,
                "target_completion_confirmed": null,
                "error_code": failure,
                "acceptance": failure.acceptance(self.submission),
                "message": failure.to_string(),
                "next_command": next_command,
            });
            if let Some(action) = self.action {
                value["schema_version"] = action.binding_version().into();
                value["action"] = serde_json::json!(action);
                value["source_restoration_confirmed"] = serde_json::Value::Null;
            }
            println!("{value}");
        } else {
            eprintln!("{} {failure}", crate::terminal::failure("ERROR"));
            if let Some(command) = next_command {
                eprintln!("Query the original request: {command}");
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) enum RecoveryFailure {
    #[serde(rename = "RECOVERY_INVALID_IDENTITY")]
    InvalidIdentity,
    #[serde(rename = "RECOVERY_INVALID_ORIGINAL_TASK")]
    InvalidOriginalTask,
    #[serde(rename = "RECOVERY_PREPARATION_FAILED")]
    Preparation,
    #[serde(rename = "RECOVERY_REQUEST_REJECTED")]
    Rejected,
    #[serde(rename = "RECOVERY_ACCEPTANCE_UNKNOWN")]
    AcceptanceUnknown,
    #[serde(rename = "RECOVERY_STATUS_UNAVAILABLE")]
    StatusUnavailable,
}

impl RecoveryFailure {
    pub(super) fn submission(status: Option<u16>) -> Self {
        // Even a successful HTTP status can precede an unreadable committed response.
        if status.is_some_and(|status| (400..500).contains(&status)) {
            Self::Rejected
        } else {
            Self::AcceptanceUnknown
        }
    }

    fn acceptance(self, submission: bool) -> &'static str {
        if !submission {
            // Failure of this query cannot establish whether an earlier POST committed.
            return "unknown";
        }
        match self {
            Self::InvalidIdentity | Self::InvalidOriginalTask | Self::Preparation => {
                "not_submitted"
            }
            Self::Rejected => "rejected",
            Self::AcceptanceUnknown | Self::StatusUnavailable => "unknown",
        }
    }
}

impl fmt::Display for RecoveryFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidIdentity => "account ID and --request-id must be full, lowercase, nonzero UUIDs",
            Self::InvalidOriginalTask => "--original-task must be the full original migration task ID for this account",
            Self::Preparation => "Recovery preparation failed. Check the local configuration and administrator user login.",
            Self::Rejected => "Recovery request was rejected. Check administrator access and the exact original migration; retain the original request ID.",
            Self::AcceptanceUnknown => "Recovery acceptance is unknown. Query the original request before repeating the same submission.",
            Self::StatusUnavailable => "Recovery status is unavailable. Acceptance of the original request remains unknown; query the same request again.",
        })
    }
}

impl std::error::Error for RecoveryFailure {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_explicit_client_rejections_prove_this_submission_rejected() {
        for status in [None, Some(200), Some(204), Some(302), Some(500), Some(503)] {
            assert_eq!(
                RecoveryFailure::submission(status).acceptance(true),
                "unknown"
            );
        }
        for status in [400, 401, 403, 404, 409, 422, 429] {
            assert_eq!(
                RecoveryFailure::submission(Some(status)).acceptance(true),
                "rejected"
            );
        }
        assert_eq!(
            RecoveryFailure::Preparation.acceptance(true),
            "not_submitted"
        );
        assert_eq!(RecoveryFailure::Preparation.acceptance(false), "unknown");
        assert_eq!(
            RecoveryFailure::StatusUnavailable.acceptance(false),
            "unknown"
        );
    }
}
