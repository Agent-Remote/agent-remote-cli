//! Current user storage observations stay separate from immutable operation receipts.

use serde::{Deserialize, Serialize};

use super::skills::{invalid_skill_response, SkillDetails, SkillResult};
use super::{ApiClient, ApiError};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoragePolicy {
    pub package_file_bytes: u64,
    pub package_bytes: u64,
    pub package_entries: u64,
    pub checkpoint_bytes: u64,
    pub directory_bytes: u64,
    pub state_entries: u64,
    pub user_package_bytes: u64,
    pub user_staging_bytes: u64,
    pub user_state_bytes: u64,
    pub history_days: u64,
    pub archive_days: u64,
    pub staging_hours: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeletionUsage {
    pub pending_tasks: u64,
    pub retrying_tasks: u64,
    pub completed_tasks: u64,
    pub pending_file_bytes: u64,
    pub cumulative_deleted_bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StorageView {
    pub scope: String,
    pub observed_at: String,
    pub package_bytes: u64,
    pub state_bytes: u64,
    pub package_reserved_bytes: u64,
    pub state_reserved_bytes: u64,
    pub policy: StoragePolicy,
    pub deletion: DeletionUsage,
    pub node_storage: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HistoryDiagnostic {
    pub kind: String,
    pub id: String,
    pub observed_at: String,
    pub retained: bool,
    pub state: String,
    pub protected_by: Vec<String>,
    pub archived: bool,
    pub retention_days: u64,
    pub released_at: Option<String>,
    pub expires_at: Option<String>,
}

fn require(valid: bool) -> Result<(), ApiError> {
    if valid {
        Ok(())
    } else {
        Err(invalid_skill_response())
    }
}

fn text(value: &str, maximum: usize) -> Result<(), ApiError> {
    require(!value.is_empty() && value.len() <= maximum && !value.chars().any(char::is_control))
}

impl StorageView {
    pub fn validate(&self) -> Result<(), ApiError> {
        require(self.scope == "user" && self.node_storage == "not_observed")?;
        text(&self.observed_at, 64)?;
        let p = &self.policy;
        for limit in [
            p.package_file_bytes,
            p.package_bytes,
            p.package_entries,
            p.checkpoint_bytes,
            p.directory_bytes,
            p.state_entries,
            p.user_package_bytes,
            p.user_staging_bytes,
            p.user_state_bytes,
            p.history_days,
            p.archive_days,
            p.staging_hours,
        ] {
            require(limit > 0)?;
        }
        require(p.package_entries <= 100_000 && p.state_entries <= 100_000)?;
        let d = &self.deletion;
        require(
            d.retrying_tasks <= d.pending_tasks
                && (d.pending_tasks > 0 || d.pending_file_bytes == 0)
                && (d.completed_tasks > 0 || d.cumulative_deleted_bytes == 0),
        )
    }
}

impl HistoryDiagnostic {
    pub fn validate(
        &self,
        kind: &str,
        id: &str,
        retained: bool,
        storage: Option<&StorageView>,
    ) -> Result<(), ApiError> {
        require(self.kind == kind && self.id == id && self.retained == retained)?;
        let parsed = uuid::Uuid::parse_str(&self.id).map_err(|_| invalid_skill_response())?;
        require(parsed.to_string() == self.id && self.retention_days > 0)?;
        text(&self.observed_at, 64)?;
        for date in [&self.released_at, &self.expires_at].into_iter().flatten() {
            text(date, 64)?;
        }
        require(self.protected_by.len() <= 32)?;
        for reason in &self.protected_by {
            text(reason, 128)?;
        }
        require(self.protected_by.windows(2).all(|pair| pair[0] < pair[1]))?;
        match self.state.as_str() {
            "retired" => require(!retained && self.expires_at.is_none())?,
            "protected" => {
                require(retained && !self.protected_by.is_empty() && self.expires_at.is_none())?
            }
            "release_unknown" => require(
                retained
                    && self.protected_by.is_empty()
                    && self.released_at.is_none()
                    && self.expires_at.is_none(),
            )?,
            "waiting" | "due" => require(
                retained
                    && self.protected_by.is_empty()
                    && self.released_at.is_some()
                    && self.expires_at.is_some(),
            )?,
            _ => return Err(invalid_skill_response()),
        }
        if let Some(storage) = storage {
            require(
                self.retention_days
                    == if self.archived {
                        storage.policy.archive_days
                    } else {
                        storage.policy.history_days
                    },
            )?;
        }
        Ok(())
    }
}

pub(super) fn details(value: &SkillDetails) -> Result<(), ApiError> {
    match value {
        SkillDetails::Library(item) => {
            if let Some(storage) = &item.storage {
                storage.validate()?;
            }
            for revision in &item.revisions {
                if let Some(retention) = &revision.retention {
                    retention.validate(
                        "revision",
                        &revision.id,
                        revision.retained,
                        item.storage.as_ref(),
                    )?;
                }
            }
        }
        SkillDetails::Local(item) => {
            if let Some(storage) = &item.storage {
                storage.validate()?;
            }
            for revision in &item.revisions {
                if let Some(retention) = &revision.retention {
                    retention.validate(
                        "local_revision",
                        &revision.id,
                        revision.retained,
                        item.storage.as_ref(),
                    )?;
                }
            }
        }
    }
    Ok(())
}

impl ApiClient {
    pub async fn skill_storage(&self, token: &str) -> Result<SkillResult<StorageView>, ApiError> {
        let result: SkillResult<StorageView> = self
            .send_skill_request(
                self.client.get(self.endpoint("/api/v1/skills/storage")),
                token,
            )
            .await?;
        if let Some(view) = &result.data {
            require(
                result.status == "ready"
                    && !result.committed
                    && !result.retryable
                    && result.operation_id.is_none()
                    && result.errors.is_empty(),
            )?;
            view.validate()?;
        }
        Ok(result)
    }
}
