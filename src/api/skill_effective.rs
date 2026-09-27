//! Read-only account diagnostics and original-session selections.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use super::skills::{
    invalid_skill_response, SkillDetails, SkillLibrary, SkillResolvedRule, SkillResult,
};
use super::{ApiClient, ApiError};

#[derive(Debug, Deserialize, Serialize)]
pub struct SystemSkillView {
    pub name: String,
    pub origin: String,
    pub read_only: bool,
    pub selected: Option<bool>,
    pub selection_reason: String,
    pub release: BTreeMap<String, ReleaseValue>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum ReleaseValue {
    Text(String),
    Number(i64),
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AccountSkillView {
    pub account_id: String,
    pub revision_selection_reason: String,
    pub directory_mode: String,
    pub directory_epoch: Option<i64>,
    pub directory_checkpoint_id: Option<String>,
    pub state_id: Option<String>,
    pub state_epoch: Option<i64>,
    pub checkpoint_id: Option<String>,
    pub state_expired: bool,
    pub preparation: String,
    pub publication_conflicts: u64,
    pub migration_conflicts: u64,
    pub latest_publication_conflict_id: Option<String>,
    pub latest_migration_conflict_id: Option<String>,
    pub last_recorded_sync_at: Option<String>,
    pub unknown_sync_times: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionSkillItem {
    pub name: String,
    pub skill_id: String,
    pub origin: String,
    pub revision_id: String,
    pub installation_epoch: i64,
    pub state_id: String,
    pub state_epoch: i64,
    pub checkpoint_id: String,
    pub checkpoint_retained: bool,
    pub resolution: SkillResolvedRule,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct SessionSkillView {
    pub session_id: String,
    pub account_id: String,
    pub basis: String,
    pub snapshot_id: Option<String>,
    pub snapshot_status: Option<String>,
    pub content_retained: Option<bool>,
    pub runtime_backend: String,
    pub library_generation: Option<i64>,
    pub directory_epoch: Option<i64>,
    pub starting_checkpoint_id: Option<String>,
    pub tree_digest: Option<String>,
    pub system_items: Vec<SystemSkillView>,
    pub items: Vec<SessionSkillItem>,
    pub next_cursor: Option<String>,
    pub project_discovery: String,
    pub model_loaded: bool,
}

impl ApiClient {
    pub async fn session_skills(
        &self,
        token: &str,
        session: &str,
        limit: u16,
        cursor: Option<&str>,
    ) -> Result<SkillResult<SessionSkillView>, ApiError> {
        uuid(session)?;
        if !(1..=200).contains(&limit) {
            return Err(invalid_skill_response());
        }
        let mut query = vec![("limit", limit.to_string())];
        if let Some(cursor) = cursor {
            query.push(("cursor", cursor.to_owned()));
        }
        let request = self
            .client
            .get(self.endpoint(&format!("/api/v1/skills/sessions/{session}")))
            .query(&query);
        let result: SkillResult<SessionSkillView> = self.send_skill_request(request, token).await?;
        if let Some(data) = &result.data {
            data.validate(session, limit, cursor)?;
        }
        Ok(result)
    }
}

fn uuid(value: &str) -> Result<(), ApiError> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| invalid_skill_response())
}

pub(super) fn validate_systems(items: &[SystemSkillView]) -> Result<(), ApiError> {
    let mut names = std::collections::BTreeSet::new();
    for item in items {
        if !matches!(item.name.as_str(), "ego-browser" | "agent-remote-device")
            || item.origin != "system"
            || !item.read_only
            || !names.insert(&item.name)
            || item.release.len() > 8
            || item.selection_reason.len() > 256
        {
            return Err(invalid_skill_response());
        }
        for (key, value) in &item.release {
            if !matches!(
                key.as_str(),
                "version"
                    | "commit"
                    | "tree_sha256"
                    | "node_release_version"
                    | "protocol_version"
                    | "legacy_reference"
            ) || matches!(value, ReleaseValue::Text(text) if text.len() > 256 || text.chars().any(char::is_control))
            {
                return Err(invalid_skill_response());
            }
        }
    }
    Ok(())
}

impl AccountSkillView {
    fn validate(&self, account: Option<&str>) -> Result<(), ApiError> {
        uuid(&self.account_id)?;
        for id in [
            &self.directory_checkpoint_id,
            &self.state_id,
            &self.checkpoint_id,
            &self.latest_publication_conflict_id,
            &self.latest_migration_conflict_id,
        ]
        .into_iter()
        .flatten()
        {
            uuid(id)?;
        }
        if !matches!(
            self.revision_selection_reason.as_str(),
            "account_pin" | "tool_pin" | "user_default" | "account_local_revision"
        ) || account != Some(self.account_id.as_str())
            || !matches!(
                self.directory_mode.as_str(),
                "legacy" | "migrating" | "managed_v1"
            )
            || self.directory_epoch.is_some_and(|v| v < 1)
            || self.state_epoch.is_some_and(|v| v < 1)
            || self.state_id.is_some() != self.state_epoch.is_some()
            || (self.checkpoint_id.is_some() && self.state_id.is_none())
            || (self.publication_conflicts == 0) != self.latest_publication_conflict_id.is_none()
            || (self.migration_conflicts == 0) != self.latest_migration_conflict_id.is_none()
            || (self.state_expired != (self.preparation == "state_expired"))
            || (self.preparation == "initialized" && self.checkpoint_id.is_none())
            || !matches!(
                self.preparation.as_str(),
                "initialized" | "uninitialized" | "migration_required" | "state_expired"
            )
        {
            return Err(invalid_skill_response());
        }
        if let Some(time) = &self.last_recorded_sync_at {
            if time.len() > 64 || time.is_empty() || time.chars().any(char::is_control) {
                return Err(invalid_skill_response());
            }
        }
        Ok(())
    }
}

pub(super) fn validate_details(item: &SkillDetails, account: Option<&str>) -> Result<(), ApiError> {
    let state = match item {
        SkillDetails::Library(item) => &item.account_state,
        SkillDetails::Local(item) => &item.account_state,
    };
    if let Some(state) = state {
        state.validate(account)?;
    }
    Ok(())
}

pub(super) fn validate_library(data: &SkillLibrary, account: Option<&str>) -> Result<(), ApiError> {
    validate_systems(&data.system_items)?;
    for state in data
        .items
        .iter()
        .filter_map(|i| i.account_state.as_ref())
        .chain(
            data.local_items
                .iter()
                .filter_map(|i| i.account_state.as_ref()),
        )
    {
        state.validate(account)?;
    }
    Ok(())
}

impl SessionSkillView {
    fn validate(&self, session: &str, limit: u16, cursor: Option<&str>) -> Result<(), ApiError> {
        uuid(&self.account_id)?;
        for id in [&self.snapshot_id, &self.starting_checkpoint_id]
            .into_iter()
            .flatten()
        {
            uuid(id)?;
        }
        if self.session_id != session
            || self.model_loaded
            || self.project_discovery != "not_inspected"
            || !matches!(self.runtime_backend.as_str(), "native" | "docker_sandbox")
            || self.items.len() > usize::from(limit)
        {
            return Err(invalid_skill_response());
        }
        match self.basis.as_str() {
            "legacy_unrecorded"
                if self.snapshot_id.is_none()
                    && self.snapshot_status.is_none()
                    && self.content_retained.is_none()
                    && self.library_generation.is_none()
                    && self.directory_epoch.is_none()
                    && self.starting_checkpoint_id.is_none()
                    && self.tree_digest.is_none()
                    && self.items.is_empty()
                    && self.system_items.is_empty()
                    && self.next_cursor.is_none()
                    && cursor.is_none() => {}
            "session_snapshot"
                if self.snapshot_id.is_some()
                    && self.snapshot_status.is_some()
                    && self.content_retained.is_some()
                    && self.library_generation.is_some_and(|v| v >= 0)
                    && self.directory_epoch.is_some_and(|v| v > 0)
                    && self.starting_checkpoint_id.is_some()
                    && self.tree_digest.as_ref().is_some_and(|v| {
                        v.len() == 64 && v.bytes().all(|c| c.is_ascii_hexdigit())
                    }) => {}
            _ => return Err(invalid_skill_response()),
        }
        validate_systems(&self.system_items)?;
        if self
            .system_items
            .iter()
            .any(|i| i.selected != Some(true) || i.selection_reason != "session_snapshot")
        {
            return Err(invalid_skill_response());
        }
        let mut previous = cursor;
        for item in &self.items {
            for id in [
                &item.skill_id,
                &item.revision_id,
                &item.state_id,
                &item.checkpoint_id,
            ] {
                uuid(id)?;
            }
            if item.name.is_empty()
                || item.name.len() > 64
                || previous.is_some_and(|p| p >= item.name.as_str())
                || item.installation_epoch < 1
                || item.state_epoch < 1
                || !matches!(item.origin.as_str(), "user_library" | "account_local")
                || item.resolution.revision_id != item.revision_id
                || !item.resolution.included
                || !item.resolution.enabled
                || !item.resolution.eligible
            {
                return Err(invalid_skill_response());
            }
            previous = Some(&item.name);
        }
        if self.next_cursor.is_some()
            && (self.items.len() != usize::from(limit)
                || self.next_cursor.as_deref() != self.items.last().map(|i| i.name.as_str()))
        {
            return Err(invalid_skill_response());
        }
        Ok(())
    }
}
