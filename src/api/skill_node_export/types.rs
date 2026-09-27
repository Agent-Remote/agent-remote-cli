//! Secret-free original identities and non-debuggable ephemeral connection authority.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::api::{skills::invalid_skill_response, ApiError};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub snapshot_id: String,
    pub session_id: String,
    pub user_id: String,
    pub account_id: String,
    pub node_id: String,
    pub task_id: String,
    pub library_generation: i64,
    pub directory_epoch: i64,
    pub initial_tree_digest: String,
}

impl Binding {
    pub(super) fn validate(&self) -> Result<(), ApiError> {
        for value in [
            &self.snapshot_id,
            &self.session_id,
            &self.user_id,
            &self.account_id,
            &self.node_id,
            &self.task_id,
        ] {
            id(value)?;
        }
        digest(&self.initial_tree_digest)?;
        require(self.library_generation >= 0 && self.directory_epoch >= 1)
    }
}

#[derive(Serialize)]
pub struct Request {
    pub device_id: String,
    pub ssh_key_id: String,
}

/// Never derive Debug or Serialize: this response includes a live stdin-only bearer grant.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Authorization {
    pub binding: Binding,
    pub device_id: String,
    pub ssh_key_id: String,
    pub(super) grant: String,
    pub expires_at: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_user: String,
    pub authorization_task_id: String,
    pub authorization_task_status: String,
}

impl Authorization {
    pub(super) fn validate(&self, snapshot: &str, request: &Request) -> Result<(), ApiError> {
        self.binding.validate()?;
        require(
            self.binding.snapshot_id == snapshot
                && self.device_id == request.device_id
                && self.ssh_key_id == request.ssh_key_id,
        )?;
        require(
            !self.ssh_host.is_empty()
                && self.ssh_host.len() <= 255
                && self.ssh_host.as_bytes()[0].is_ascii_alphanumeric()
                && self
                    .ssh_host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".:-".contains(&b))
                && self.ssh_port > 0,
        )?;
        require(
            !self.ssh_user.is_empty()
                && self.ssh_user.len() <= 64
                && (self.ssh_user.as_bytes()[0].is_ascii_lowercase()
                    || self.ssh_user.starts_with('_'))
                && self
                    .ssh_user
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b)),
        )?;
        require(
            self.expires_at.len() >= 20
                && self.expires_at.len() <= 40
                && self
                    .expires_at
                    .bytes()
                    .all(|b| b.is_ascii_digit() || b"T:.-+Z".contains(&b))
                && !self.authorization_task_id.is_empty()
                && self.authorization_task_id.len() <= 256
                && self
                    .authorization_task_id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-:.".contains(&b))
                && matches!(
                    self.authorization_task_status.as_str(),
                    "pending" | "leased" | "running" | "succeeded"
                ),
        )?;
        let (payload, signature) = self
            .grant
            .split_once('.')
            .ok_or_else(invalid_skill_response)?;
        require(
            self.grant.len() <= 4096
                && !payload.is_empty()
                && payload
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_=-".contains(&b)),
        )?;
        digest(signature)
    }
}

#[derive(Serialize)]
pub struct Exported {
    pub format: &'static str,
    pub binding: Binding,
    pub tree_digest: String,
    pub unclean: bool,
    pub output: PathBuf,
    pub file_objects: usize,
}

pub(super) fn require(value: bool) -> Result<(), ApiError> {
    if value {
        Ok(())
    } else {
        Err(invalid_skill_response())
    }
}

pub(super) fn id(value: &str) -> Result<(), ApiError> {
    require(uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value))
}

pub(super) fn digest(value: &str) -> Result<(), ApiError> {
    require(
        value.len() == 64
            && value
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
    )
}
