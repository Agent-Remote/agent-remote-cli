//! Preserve a rejected Server envelope without replacing it with a transport failure.

use crate::api::skills::{SkillError, SkillResult};
use anyhow::{Context, Result};
use serde::Serialize;
use std::fmt;

#[derive(Debug)]
pub(super) struct Rejected(pub SkillResult<serde_json::Value>);
impl fmt::Display for Rejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Server rejected the skill request")
    }
}
impl std::error::Error for Rejected {}

pub(super) fn data<T: Serialize>(mut result: SkillResult<T>) -> Result<T> {
    if result.data.is_none() || !result.errors.is_empty() {
        return Err(Rejected(serde_json::from_value(serde_json::to_value(result)?)?).into());
    }
    result
        .data
        .take()
        .context("skill response data unavailable")
}

pub(super) fn failure(code: &str, message: &str, object_id: Option<String>) -> anyhow::Error {
    Rejected(SkillResult {
        schema_version: 1,
        operation_id: None,
        status: "failed".to_owned(),
        committed: false,
        retryable: false,
        data: None,
        errors: vec![SkillError {
            code: code.to_owned(),
            message: message.to_owned(),
            object_id,
            details: Default::default(),
        }],
    })
    .into()
}
