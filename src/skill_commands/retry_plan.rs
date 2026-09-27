//! Retain exact failed attempt identities and validate later observations of their successors.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

use crate::api::skill_retry::{SkillRetryRequest, SkillRetryTarget};
use crate::api::skills::{SkillMutation, SkillResult};
use crate::local_state::SkillCommandRecord;

pub(super) fn saved(record: &SkillCommandRecord) -> Result<Option<Saved>> {
    #[derive(Deserialize)]
    struct Tag {
        command: Option<String>,
    }
    let tag: Tag = serde_json::from_str(&record.request_json)?;
    if tag.command.as_deref() != Some("deployment_retry") {
        return Ok(None);
    }
    let super::requests::Request::Retry(plan) = super::requests::Request::retained(record)? else {
        bail!("retained command is not a deployment retry");
    };
    Ok(Some(plan))
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Command {
    DeploymentRetry,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Saved {
    command: Command,
    pub operation_id: String,
    pub request: SkillRetryRequest,
    attempts: Vec<Attempt>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Attempt {
    number: u64,
    plan_digest: String,
}

impl Saved {
    pub(super) fn from_operation(result: &SkillResult<SkillMutation>) -> Result<Self> {
        let data = result.data.as_ref().context("operation response missing")?;
        if !result.committed
            || result.status != "failed"
            || !result.retryable
            || data.replacement_id.is_some()
            || data.targets.iter().any(|target| {
                matches!(
                    target.readiness.as_str(),
                    "pending" | "running" | "needs_resolution"
                )
            })
        {
            bail!("original operation is not eligible for retry");
        }
        let mut targets = Vec::new();
        let mut attempts = Vec::new();
        let mut accounts = BTreeSet::new();
        for target in &data.targets {
            if !accounts.insert(&target.account_id) {
                bail!("operation contains duplicate targets");
            }
            if target.retryable != Some(true) {
                continue;
            }
            if target.node_id.is_none() || target.readiness != "failed" {
                bail!("retry target has no original failed deployment");
            }
            targets.push(SkillRetryTarget {
                account_id: target.account_id.clone(),
                attempt_id: target
                    .attempt_id
                    .clone()
                    .context("attempt identity missing")?,
            });
            attempts.push(Attempt {
                number: target.attempt_number.context("attempt number missing")?,
                plan_digest: target
                    .plan_digest
                    .clone()
                    .context("original plan missing")?,
            });
        }
        let saved = Self {
            command: Command::DeploymentRetry,
            operation_id: result
                .operation_id
                .clone()
                .context("operation identity missing")?,
            request: SkillRetryRequest {
                idempotency_key: super::requests::new_key()?,
                expected_generation: data.generation,
                targets,
            },
            attempts,
        };
        saved.validate()?;
        Ok(saved)
    }

    pub(super) fn validate(&self) -> Result<()> {
        let canonical =
            |id: &str| uuid::Uuid::parse_str(id).is_ok_and(|parsed| parsed.to_string() == id);
        let mut accounts = BTreeSet::new();
        if !canonical(&self.operation_id)
            || self.request.expected_generation < 0
            || self.request.idempotency_key.is_empty()
            || self.request.idempotency_key.len() > 128
            || self.request.targets.is_empty()
            || self.request.targets.len() > 10_000
            || self.request.targets.len() != self.attempts.len()
        {
            bail!("invalid retained retry identity");
        }
        for (target, attempt) in self.request.targets.iter().zip(&self.attempts) {
            if !canonical(&target.account_id)
                || !canonical(&target.attempt_id)
                || !accounts.insert(&target.account_id)
                || attempt.number == 0
                || attempt.number == u64::MAX
                || attempt.plan_digest.len() != 64
                || !attempt
                    .plan_digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                bail!("invalid retained retry selection");
            }
        }
        Ok(())
    }

    pub(super) fn validate_receipt(&self, result: &SkillResult<SkillMutation>) -> Result<()> {
        let Some(data) = &result.data else {
            return Ok(());
        };
        if !result.committed
            || result.operation_id.as_ref() != Some(&self.operation_id)
            || data.generation != self.request.expected_generation
        {
            bail!("retry receipt differs from original operation");
        }
        let mut accounts = BTreeSet::new();
        if data
            .targets
            .iter()
            .any(|target| !accounts.insert(&target.account_id))
        {
            bail!("retry receipt contains duplicate targets");
        }
        for (selected, original) in self.request.targets.iter().zip(&self.attempts) {
            let target = data
                .targets
                .iter()
                .find(|target| target.account_id == selected.account_id)
                .context("retry receipt omits selected target")?;
            if target.plan_digest.as_ref() != Some(&original.plan_digest)
                || target
                    .attempt_number
                    .is_none_or(|number| number <= original.number)
                || target
                    .attempt_id
                    .as_ref()
                    .is_none_or(|id| *id == selected.attempt_id)
            {
                bail!("retry receipt does not observe an original-plan successor");
            }
        }
        Ok(())
    }
}
