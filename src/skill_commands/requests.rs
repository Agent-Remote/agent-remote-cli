//! Canonical requests shared by exact-request acceptance and restart recovery.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

use crate::api::skill_mutations::{SkillAddRequest, SkillMutationRequest, SkillUpdateRequest};
use crate::api::skills::{SkillMutation, SkillResult};
use crate::api::{ApiClient, ApiError};
use crate::local_state::SkillCommandRecord;

#[derive(Deserialize, Serialize)]
#[serde(untagged)]
pub(super) enum Request {
    Rule(SkillMutationRequest),
    Add(SkillAddRequest),
    Update(SkillUpdateRequest),
    Retry(super::retry_plan::Saved),
}

impl Request {
    pub(super) fn retained(record: &SkillCommandRecord) -> Result<Self> {
        let request: Self = serde_json::from_str(&record.request_json)?;
        if request.key() != record.idempotency_key
            || request.generation() < 0
            || request.generation() == i64::MAX && !matches!(request, Self::Retry(_))
            || serde_json::to_string(&request)? != record.request_json
        {
            bail!("retained skill request identity differs");
        }
        match &request {
            Self::Retry(retry) => retry.validate()?,
            Self::Rule(rule) if uuid::Uuid::parse_str(&rule.skill).is_err() => {
                bail!("invalid retained skill identity")
            }
            Self::Add(add) if add.items.is_empty() || add.items.len() > 100 => {
                bail!("invalid retained installation selection")
            }
            Self::Update(update) if uuid::Uuid::parse_str(&update.skill).is_err() => {
                bail!("invalid retained update identity")
            }
            _ => {}
        }
        Ok(request)
    }
    pub(super) fn key(&self) -> &str {
        match self {
            Self::Rule(r) => &r.idempotency_key,
            Self::Add(r) => &r.idempotency_key,
            Self::Update(r) => &r.idempotency_key,
            Self::Retry(r) => &r.request.idempotency_key,
        }
    }
    pub(super) fn generation(&self) -> i64 {
        match self {
            Self::Rule(r) => r.expected_generation,
            Self::Add(r) => r.expected_generation,
            Self::Update(r) => r.expected_generation,
            Self::Retry(r) => r.request.expected_generation,
        }
    }
    pub(super) fn object_id(&self) -> Option<String> {
        match self {
            Self::Rule(r) => Some(r.skill.clone()),
            Self::Add(_) => None,
            Self::Update(r) => Some(r.skill.clone()),
            Self::Retry(r) => Some(r.operation_id.clone()),
        }
    }
    pub(super) fn same_intent_kind(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Retry(a), Self::Retry(b)) => a.operation_id == b.operation_id,
            (Self::Rule(a), Self::Rule(b)) => a.change == b.change,
            (Self::Add(a), Self::Add(b)) => {
                a.scope == b.scope && a.scope_explicit == b.scope_explicit
            }
            (Self::Update(a), Self::Update(b)) => {
                a.skill == b.skill && a.stage == b.stage && a.switch_tracking == b.switch_tracking
            }
            _ => false,
        }
    }
    pub(super) async fn send(
        &self,
        client: &ApiClient,
        token: &str,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        match self {
            Self::Rule(r) => client.change_skill(token, r).await,
            Self::Add(r) => client.install_skills(token, r).await,
            Self::Update(r) => client.update_skill(token, r).await,
            Self::Retry(r) => client.retry_skill(token, &r.operation_id, &r.request).await,
        }
    }
    pub(super) fn validate_receipt(&self, result: &SkillResult<SkillMutation>) -> Result<()> {
        if let Self::Retry(retry) = self {
            return retry.validate_receipt(result);
        }
        if let Some(data) = &result.data {
            if self.generation().checked_add(i64::from(data.changed)) != Some(data.generation) {
                bail!("skill receipt generation differs from retained plan");
            }
            match self {
                Self::Rule(rule) if data.skill_ids != [rule.skill.clone()] => {
                    bail!("skill receipt identity differs from retained plan")
                }
                Self::Update(update)
                    if data.skill_ids != [update.skill.clone()]
                        || data.revision_ids.len() != 1
                        || data
                            .revision_ids
                            .iter()
                            .any(|id| uuid::Uuid::parse_str(id).is_err()) =>
                {
                    bail!("update receipt differs from retained skill/revision")
                }
                Self::Add(add) => {
                    let identities: std::collections::BTreeSet<_> = data.skill_ids.iter().collect();
                    if identities.len() != add.items.len()
                        || data.skill_ids.len() != add.items.len()
                        || data.revision_ids.len() != add.items.len()
                        || data
                            .skill_ids
                            .iter()
                            .chain(&data.revision_ids)
                            .any(|id| uuid::Uuid::parse_str(id).is_err())
                    {
                        bail!("installation receipt differs from retained selection");
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    pub(super) async fn lookup(
        &self,
        client: &ApiClient,
        token: &str,
    ) -> Result<SkillResult<SkillMutation>, ApiError> {
        match self {
            Self::Retry(retry) => {
                client
                    .skill_retry_by_key(token, &retry.operation_id, self.key())
                    .await
            }
            _ => client.skill_operation_by_key(token, self.key()).await,
        }
    }
}

pub(super) fn new_key() -> Result<String> {
    use rand_core::{OsRng, RngCore};
    use sha2::{Digest, Sha256};
    let mut random = [0u8; 16];
    OsRng
        .try_fill_bytes(&mut random)
        .map_err(|_| anyhow::anyhow!("random command identity unavailable"))?;
    Ok(format!("skill-{:x}", Sha256::digest(random)))
}
