//! Internal broker records, not a desktop request or an authorization boundary.

use serde::{Deserialize, Serialize};

use super::configuration::ConfigError;
use super::inspection::ConfigBinding;
use super::target::TargetObservation;
use super::tunnel::Action;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ExecutionRequest {
    pub version: u32,
    pub request_id: String,
    /// Derived from the authenticated OS peer, never accepted as caller proof.
    pub caller_sha256: String,
    /// Digest of the complete, independently validated execution plan.
    pub plan_sha256: String,
    /// Broker-observed namespace or host scope; independent of CLI home/user.
    pub target_scope_sha256: String,
    pub action: Action,
    pub logical_name: String,
    pub config: ConfigBinding,
}

impl ExecutionRequest {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        if self.version != 1
            || ![
                &self.request_id,
                &self.caller_sha256,
                &self.plan_sha256,
                &self.target_scope_sha256,
                &self.config.file_identity,
                &self.config.content_sha256,
            ]
            .into_iter()
            .all(|value| digest(value))
            || !super::target::valid_name(&self.logical_name)
            || !super::validation::public_key(&self.config.public_key)
        {
            return Err(ConfigError("wireguard_execution_invalid"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OperationPhase {
    Prepared,
    Submitted,
    Observed,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ExecutionFailure {
    Cancelled,
    ToolFailed,
    ObservationFailed,
    TargetChanged,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct OperationRecord {
    pub version: u32,
    pub request: ExecutionRequest,
    pub snapshot_identity: String,
    pub phase: OperationPhase,
    pub observation: Option<TargetObservation>,
    pub failure: Option<ExecutionFailure>,
}

impl OperationRecord {
    pub(super) fn validate(&self) -> Result<(), ConfigError> {
        self.request.validate()?;
        if self.version != 1 || !digest(&self.snapshot_identity) {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        let coherent = match self.phase {
            OperationPhase::Prepared | OperationPhase::Submitted => {
                self.observation.is_none() && self.failure.is_none()
            }
            OperationPhase::Failed => self.observation.is_none() && self.failure.is_some(),
            OperationPhase::Observed => {
                self.failure.is_none()
                    && self.observation.as_ref().is_some_and(|observation| {
                        observation.logical_name == self.request.logical_name
                            && super::execution_observation::valid(observation)
                    })
            }
        };
        if !coherent {
            return Err(ConfigError("wireguard_execution_record_invalid"));
        }
        Ok(())
    }
}

pub(super) fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}
