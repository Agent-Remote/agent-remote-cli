//! Reviewed Skill rule changes exposed to desktop-control.
//!
//! The desktop boundary accepts only the public identity of a Skill, its
//! generation and an explicit enable/disable action.  Skill content, source
//! locators, tracking metadata and credentials stay inside the CLI/API layer.

use std::path::{Component, Path};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::{
    account_defaults::Context,
    api::{
        skill_mutations::{SkillChange, SkillMutationRequest, SkillScope},
        ApiClient,
    },
    auth,
    config::{AppPaths, Config},
};

use super::{Failure, Request};

const METHOD: &str = "skills.change";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangeRequest {
    confirmed: bool,
    expected_context: Context,
    expected_generation: i64,
    skill: String,
    action: String,
    scope: Scope,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Scope {
    #[serde(default)]
    tools: Vec<String>,
    #[serde(default)]
    account_id: Option<String>,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    if request.method != METHOD {
        return Err(Failure::new("unsupported_method"));
    }
    let input: ChangeRequest = serde_json::from_value(request.params.clone())
        .map_err(|_| Failure::new("invalid_params"))?;
    if !input.confirmed
        || input.expected_generation < 0
        || input.expected_generation == i64::MAX
        || !canonical_uuid(&input.skill)
        || !matches!(input.action.as_str(), "enable" | "disable")
        || input.scope.tools.len() > 32
        || input.scope.tools.iter().any(|tool| !super::valid_id(tool))
        || input.scope.tools.windows(2).any(|pair| pair[0] >= pair[1])
        || input
            .scope
            .account_id
            .as_deref()
            .is_some_and(|id| !canonical_uuid(id))
    {
        return Err(Failure::new("invalid_params"));
    }
    if input
        .expected_context
        .home
        .components()
        .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
        || !input.expected_context.home.is_absolute()
        || input
            .expected_context
            .server_url
            .as_deref()
            .is_none_or(|url| {
                url.is_empty() || url.len() > 8192 || url.chars().any(char::is_control)
            })
        || input
            .expected_context
            .active_device_id
            .as_deref()
            .is_some_and(|id| !super::valid_id(id))
    {
        return Err(Failure::new("invalid_params"));
    }

    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if paths.home() != Path::new(&input.expected_context.home) {
        return Err(Failure::new("configuration_changed"));
    }
    let config =
        Config::load_strict(&paths).map_err(|_| Failure::new("configuration_unavailable"))?;
    if config.server_url != input.expected_context.server_url
        || config.active_device_id != input.expected_context.active_device_id
    {
        return Err(Failure::new("configuration_changed"));
    }
    let server = config
        .server_url
        .clone()
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let token = auth::load_user_token(&paths, &server)
        .await
        .map_err(|_| Failure::new("credential_unavailable"))?
        .ok_or_else(|| Failure::new("authentication_required"))?;
    let client =
        ApiClient::new(server.clone()).map_err(|_| Failure::new("configuration_unavailable"))?;
    let change = match input.action.as_str() {
        "enable" => SkillChange::Enable {
            scope: SkillScope {
                tools: input.scope.tools,
                account_id: input.scope.account_id,
            },
        },
        "disable" => SkillChange::Disable {
            scope: SkillScope {
                tools: input.scope.tools,
                account_id: input.scope.account_id,
            },
            all_scopes: false,
        },
        _ => unreachable!("action validated above"),
    };
    let action = input.action.clone();
    let expected_generation = input.expected_generation;
    let skill = input.skill.clone();
    let payload = SkillMutationRequest {
        idempotency_key: request.request_id.clone(),
        expected_generation,
        skill: skill.clone(),
        change,
    };
    let result = client
        .change_skill(&token, &payload)
        .await
        .map_err(skill_api_failure)?;
    let data = result
        .data
        .ok_or_else(|| Failure::new("skill_outcome_unknown"))?;
    if data.skill_ids != [skill.clone()]
        || data.generation != expected_generation + i64::from(data.changed)
    {
        return Err(Failure::new("skill_outcome_unknown"));
    }
    let operation_id = request.request_id.clone();
    Ok(json!({
        "operation_id": operation_id,
        "context": input.expected_context,
        "accepted": result.committed,
        "action": action,
        "skill": skill,
        "generation": data.generation,
        "changed": data.changed,
        "status": result.status,
    }))
}

fn canonical_uuid(value: &str) -> bool {
    uuid::Uuid::parse_str(value).is_ok_and(|id| id.to_string() == value)
}

fn skill_api_failure(error: crate::api::ApiError) -> Failure {
    match error.status_code() {
        Some(409) => Failure::new("skill_generation_conflict"),
        Some(400..=499) => Failure::new("skill_rejected"),
        _ => Failure::api(error),
    }
}
