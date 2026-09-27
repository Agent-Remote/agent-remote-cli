//! Resolve once, preview completely, and preserve original plans across retries.

use super::{
    acceptance,
    journal::{self, Kind, Saved},
};
use crate::api::skill_state::{
    StateAction, StateCommandRequest, StateCommandView, StateScope, StateSelector,
};
use crate::api::skills::SkillResult;
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skill_commands::{context::ContextData, remote_result, requests};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Intent<'a> {
    command: &'static str,
    action: StateAction,
    selector: &'a StateSelector,
    checkpoint_id: &'a Option<String>,
}

pub(super) struct Plan {
    pub record: SkillCommandRecord,
    pub saved: Saved,
    pub preview: Option<SkillResult<StateCommandView>>,
    pub recovered_result: Option<SkillResult<StateCommandView>>,
    pub recovering: bool,
}

pub(super) async fn prepare(
    context: &ContextData,
    selector: StateSelector,
    action: StateAction,
    checkpoint: Option<String>,
    dry_run: bool,
) -> Result<Plan> {
    let digest = format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(&Intent {
            command: "state",
            action,
            selector: &selector,
            checkpoint_id: &checkpoint
        })?)
    );
    let lookup = (context.server.clone(), context.user.clone(), digest.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    if let Some(record) = pending {
        let saved = journal::saved(&record)?.context("retained request is not a state command")?;
        matches_intent(&saved, &selector, action, &checkpoint)?;
        let mut plan = Plan {
            record,
            saved,
            preview: None,
            recovered_result: None,
            recovering: true,
        };
        if dry_run {
            let original = context
                .client
                .skill_state_operation_by_key(&context.token, &plan.saved.request.idempotency_key)
                .await?;
            if original.data.is_some() {
                plan.saved.validate_receipt(&original)?;
                plan.recovered_result = Some(original);
            } else if acceptance::not_found(&original) {
                let mut request = plan.saved.request.clone();
                request.dry_run = true;
                let result = context
                    .client
                    .change_skill_state(&context.token, &request)
                    .await?;
                let view = remote_result::data(result.clone())?;
                if view.result_tree_digest != plan.saved.preview_tree_digest {
                    bail!("original state preview changed");
                }
                plan.preview = Some(result);
            } else {
                remote_result::data(original)?;
            }
        }
        return Ok(plan);
    }
    let current = remote_result::data(
        context
            .client
            .skill_current_state(&context.token, &selector)
            .await?,
    )?;
    let mut stable = selector;
    if stable.scope == StateScope::Item {
        stable.skill = Some(
            current
                .precondition
                .targets
                .first()
                .context("missing selected state target")?
                .skill_id
                .clone(),
        );
    }
    let mut request = StateCommandRequest {
        idempotency_key: requests::new_key()?,
        action,
        selector: stable,
        expected: current.precondition,
        checkpoint_id: checkpoint,
        dry_run: true,
    };
    let preview = context
        .client
        .change_skill_state(&context.token, &request)
        .await?;
    let view = remote_result::data(preview.clone())?;
    request.dry_run = false;
    let saved = Saved {
        command: Kind::State,
        request,
        preview_tree_digest: view.result_tree_digest,
    };
    let request_json = serde_json::to_string(&saved)?;
    if request_json.len() > 4 * 1024 * 1024 {
        return Err(remote_result::failure(
            "LIMIT_EXCEEDED",
            "The exact state request exceeds the 4 MiB recovery journal limit.",
            Some(saved.request.selector.account_id.clone()),
        ));
    }
    Ok(Plan {
        record: SkillCommandRecord {
            server_url: context.server.clone(),
            user_id: context.user.clone(),
            intent_digest: digest,
            idempotency_key: saved.request.idempotency_key.clone(),
            request_json,
        },
        saved,
        preview: Some(preview),
        recovered_result: None,
        recovering: false,
    })
}

fn matches_intent(
    saved: &Saved,
    selector: &StateSelector,
    action: StateAction,
    checkpoint: &Option<String>,
) -> Result<()> {
    let request = &saved.request;
    if request.action != action
        || request.selector.account_id != selector.account_id
        || request.selector.scope != selector.scope
        || request.checkpoint_id != *checkpoint
    {
        bail!("retained state intent differs");
    }
    if let Some(skill) = &selector.skill {
        let target = request
            .expected
            .targets
            .first()
            .context("retained target missing")?;
        if request.selector.skill.as_deref() != Some(&target.skill_id)
            || (skill != &target.name && skill != &target.skill_id)
        {
            bail!("retained state source differs");
        }
    }
    Ok(())
}
