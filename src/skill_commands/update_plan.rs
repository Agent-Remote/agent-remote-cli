//! Per-skill update plans and exact original-request recovery before source access.

use super::{context::ContextData, remote_result, requests, update_source};
use crate::api::skill_mutations::{SkillUpdateCommand, SkillUpdateRequest};
use crate::cli::skills::SkillUpdateArgs;
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skills::snapshot::PackageSnapshot;
use anyhow::{bail, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Serialize)]
struct Intent<'a> {
    command: &'static str,
    skill: &'a str,
    reference: &'a Option<String>,
    from_fingerprint: Option<String>,
    stage: bool,
}

pub(super) struct Plan {
    pub record: SkillCommandRecord,
    pub request: SkillUpdateRequest,
    pub package: Option<Arc<PackageSnapshot>>,
    pub recovering: bool,
    pub content_retained: bool,
}
impl Plan {
    pub(super) fn retained(record: SkillCommandRecord) -> Result<Self> {
        let requests::Request::Update(request) = requests::Request::retained(&record)? else {
            bail!("retained command is not an update");
        };
        Ok(Self {
            record,
            request,
            package: None,
            recovering: true,
            content_retained: true,
        })
    }
    pub(super) fn preview(&self) -> serde_json::Value {
        serde_json::json!({"request":self.request,"recovering_original_request":self.recovering,
            "reuse_server_content":self.content_retained,
            "package":self.package.as_ref().map(|package| serde_json::json!({"bytes":package.total_bytes(),"entries":package.manifest().entries.len()}))})
    }
}

pub(super) async fn prepare(
    context: &ContextData,
    identifier: &str,
    args: &SkillUpdateArgs,
) -> Result<Plan> {
    let from = args
        .from
        .as_ref()
        .map(|path| -> Result<PathBuf> {
            Ok(if path.is_absolute() {
                path.clone()
            } else {
                std::env::current_dir()?.join(path)
            })
        })
        .transpose()?;
    let intent = Intent {
        command: "update",
        skill: identifier,
        reference: &args.reference,
        from_fingerprint: from
            .as_ref()
            .map(|path| format!("{:x}", Sha256::digest(path.as_os_str().as_encoded_bytes()))),
        stage: args.stage,
    };
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&intent)?));
    let lookup = (context.server.clone(), context.user.clone(), digest.clone());
    let pending = skill_command_state(context.paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    if let Some(record) = pending {
        let plan = Plan::retained(record)?;
        if plan.request.stage != args.stage
            || plan.request.switch_tracking != args.reference.is_some()
        {
            bail!("retained update options differ");
        }
        return Ok(plan);
    }
    let library = remote_result::data(
        context
            .client
            .list_skills(&context.token, None, None, false)
            .await?,
    )?;
    let item = update_source::details(&context.client, &context.token, identifier).await?;
    let captured =
        update_source::observe(&item, args.reference.as_deref(), from.as_deref()).await?;
    let content_retained = item
        .revisions
        .iter()
        .any(|revision| revision.retained && revision.content_digest == captured.item.tree_digest);
    let request = SkillUpdateRequest {
        command: SkillUpdateCommand::Update,
        idempotency_key: requests::new_key()?,
        expected_generation: library.generation,
        skill: item.id,
        item: captured.item,
        stage: args.stage,
        switch_tracking: args.reference.is_some(),
    };
    let record = SkillCommandRecord {
        server_url: context.server.clone(),
        user_id: context.user.clone(),
        intent_digest: digest,
        idempotency_key: request.idempotency_key.clone(),
        request_json: serde_json::to_string(&request)?,
    };
    Ok(Plan {
        record,
        request,
        package: Some(captured.snapshot),
        recovering: false,
        content_retained,
    })
}
