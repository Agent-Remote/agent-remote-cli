//! Confirmed configuration changes with crash-safe exact-request recovery.

use std::io::IsTerminal;

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::api::skill_mutations::{SkillChange, SkillMutationRequest, SkillScope};
use crate::api::skills::{SkillDetails, SkillError, SkillResult};
use crate::api::ApiClient;
use crate::auth::{load_user_token, user_login_error};
use crate::cli::skills::{SkillCommand, SkillInheritField, SkillMutationOptions, SkillRuleArgs};
use crate::config::{AppPaths, Config};
use crate::local_state::{skill_command_state, SkillCommandRecord};

use super::{
    configuration::{self, Submission},
    print_json, render_summary, SkillExit,
};

#[derive(Serialize)]
struct Intent {
    skill: String,
    change: SkillChange,
}

pub(super) async fn run(paths: AppPaths, command: SkillCommand, json: bool) -> Result<()> {
    configuration::run(paths.clone(), Box::pin(prepare(paths, command, json)), json).await
}

async fn prepare(paths: AppPaths, command: SkillCommand, json: bool) -> Result<Option<Submission>> {
    let (intent, options) = match intent(command) {
        Ok(value) => value,
        Err(_) => {
            return local_error(
                "INVALID_ARGUMENT",
                "This command requires an explicit tool/account scope and unique tools.",
                2,
                json,
            )
        }
    };
    if !options.dry_run && !options.yes && !std::io::stdin().is_terminal() {
        return local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm this noninteractive change, or --dry-run to inspect it.",
            2,
            json,
        );
    }
    let server = Config::load(&paths)?
        .server_url
        .context("server profile missing")?;
    let token = load_user_token(&paths, &server)
        .await?
        .ok_or_else(user_login_error)?;
    let client = ApiClient::new(server)?;
    let server = client.skill_server_identity()?;
    let user = client.skill_user_id(&token).await?;
    let digest = format!("{:x}", Sha256::digest(serde_json::to_vec(&intent)?));
    let lookup = (server.clone(), user.clone(), digest.clone());
    let pending = skill_command_state(paths.clone(), move |state| {
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    let recovering = pending.is_some();
    let proposed = match pending {
        Some(record) => record,
        None => {
            let listing = client.list_skills(&token, None, None, false).await?;
            if super::query_exit(&listing) != 0 {
                if json {
                    print_json(&listing)?;
                } else {
                    render_summary(&listing);
                }
                return Err(SkillExit(1).into());
            }
            let library = listing.data.context("library response unavailable")?;
            let scope = intent.change.scope();
            let account = scope.and_then(|s| s.account_id.as_deref());
            let tools = scope.map_or(&[][..], |s| s.tools.as_slice());
            let view = client
                .skill_info(
                    &token,
                    &intent.skill,
                    tools.first().map(String::as_str),
                    account,
                )
                .await?;
            let query_code = super::query_exit(&view);
            if query_code != 0 {
                if json {
                    print_json(&view)?;
                } else {
                    render_summary(&view);
                }
                return Err(SkillExit(query_code).into());
            }
            let skill = view.data.context("skill response unavailable")?;
            let matches_input = match uuid::Uuid::parse_str(&intent.skill) {
                Ok(id) => uuid::Uuid::parse_str(skill.id()).ok() == Some(id),
                Err(_) => skill.name() == intent.skill,
            };
            if !matches_input {
                return local_error(
                    "INVALID_SKILL_RESPONSE",
                    "Skill details do not match the requested identity.",
                    1,
                    json,
                );
            }
            if skill.removed() {
                return local_error("SKILL_REMOVED", "This skill has been removed.", 1, json);
            }
            if let SkillDetails::Local(item) = &skill {
                if account != Some(item.account_id.as_str()) {
                    return local_error(
                        "LOCAL_SKILL_SCOPE_REQUIRED",
                        "Local skills require their exact account.",
                        2,
                        json,
                    );
                }
                let allowed = match &intent.change {
                    SkillChange::Enable { .. } => true,
                    SkillChange::Disable { all_scopes, .. } => !all_scopes,
                    SkillChange::Inherit { field, .. } => field == "enabled" || field == "all",
                    _ => false,
                };
                if !allowed {
                    return local_error("LOCAL_SKILL_COMMAND_UNSUPPORTED", "Local skills support enable, disable and enabled inheritance; use state restore for history.", 2, json);
                }
            }
            let skill_id = uuid::Uuid::parse_str(skill.id())
                .context("invalid skill identity")?
                .to_string();
            for tool in tools.iter().skip(1) {
                let view = client
                    .skill_info(&token, &skill_id, Some(tool), None)
                    .await?;
                if super::query_exit(&view) != 0 {
                    if json {
                        print_json(&view)?;
                    } else {
                        render_summary(&view);
                    }
                    return Err(SkillExit(1).into());
                }
            }

            let key = super::requests::new_key()?;
            let request = SkillMutationRequest {
                idempotency_key: key.clone(),
                expected_generation: library.generation,
                skill: skill_id,
                change: intent.change.clone(),
            };
            SkillCommandRecord {
                server_url: server,
                user_id: user,
                intent_digest: digest,
                idempotency_key: key,
                request_json: serde_json::to_string(&request)?,
            }
        }
    };
    let request = retained_request(&proposed, &intent.change)?;
    if options.dry_run {
        let result = SkillResult {
            schema_version: 1,
            operation_id: None,
            status: "planned".to_owned(),
            committed: false,
            retryable: false,
            data: Some(
                serde_json::json!({"request":request,"recovering_original_request":recovering}),
            ),
            errors: Vec::<SkillError>::new(),
        };
        super::output::display(move || {
            if json {
                print_json(&result)?;
            } else {
                eprintln!("{}", serde_json::to_string_pretty(&result.data)?);
            }
            Ok(())
        })
        .await?;
        return Ok(None);
    }
    if !options.yes && !super::confirmation::review(&request).await? {
        return local_error(
            "CHANGE_CANCELLED",
            "No configuration change was submitted.",
            1,
            json,
        );
    }
    Ok(Some(Submission {
        client,
        token,
        record: proposed,
        recovering,
        options,
    }))
}

fn retained_request(
    record: &SkillCommandRecord,
    change: &SkillChange,
) -> Result<SkillMutationRequest> {
    let request: SkillMutationRequest = serde_json::from_str(&record.request_json)?;
    if request.idempotency_key != record.idempotency_key
        || request.change != *change
        || request.expected_generation < 0
        || uuid::Uuid::parse_str(&request.skill).is_err()
        || serde_json::to_string(&request)? != record.request_json
    {
        bail!("retained skill request identity differs");
    }
    Ok(request)
}

pub(super) fn local_error<T>(code: &str, message: &str, exit: i32, json: bool) -> Result<T> {
    let result: SkillResult<serde_json::Value> = SkillResult {
        schema_version: 1,
        operation_id: None,
        status: "failed".to_owned(),
        committed: false,
        retryable: false,
        data: None,
        errors: vec![SkillError {
            code: code.to_owned(),
            message: message.to_owned(),
            object_id: None,
            details: Default::default(),
        }],
    };
    if json {
        print_json(&result)?;
    } else {
        render_summary(&result);
    }
    Err(SkillExit(exit).into())
}

fn scope(args: &SkillRuleArgs, required: bool) -> Result<SkillScope> {
    let mut tools = args.tool.clone();
    tools.sort();
    if tools.len() > 32
        || tools.windows(2).any(|pair| pair[0] == pair[1])
        || required && tools.is_empty() && args.account_id.is_none()
    {
        bail!("explicit unique scope required");
    }
    Ok(SkillScope {
        tools,
        account_id: args.account_id.clone(),
    })
}

fn intent(command: SkillCommand) -> Result<(Intent, SkillMutationOptions)> {
    let (skill, change, options) = match command {
        SkillCommand::Enable(args) => (
            args.skill.clone(),
            SkillChange::Enable {
                scope: scope(&args, false)?,
            },
            args.options,
        ),
        SkillCommand::Disable(args) => (
            args.rule.skill.clone(),
            SkillChange::Disable {
                scope: scope(&args.rule, false)?,
                all_scopes: args.all_scopes,
            },
            args.rule.options,
        ),
        SkillCommand::Pin(args) => (
            args.rule.skill.clone(),
            SkillChange::Pin {
                scope: scope(&args.rule, true)?,
                revision: args.revision,
            },
            args.rule.options,
        ),
        SkillCommand::Unpin(args) => (
            args.skill.clone(),
            SkillChange::Unpin {
                scope: scope(&args, true)?,
            },
            args.options,
        ),
        SkillCommand::Inherit(args) => (
            args.rule.skill.clone(),
            SkillChange::Inherit {
                scope: scope(&args.rule, true)?,
                field: match args.field {
                    SkillInheritField::Enabled => "enabled",
                    SkillInheritField::Revision => "revision",
                    SkillInheritField::All => "all",
                }
                .to_owned(),
            },
            args.rule.options,
        ),
        SkillCommand::Remove(args) => (args.skill, SkillChange::Remove, args.options),
        SkillCommand::Rollback(args) => (
            args.target.skill,
            SkillChange::Rollback {
                revision: args.revision,
            },
            args.target.options,
        ),
        _ => bail!("not a configuration mutation"),
    };
    Ok((Intent { skill, change }, options))
}
