//! Read-only state orchestration and complete local checkpoint export.

mod conflict_render;
mod conflicts;
mod node_export;
pub(super) mod render;

use anyhow::{Context, Result};
use serde::Serialize;
use std::path::PathBuf;

use super::{print_json, remote_result};
use crate::api::skill_state::{
    Checkpoint, CheckpointDiff, CheckpointPage, MemberPage, PendingPage, StateScope, StateSelector,
};
use crate::api::skills::SkillResult;
use crate::api::ApiClient;
use crate::auth::{load_user_token, user_login_error};
use crate::cli::skills::{SkillStateCommand, StateExportArgs};
use crate::config::{AppPaths, Config};
use crate::skills::export::ExportBundle;

#[derive(Serialize)]
struct History {
    selector: StateSelector,
    checkpoints: CheckpointPage,
    pending: PendingPage,
}

#[derive(Serialize)]
struct Info {
    checkpoint: Checkpoint,
    members: Option<MemberPage>,
}

#[derive(Serialize)]
struct Exported {
    checkpoint: Checkpoint,
    tree_digest: String,
    format: &'static str,
    output: PathBuf,
    file_objects: usize,
}

#[derive(Serialize)]
struct BundleMetadata<'a> {
    format: &'static str,
    checkpoint: &'a Checkpoint,
    checkpoint_id: &'a str,
    source_tree_digest: &'a str,
    tree_digest: &'a str,
    subtree_prefix: &'a str,
    dependency_roots: &'a [String],
    locally_removed: bool,
}

enum Query {
    FrozenExport {
        bundle: ExportBundle,
        result: crate::api::skill_node_export::Exported,
    },
    History(History),
    Info(Info),
    Diff(CheckpointDiff),
    Conflicts(crate::api::skill_state::ConflictHistory),
    ConflictDiff(crate::api::skill_state::ConflictComparison),
    Export {
        bundle: ExportBundle,
        result: Exported,
    },
}

pub(super) async fn run(paths: AppPaths, command: SkillStateCommand, json: bool) -> Result<()> {
    let command = match command {
        SkillStateCommand::Prune(args) => return super::state_prune::run(paths, args, json).await,
        SkillStateCommand::Migrate(args) => {
            return super::state_migrations::run(paths, args, json).await
        }
        SkillStateCommand::Resolve(args) => {
            return super::state_resolutions::run(paths, args, json).await
        }
        SkillStateCommand::Reset(args) => {
            return super::state_mutations::run(
                paths,
                args.selection,
                crate::api::skill_state::StateAction::Reset,
                None,
                args.options,
                json,
            )
            .await
        }
        SkillStateCommand::Restore(args) => {
            return super::state_mutations::run(
                paths,
                args.selection,
                crate::api::skill_state::StateAction::Restore,
                Some(args.checkpoint),
                args.options,
                json,
            )
            .await
        }
        query => query,
    };
    match run_query(paths, command, json).await {
        Err(error) if error.downcast_ref::<super::SkillExit>().is_none() => {
            if super::interruption::result_started() {
                return Err(super::SkillExit(1).into());
            }
            super::output::finish(json, move || {
                super::print_failure(&error, json);
                Err(super::SkillExit(1).into())
            })
            .await
        }
        result => result,
    }
}

async fn run_query(paths: AppPaths, command: SkillStateCommand, json: bool) -> Result<()> {
    let query = tokio::select! {
        result = prepare(paths, command) => result?,
        signal = super::interruption::cancelled() => {
            signal?;
            return super::interruption::report("State query or export interrupted; no remote skill state was changed.", None, json).await;
        }
    };
    if super::interruption::is_cancelled() {
        return super::interruption::report("State query or export interrupted before local publication; no remote skill state was changed.", None, json).await;
    }
    match query {
        Query::FrozenExport { bundle, mut result } => {
            result.output = tokio::task::spawn_blocking(move || bundle.publish()).await?
                .map_err(|_| remote_result::failure("SKILL_EXPORT_FAILED", "Could not publish the verified frozen bundle. The destination must remain absent or empty.", Some(result.binding.snapshot_id.clone())))?;
            emit(result, "ready", json, |value| {
                crate::terminal::success(format!(
                    "Exported frozen snapshot {} to {} ({} file objects; unclean={}).",
                    value.binding.snapshot_id,
                    super::safe(&value.output.to_string_lossy()),
                    value.file_objects,
                    value.unclean
                ));
            })
            .await
        }
        Query::History(history) => emit(history, "ready", json, render::history).await,
        Query::Info(info) => {
            let status = if info.checkpoint.retained {
                "ready"
            } else {
                "state_expired"
            };
            emit(info, status, json, render::info).await
        }
        Query::Diff(diff) => emit(diff, "ready", json, render::diff).await,
        Query::Conflicts(value) => emit(value, "ready", json, conflict_render::history).await,
        Query::ConflictDiff(value) => emit(value, "ready", json, conflict_render::comparison).await,
        Query::Export { bundle, mut result } => {
            // Once publication starts, observe its outcome even if Ctrl-C arrives during rename.
            result.output = tokio::task::spawn_blocking(move || bundle.publish()).await?
                .map_err(|_| remote_result::failure("SKILL_EXPORT_FAILED", "Could not publish the verified bundle. The destination must remain absent or empty.", Some(result.checkpoint.id.clone())))?;
            emit(result, "ready", json, render::exported).await
        }
    }
}

async fn emit<T: Serialize + Send + 'static>(
    data: T,
    status: &str,
    json: bool,
    render: impl FnOnce(&T) + Send + 'static,
) -> Result<()> {
    let result = SkillResult {
        schema_version: 1,
        operation_id: None,
        status: status.to_owned(),
        committed: false,
        retryable: false,
        data: Some(data),
        errors: Vec::new(),
    };
    super::output::finish(json, move || {
        if json {
            print_json(&result)?;
        } else if let Some(data) = &result.data {
            render(data);
        }
        Ok(())
    })
    .await
}

async fn prepare(paths: AppPaths, command: SkillStateCommand) -> Result<Query> {
    let server = Config::load(&paths)?
        .server_url
        .context("server profile missing")?;
    let token = load_user_token(&paths, &server)
        .await?
        .ok_or_else(user_login_error)?;
    let client = ApiClient::new(server)?;
    match command {
        SkillStateCommand::Conflicts(args) => conflicts::list(&client, &token, args)
            .await
            .map(Query::Conflicts),
        SkillStateCommand::List(args) => {
            let selector = args.selection.selector();
            let checkpoints = remote_result::data(
                client
                    .skill_state_history(&token, &selector, args.limit, args.cursor.as_deref())
                    .await?,
            )?;
            let pending = remote_result::data(
                client
                    .skill_state_pending(
                        &token,
                        &selector,
                        args.limit,
                        args.pending_cursor.as_deref(),
                    )
                    .await?,
            )?;
            Ok(Query::History(History {
                selector,
                checkpoints,
                pending,
            }))
        }
        SkillStateCommand::Info(args) => {
            let checkpoint =
                remote_result::data(client.skill_checkpoint(&token, &args.checkpoint).await?)?;
            let members = if args.members {
                if checkpoint.scope != StateScope::AccountDirectory {
                    return Err(scope_failure(&checkpoint.id));
                }
                Some(remote_result::data(
                    client
                        .skill_checkpoint_members(
                            &token,
                            &checkpoint.id,
                            args.limit,
                            args.cursor.as_deref(),
                        )
                        .await?,
                )?)
            } else {
                None
            };
            Ok(Query::Info(Info {
                checkpoint,
                members,
            }))
        }
        SkillStateCommand::Diff(args) => {
            if let Some(id) = args.conflict {
                return conflicts::diff(&client, &token, &id, args.limit, args.cursor.as_deref())
                    .await
                    .map(Query::ConflictDiff);
            }
            let result = if let Some(id) = args.checkpoint {
                client
                    .skill_checkpoint_diff(&token, &id, args.limit, args.cursor.as_deref())
                    .await?
            } else {
                let selector = StateSelector {
                    account_id: args.account_id.context("account missing")?,
                    scope: if args.scope.is_some() {
                        StateScope::AccountDirectory
                    } else {
                        StateScope::Item
                    },
                    skill: args.skill,
                };
                client
                    .skill_current_diff(&token, &selector, args.limit)
                    .await?
            };
            Ok(Query::Diff(remote_result::data(result)?))
        }
        SkillStateCommand::Export(args) if args.snapshot.is_some() => {
            node_export::prepare(paths, &client, &token, args).await
        }
        SkillStateCommand::Export(args) => export(&client, &token, args).await,
        SkillStateCommand::Prune(_)
        | SkillStateCommand::Migrate(_)
        | SkillStateCommand::Resolve(_)
        | SkillStateCommand::Reset(_)
        | SkillStateCommand::Restore(_) => {
            anyhow::bail!("state mutation reached query dispatch")
        }
    }
}

async fn export(client: &ApiClient, token: &str, args: StateExportArgs) -> Result<Query> {
    let checkpoint = remote_result::data(
        client
            .skill_checkpoint(
                token,
                args.checkpoint.as_deref().context("checkpoint missing")?,
            )
            .await?,
    )?;
    let scope = if args.scope.is_some() {
        StateScope::AccountDirectory
    } else {
        StateScope::Item
    };
    if checkpoint.scope != scope
        || args
            .account_id
            .as_ref()
            .is_some_and(|id| id != &checkpoint.account_id)
    {
        return Err(scope_failure(&checkpoint.id));
    }
    if let Some(skill) = &args.skill {
        let identity = if uuid::Uuid::parse_str(skill).is_ok() {
            skill.clone()
        } else {
            remote_result::data(
                client
                    .skill_info(token, skill, None, Some(&checkpoint.account_id))
                    .await?,
            )?
            .id()
            .to_owned()
        };
        if checkpoint.skill_id.as_ref() != Some(&identity) {
            return Err(scope_failure(&checkpoint.id));
        }
    }
    if !checkpoint.retained {
        return Err(remote_result::failure(
            "STATE_EXPIRED",
            "Checkpoint content is no longer retained.",
            Some(checkpoint.id),
        ));
    }
    let tree = remote_result::data(client.skill_checkpoint_tree(token, &checkpoint).await?)?;
    if !tree.dependency_roots.is_empty() && scope == StateScope::Item {
        return Err(remote_result::failure("STATE_SCOPE_MISMATCH", "This checkpoint has cross-skill links. Export its backing account-directory checkpoint with --scope account-directory and --account-id.", Some(checkpoint.id)));
    }
    let staged_checkpoint = checkpoint.clone();
    let staged_tree = tree.clone();
    let mut bundle = tokio::task::spawn_blocking(move || ExportBundle::prepare(&args.output, &staged_tree.manifest, &BundleMetadata {
        format: "agent-remote-skill-checkpoint-v1", checkpoint: &staged_checkpoint,
        checkpoint_id: &staged_tree.checkpoint_id, source_tree_digest: &staged_tree.source_tree_digest,
        tree_digest: &staged_tree.tree_digest, subtree_prefix: &staged_tree.subtree_prefix,
        dependency_roots: &staged_tree.dependency_roots, locally_removed: staged_tree.locally_removed,
    })).await?
        .map_err(|_| remote_result::failure("SKILL_EXPORT_FAILED", "Cannot stage this bundle. Choose an absent or empty destination with an existing writable parent; exports are limited to 10 GiB.", Some(checkpoint.id.clone())))?;
    for index in 0..bundle.objects().len() {
        let (returned, file) = tokio::task::spawn_blocking(move || {
            let file = bundle.create_object(index);
            (bundle, file)
        })
        .await?;
        bundle = returned;
        let file = file.map_err(|_| {
            remote_result::failure(
                "SKILL_EXPORT_FAILED",
                "Could not create a private export object.",
                Some(checkpoint.id.clone()),
            )
        })?;
        client
            .download_checkpoint_file(token, &tree, &bundle.objects()[index], file)
            .await?;
    }
    let result = Exported {
        checkpoint,
        tree_digest: tree.tree_digest,
        format: "agent-remote-skill-checkpoint-v1",
        output: PathBuf::new(),
        file_objects: bundle.objects().len(),
    };
    Ok(Query::Export { bundle, result })
}

fn scope_failure(id: &str) -> anyhow::Error {
    remote_result::failure(
        "STATE_SCOPE_MISMATCH",
        "Checkpoint account, source or scope does not match the requested selection.",
        Some(id.to_owned()),
    )
}
