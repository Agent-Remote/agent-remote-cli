//! Atomic Git/local-source installation, with content completion before configuration acceptance.

use anyhow::{bail, Context, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::IsTerminal;
use std::path::PathBuf;

use super::configuration::{self, Submission};
use super::mutations::local_error;
use super::{install_source, print_json, remote_result, requests, safe, upload};
use crate::api::skill_mutations::{SkillAddCommand, SkillAddRequest, SkillScope};
use crate::api::skills::{SkillError, SkillResult};
use crate::api::ApiClient;
use crate::auth::{load_user_token, user_login_error};
use crate::cli::skills::SkillAddArgs;
use crate::config::{AppPaths, Config};
use crate::local_state::{skill_command_state, SkillCommandRecord};
use crate::skills::discovery::Selection;
use crate::skills::git_source::{GitReference, GitSource};
use crate::terminal::Table;

#[derive(Serialize)]
struct Intent {
    command: &'static str,
    source_input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    reference: Option<String>,
    subpath: Option<String>,
    all: bool,
    names: Vec<String>,
    scope: SkillScope,
}

pub(super) async fn run(paths: AppPaths, args: SkillAddArgs, json: bool) -> Result<()> {
    configuration::run(paths.clone(), Box::pin(prepare(paths, args, json)), json).await
}

async fn prepare(
    paths: AppPaths,
    mut args: SkillAddArgs,
    json: bool,
) -> Result<Option<Submission>> {
    args.tool.sort();
    args.skill.sort();
    if args.tool.len() > 32
        || args.tool.windows(2).any(|p| p[0] == p[1])
        || args.skill.windows(2).any(|p| p[0] == p[1])
    {
        return local_error(
            "INVALID_ARGUMENT",
            "Select unique tool and skill names.",
            2,
            json,
        );
    }
    if !args.list && !args.options.dry_run && !args.options.yes && !std::io::stdin().is_terminal() {
        return local_error(
            "CONFIRMATION_REQUIRED",
            "Use --yes to confirm installation, or --dry-run to inspect it.",
            2,
            json,
        );
    }
    let git = match GitSource::parse(&args.source) {
        Ok(value) => value,
        Err(error) => return source_error(error, json),
    };
    let reference = match GitReference::parse(args.reference.as_deref()) {
        Ok(value) => value,
        Err(error) => return source_error(error, json),
    };
    if git.is_none() && args.reference.is_some() {
        return local_error("INVALID_REF", "--ref requires a Git source.", 2, json);
    }
    let input = PathBuf::from(&args.source);
    let root = if input.is_absolute() {
        input
    } else {
        std::env::current_dir()?.join(input)
    };
    if args.list {
        let catalog = match install_source::acquire(root, git, reference, args.path).await {
            Ok(value) => value,
            Err(error) => return source_error(error, json),
        };
        let result = SkillResult {
            schema_version: 1,
            operation_id: None,
            status: "ready".to_owned(),
            committed: false,
            retryable: false,
            errors: Vec::<SkillError>::new(),
            data: Some(
                serde_json::json!({"candidates":catalog.candidates(),"issues":catalog.issues()}),
            ),
        };
        let candidates = catalog.candidates().to_vec();
        let issues = catalog.issues().to_vec();
        super::output::display(move || {
            if json {
                print_json(&result)?;
            } else {
                let mut table = Table::new(["Skill", "Relative path", "Description"]);
                for candidate in &candidates {
                    table.row([
                        safe(&candidate.metadata.name),
                        safe(&candidate.path),
                        safe(&candidate.metadata.description),
                    ]);
                }
                table.render();
                for issue in &issues {
                    eprintln!("{}: {}", safe(&issue.path), safe(&issue.message));
                }
            }
            Ok(())
        })
        .await?;
        return Ok(None);
    }
    let scope = SkillScope {
        tools: args.tool,
        account_id: args.account_id,
    };
    let local_input = format!("{:x}", Sha256::digest(root.as_os_str().as_encoded_bytes()));
    let mut intent = Intent {
        command: "add",
        source_input: git
            .as_ref()
            .map(|source| format!("git:{}", source.url))
            .unwrap_or_else(|| local_input.clone()),
        reference: args.reference.clone(),
        subpath: args.path.clone(),
        all: args.all,
        names: args.skill.clone(),
        scope: scope.clone(),
    };
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
    // Earlier local-only versions accepted owner/repo paths. Recover any pending exact local
    // request before applying the new shorthand classification, even if that directory vanished.
    intent.source_input = local_input;
    let legacy_digest = if git.is_some() && args.reference.is_none() && !args.source.contains("://")
    {
        Some(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&intent)?)
        ))
    } else {
        None
    };
    let lookup = (server.clone(), user.clone(), digest.clone());
    let pending = skill_command_state(paths.clone(), move |state| {
        if let Some(legacy) = legacy_digest {
            if let Some(record) = state.pending_skill_command(&lookup.0, &lookup.1, &legacy)? {
                return Ok(Some(record));
            }
        }
        state.pending_skill_command(&lookup.0, &lookup.1, &lookup.2)
    })
    .await?;
    let recovering = pending.is_some();
    let mut captured = Vec::new();
    let proposed = match pending {
        Some(record) => record,
        None => {
            let catalog = match install_source::acquire(root, git, reference, args.path).await {
                Ok(value) => value,
                Err(error) => return source_error(error, json),
            };
            let selection = if args.all {
                Selection::All
            } else if !args.skill.is_empty() {
                Selection::Names(args.skill)
            } else {
                Selection::Automatic
            };
            captured = match catalog
                .capture(selection, std::io::stdin().is_terminal())
                .await
            {
                Ok(value) => value,
                Err(error) => return source_error(error, json),
            };
            // Each read validates scope while its generation anchors the final atomic request.
            let mut generation = None;
            if scope.tools.is_empty() {
                generation = Some(
                    remote_result::data(
                        client
                            .list_skills(
                                &token,
                                None,
                                scope.account_id.as_deref(),
                                scope.account_id.is_some(),
                            )
                            .await?,
                    )?
                    .generation,
                );
            } else {
                for tool in &scope.tools {
                    let library = remote_result::data(
                        client.list_skills(&token, Some(tool), None, false).await?,
                    )?;
                    generation.get_or_insert(library.generation);
                }
            }
            let request = SkillAddRequest {
                command: SkillAddCommand::Add,
                idempotency_key: requests::new_key()?,
                expected_generation: generation.context("library generation unavailable")?,
                items: captured.iter().map(|entry| entry.item.clone()).collect(),
                scope_explicit: !scope.tools.is_empty() || scope.account_id.is_some(),
                scope: scope.clone(),
            };
            SkillCommandRecord {
                server_url: server,
                user_id: user,
                intent_digest: digest,
                idempotency_key: request.idempotency_key.clone(),
                request_json: serde_json::to_string(&request)?,
            }
        }
    };
    let retained = requests::Request::retained(&proposed)?;
    let requests::Request::Add(request) = &retained else {
        bail!("retained command is not an installation");
    };
    if request.scope != scope {
        bail!("retained installation scope differs");
    }
    let preview = serde_json::json!({
        "request":request,"recovering_original_request":recovering,
        "packages":captured.iter().map(|entry| serde_json::json!({
            "name":entry.item.name,"tree_digest":entry.item.tree_digest,
            "bytes":entry.snapshot.total_bytes(),"entries":entry.snapshot.manifest().entries.len()
        })).collect::<Vec<_>>()
    });
    if args.options.dry_run {
        let result = SkillResult {
            schema_version: 1,
            operation_id: None,
            status: "planned".to_owned(),
            committed: false,
            retryable: false,
            errors: Vec::<SkillError>::new(),
            data: Some(preview),
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
    if !args.options.yes && !super::confirmation::review(&preview).await? {
        return local_error(
            "CHANGE_CANCELLED",
            "This invocation did not upload packages or submit an installation.",
            1,
            json,
        );
    }
    for (index, entry) in captured.into_iter().enumerate() {
        let key = format!("upload-{}-{index}", request.idempotency_key);
        upload::package(&client, &token, &key, entry.snapshot).await?;
    }
    Ok(Some(Submission {
        client,
        token,
        record: proposed,
        recovering,
        options: args.options,
    }))
}

fn source_error<T>(error: anyhow::Error, json: bool) -> Result<T> {
    let message = error.to_string();
    let code = message
        .split_once(':')
        .map(|(code, _)| code)
        .filter(|code| {
            !code.is_empty()
                && code.len() <= 80
                && code.bytes().all(|b| b.is_ascii_uppercase() || b == b'_')
        })
        .unwrap_or("SKILL_SOURCE_FAILED");
    local_error(
        code,
        &message,
        if code == "SOURCE_INTERRUPTED" {
            130
        } else if matches!(
            code,
            "SELECTION_REQUIRED"
                | "INVALID_SOURCE"
                | "INVALID_REF"
                | "REF_AMBIGUOUS"
                | "REF_REQUIRED"
        ) {
            2
        } else {
            1
        },
        json,
    )
}
