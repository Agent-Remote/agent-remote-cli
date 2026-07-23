use std::env;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_remote_cli::api::{
    ApiClient, CreateSessionRequest, CreateSyncSessionRequest, CreateWorkspaceRequest,
    GitSyncPolicy, SessionData, SyncSessionData, ToolAccountData, WorkspaceData,
};
use agent_remote_cli::auth::load_device_token;
use agent_remote_cli::config::AppPaths;
use agent_remote_cli::local_state::{LocalState, LocalSyncSession, LocalWorkspace};
use agent_remote_cli::{mutagen, ssh, workspace};
use anyhow::{bail, Context, Result};
use tokio::time::sleep;

const TOOL_TYPE: &str = "claude";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run,
    New,
    List,
    Attach(String),
    Stop(String),
}

#[derive(Debug)]
struct FClaudeArgs {
    home: Option<PathBuf>,
    account_id: Option<String>,
    yes: bool,
    dry_run: bool,
    print_only: bool,
    mode: Mode,
    claude_args: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = parse_args(env::args().skip(1).collect())?;
    run(args).await
}

async fn run(args: FClaudeArgs) -> Result<()> {
    let paths = AppPaths::new(args.home.clone())?;
    match &args.mode {
        Mode::List => list_sessions(&paths).await,
        Mode::Attach(session_id) => attach_session(&paths, session_id, args.print_only).await,
        Mode::Stop(session_id) => stop_session(&paths, session_id).await,
        Mode::Run | Mode::New => run_or_create_session(&paths, args).await,
    }
}

async fn run_or_create_session(paths: &AppPaths, args: FClaudeArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let identity = workspace::identify_workspace(None)?;
    let sync = ensure_workspace_sync(paths, None, args.yes, args.dry_run).await?;
    ensure_sync_ready(paths, &sync)?;

    let client = ApiClient::new(server_url)?;
    let existing = match &args.mode {
        Mode::Run => match client
            .get_current_project_session(&token, TOOL_TYPE, &identity.project_key)
            .await
        {
            Ok(session) if account_matches(&session, args.account_id.as_deref()) => Some(session),
            Ok(_) => None,
            Err(error) if error.is_not_found() => None,
            Err(error) => return Err(error.into()),
        },
        Mode::New => None,
        _ => None,
    };

    let session = match existing {
        Some(session) if session.status == "interrupted" => {
            client
                .create_tool_session(
                    &token,
                    &CreateSessionRequest {
                        tool_type: TOOL_TYPE.to_string(),
                        tool_account_id: session.tool_account_id.clone(),
                        workspace_id: session.workspace_id.clone(),
                        project_key: session.project_key.clone(),
                        argv: args.claude_args,
                        replaces_session_id: Some(session.id),
                    },
                )
                .await?
        }
        Some(session) => session,
        None => {
            let account =
                choose_account(paths, &client, &token, args.account_id.as_deref()).await?;
            client
                .create_tool_session(
                    &token,
                    &CreateSessionRequest {
                        tool_type: TOOL_TYPE.to_string(),
                        tool_account_id: account.id,
                        workspace_id: sync.workspace_id.clone(),
                        project_key: identity.project_key,
                        argv: args.claude_args,
                        replaces_session_id: None,
                    },
                )
                .await?
        }
    };
    let session = wait_until_attachable(&client, &token, session).await?;
    attach_with_client(&client, &token, &session.id, args.print_only).await
}

async fn list_sessions(paths: &AppPaths) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let sessions = ApiClient::new(server_url)?
        .list_sessions(&token, Some(TOOL_TYPE))
        .await?;
    if sessions.is_empty() {
        println!("claude sessions: none");
        return Ok(());
    }
    for session in sessions {
        println!(
            "{}\t{}\t{}\t{}\t{}\t{}",
            session.id,
            session.status,
            session.project_key,
            session.node_id,
            session.runtime_backend,
            session.tmux_session_name.unwrap_or_else(|| "-".to_string())
        );
    }
    Ok(())
}

async fn attach_session(paths: &AppPaths, session_id: &str, print_only: bool) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let client = ApiClient::new(server_url)?;
    attach_with_client(&client, &token, session_id, print_only).await
}

async fn stop_session(paths: &AppPaths, session_id: &str) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let session = ApiClient::new(server_url)?
        .stop_tool_session(&token, session_id)
        .await?;
    println!("session: {} ({})", session.id, session.status);
    if let Some(task_id) = session.stop_task_id {
        println!("stop task: {task_id}");
    }
    Ok(())
}

async fn attach_with_client(
    client: &ApiClient,
    token: &str,
    session_id: &str,
    print_only: bool,
) -> Result<()> {
    let attach = client.attach_session(token, session_id).await?;
    println!("{}", attach.ssh_command);
    println!("tmux: {}", attach.tmux_session_name);
    if print_only {
        return Ok(());
    }
    ssh::execute_attach(&attach)
}

async fn choose_account(
    paths: &AppPaths,
    client: &ApiClient,
    token: &str,
    explicit_account_id: Option<&str>,
) -> Result<ToolAccountData> {
    if let Some(account_id) = explicit_account_id {
        let account = client.get_tool_account(token, account_id).await?;
        validate_active_account(&account)?;
        return Ok(account);
    }

    let state = LocalState::open(paths)?;
    state.init_schema()?;
    if let Some(account_id) = state.get_kv(&default_account_key())? {
        let account = client.get_tool_account(token, &account_id).await?;
        validate_active_account(&account)?;
        return Ok(account);
    }

    let accounts = client.list_tool_accounts(token).await?;
    let active: Vec<_> = accounts
        .into_iter()
        .filter(|account| account.tool_type == TOOL_TYPE && account.status == "active")
        .collect();
    match active.len() {
        0 => bail!("no active Claude account; bind and verify one with agent-remote account"),
        1 => Ok(active.into_iter().next().expect("one active account")),
        _ => {
            eprintln!("multiple active Claude accounts found:");
            for account in active {
                eprintln!(
                    "{}\t{}\t{}",
                    account.id, account.display_name, account.region_code
                );
            }
            bail!("choose one with --account-id or set a default with agent-remote account default set")
        }
    }
}

fn validate_active_account(account: &ToolAccountData) -> Result<()> {
    if account.tool_type != TOOL_TYPE {
        bail!(
            "account {} is {}, not claude",
            account.id,
            account.tool_type
        );
    }
    if account.status != "active" {
        bail!("account {} is not active: {}", account.id, account.status);
    }
    Ok(())
}

fn account_matches(session: &SessionData, account_id: Option<&str>) -> bool {
    match account_id {
        Some(account_id) => session.tool_account_id == account_id,
        None => true,
    }
}

async fn wait_until_attachable(
    client: &ApiClient,
    token: &str,
    initial: SessionData,
) -> Result<SessionData> {
    if initial.status == "running" || initial.status == "active" {
        return Ok(initial);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
        let session = client.get_tool_session(token, &initial.id).await?;
        if session.status == "running" || session.status == "active" {
            return Ok(session);
        }
        if session.status == "failed" || session.status == "stopped" {
            bail!("session {} became {}", session.id, session.status);
        }
    }
    Ok(initial)
}

async fn ensure_workspace_sync(
    paths: &AppPaths,
    workspace_path: Option<&Path>,
    assume_yes: bool,
    dry_run: bool,
) -> Result<SyncSessionData> {
    let (server_url, device_id, token) = load_device_token(paths).await?;
    let identity = workspace::identify_workspace(workspace_path)?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let client = ApiClient::new(server_url.clone())?;

    let workspace = match state.get_workspace_by_project_key(&server_url, &identity.project_key)? {
        Some(local) => WorkspaceData {
            id: local.id,
            user_id: String::new(),
            device_id: device_id.clone(),
            project_key: local.project_key,
            local_start_path: local.local_path,
            display_name: local.display_name,
            remote_path: local.remote_path,
            sync_git: true,
            git_sync_policy: GitSyncPolicy::default(),
            created_at: String::new(),
            updated_at: String::new(),
        },
        None => {
            if !assume_yes {
                println!("workspace: {}", identity.local_path.display());
                println!(
                    "agent-remote needs to create a remote sync relationship for this directory."
                );
                if !prompt_yes_no("Create workspace sync now? [y/N] ")? {
                    bail!("workspace sync not confirmed; remote session will not be started");
                }
            }
            let remote = client
                .create_workspace(
                    &token,
                    &CreateWorkspaceRequest {
                        device_id: device_id.clone(),
                        project_key: identity.project_key.clone(),
                        local_start_path: identity.local_path.to_string_lossy().to_string(),
                        display_name: identity.display_name.clone(),
                        sync_git: true,
                        git_sync_policy: GitSyncPolicy::default(),
                    },
                )
                .await?;
            persist_workspace(&state, &server_url, &remote)?;
            remote
        }
    };

    let mut should_create_mutagen = false;
    let mut sync = match state.get_sync_session_for_workspace(&workspace.id)? {
        Some(local) => client.get_sync_session(&token, &local.id).await?,
        None => {
            should_create_mutagen = true;
            client
                .create_sync_session(
                    &token,
                    &CreateSyncSessionRequest {
                        workspace_id: workspace.id.clone(),
                        node_id: None,
                        local_path: Some(identity.local_path.to_string_lossy().to_string()),
                        sync_mode: "two_way".to_string(),
                        sync_git: true,
                        exclude: workspace::DEFAULT_EXCLUDES
                            .iter()
                            .map(|value| (*value).to_string())
                            .collect(),
                    },
                )
                .await?
        }
    };
    persist_sync_session(&state, &server_url, &sync)?;
    if should_create_mutagen {
        sync = wait_until_sync_active(&client, &token, sync).await?;
        persist_sync_session(&state, &server_url, &sync)?;
        mutagen::create(paths, &sync, dry_run)?;
    }
    Ok(sync)
}

async fn wait_until_sync_active(
    client: &ApiClient,
    token: &str,
    initial: SyncSessionData,
) -> Result<SyncSessionData> {
    if initial.status == "active" {
        return Ok(initial);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
        let sync = client.get_sync_session(token, &initial.id).await?;
        if sync.status == "active" {
            return Ok(sync);
        }
        if sync.status == "failed" || sync.status == "stopped" {
            bail!("sync session {} became {}", sync.id, sync.status);
        }
    }
    bail!(
        "sync session {} was not prepared within 30 seconds",
        initial.id
    )
}

fn ensure_sync_ready(paths: &AppPaths, sync: &SyncSessionData) -> Result<()> {
    if sync.sync_git {
        workspace::ensure_git_ready(Path::new(&sync.local_path))?;
    }
    if sync.conflict_status != "none" || sync.status == "conflicted" || sync.status == "failed" {
        bail!("workspace sync has unresolved conflicts or failed state");
    }
    let status = mutagen::status(paths, sync)?;
    if status.has_conflicts {
        bail!("workspace sync has unresolved Mutagen conflicts");
    }
    Ok(())
}

fn persist_workspace(
    state: &LocalState,
    server_url: &str,
    workspace: &WorkspaceData,
) -> Result<()> {
    state.upsert_workspace(&LocalWorkspace {
        id: workspace.id.clone(),
        server_url: server_url.to_string(),
        project_key: workspace.project_key.clone(),
        local_path: workspace.local_start_path.clone(),
        display_name: workspace.display_name.clone(),
        remote_path: workspace.remote_path.clone(),
    })
}

fn persist_sync_session(
    state: &LocalState,
    server_url: &str,
    sync: &SyncSessionData,
) -> Result<()> {
    state.upsert_sync_session(&LocalSyncSession {
        id: sync.id.clone(),
        server_url: server_url.to_string(),
        workspace_id: sync.workspace_id.clone(),
        node_id: sync.node_id.clone(),
        status: sync.status.clone(),
        conflict_status: sync.conflict_status.clone(),
        mutagen_session_id: sync.mutagen_session_id.clone(),
        remote_endpoint: sync.remote_endpoint.clone(),
    })
}

fn parse_args(raw: Vec<String>) -> Result<FClaudeArgs> {
    let mut home = None;
    let mut account_id = None;
    let mut yes = false;
    let mut dry_run = false;
    let mut print_only = false;
    let mut mode = Mode::Run;
    let mut claude_args = Vec::new();
    let mut index = 0;
    while index < raw.len() {
        let value = &raw[index];
        match value.as_str() {
            "--" => {
                claude_args.extend(raw[index + 1..].iter().cloned());
                break;
            }
            "--home" => {
                index += 1;
                home = Some(PathBuf::from(
                    raw.get(index).context("--home requires a value")?,
                ));
            }
            "--account-id" => {
                index += 1;
                account_id = Some(
                    raw.get(index)
                        .context("--account-id requires a value")?
                        .clone(),
                );
            }
            "--yes" | "-y" => yes = true,
            "--dry-run" => dry_run = true,
            "--print-only" => print_only = true,
            "new" if mode == Mode::Run => mode = Mode::New,
            "list" if mode == Mode::Run => mode = Mode::List,
            "attach" if mode == Mode::Run => {
                index += 1;
                mode = Mode::Attach(
                    raw.get(index)
                        .context("attach requires a session ID")?
                        .clone(),
                );
            }
            "stop" if mode == Mode::Run => {
                index += 1;
                mode = Mode::Stop(
                    raw.get(index)
                        .context("stop requires a session ID")?
                        .clone(),
                );
            }
            _ if value.starts_with('-') => {
                claude_args.extend(raw[index..].iter().cloned());
                break;
            }
            _ => {
                claude_args.extend(raw[index..].iter().cloned());
                break;
            }
        }
        index += 1;
    }
    Ok(FClaudeArgs {
        home,
        account_id,
        yes,
        dry_run,
        print_only,
        mode,
        claude_args,
    })
}

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};

    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn default_account_key() -> String {
    format!("default_tool_account:{TOOL_TYPE}")
}

#[cfg(test)]
mod tests {
    use super::{parse_args, Mode};

    #[test]
    fn parses_direct_passthrough_flags() {
        let args = parse_args(vec!["--model".into(), "opus".into()]).unwrap();
        assert_eq!(args.mode, Mode::Run);
        assert_eq!(args.claude_args, vec!["--model", "opus"]);
    }

    #[test]
    fn parses_double_dash_passthrough_flags() {
        let args = parse_args(vec!["--".into(), "--model".into(), "opus".into()]).unwrap();
        assert_eq!(args.mode, Mode::Run);
        assert_eq!(args.claude_args, vec!["--model", "opus"]);
    }

    #[test]
    fn parses_attach_mode() {
        let args = parse_args(vec!["attach".into(), "session_1".into()]).unwrap();
        assert_eq!(args.mode, Mode::Attach("session_1".into()));
    }
}
