use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use agent_remote_cli::api::{
    ApiClient, CreateSessionRequest, CreateSyncSessionRequest, CreateWorkspaceRequest,
    GitSyncPolicy, SessionData, SyncSessionData, ToolAccountData, WorkspaceData,
};
use agent_remote_cli::auth::load_device_token;
use agent_remote_cli::cli::VERSION;
use agent_remote_cli::config::AppPaths;
use agent_remote_cli::identifiers::{resolve_id, short_id};
use agent_remote_cli::local_state::{LocalState, LocalSyncSession, LocalWorkspace};
use agent_remote_cli::terminal::{self, ColorChoice, Details, Table};
use agent_remote_cli::{mutagen, ssh, workspace};
use anyhow::{bail, Context, Result};
use clap::{Args as ClapArgs, Parser, Subcommand};
use tokio::time::sleep;

const TOOL_TYPE: &str = "claude";

#[derive(Debug, PartialEq, Eq)]
enum Mode {
    Run,
    New,
    List(SessionListArgs),
    Attach(String),
    Stop(String),
}

#[derive(Debug, Default, PartialEq, Eq)]
struct SessionListArgs {
    statuses: Vec<String>,
    no_trunc: bool,
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

#[derive(Debug, Parser)]
#[command(
    name = "fclaude",
    version = VERSION,
    about = "Run and manage remote Claude Code sessions",
    long_about = "Start Claude Code in the synchronized current workspace, resume the matching remote session, or explicitly list, attach, and stop sessions.",
    after_help = "Examples:\n  fclaude\n  fclaude --model opus\n  fclaude new -- --model sonnet\n  fclaude list --running\n  fclaude attach b68873d48e07\n  fclaude stop b68873d48e07",
    trailing_var_arg = true,
    args_conflicts_with_subcommands = true
)]
struct FClaudeCli {
    /// Override the agent-remote state and configuration directory.
    #[arg(long, env = "AGENT_REMOTE_HOME", global = true, value_name = "PATH")]
    home: Option<PathBuf>,

    /// Use a Claude account by its displayed short ID or full UUID.
    #[arg(long, global = true, value_name = "ACCOUNT_ID")]
    account_id: Option<String>,

    /// Accept workspace synchronization prompts.
    #[arg(long, short = 'y', global = true)]
    yes: bool,

    /// Print local synchronization actions without executing them.
    #[arg(long, global = true)]
    dry_run: bool,

    /// Control colored output.
    #[arg(
        long,
        env = "AGENT_REMOTE_COLOR",
        global = true,
        value_enum,
        default_value_t = ColorChoice::Auto
    )]
    color: ColorChoice,

    #[command(subcommand)]
    command: Option<FClaudeCommand>,

    /// Arguments passed directly to Claude Code in the default run mode.
    #[arg(value_name = "CLAUDE_ARG", allow_hyphen_values = true)]
    claude_args: Vec<String>,
}

#[derive(Debug, Subcommand)]
enum FClaudeCommand {
    /// Start or resume the Claude session for the current workspace.
    Run(ClaudePassthroughArgs),
    /// Always create a new Claude session for the current workspace.
    New(ClaudePassthroughArgs),
    /// List Claude sessions with optional status filters.
    List(FClaudeListArgs),
    /// Attach to a session using its displayed short ID or full UUID.
    Attach(AttachArgs),
    /// Stop a session using its displayed short ID or full UUID.
    Stop(SessionReferenceArgs),
}

#[derive(Debug, Default, ClapArgs)]
#[command(trailing_var_arg = true)]
struct ClaudePassthroughArgs {
    /// Arguments passed directly to Claude Code; use -- before ambiguous values.
    #[arg(value_name = "CLAUDE_ARG", allow_hyphen_values = true)]
    claude_args: Vec<String>,
}

#[derive(Debug, ClapArgs)]
struct FClaudeListArgs {
    /// Include sessions with this status; repeat for multiple statuses.
    #[arg(long = "status", value_name = "STATUS")]
    statuses: Vec<String>,

    /// Include starting sessions.
    #[arg(long)]
    starting: bool,

    /// Include running sessions.
    #[arg(long)]
    running: bool,

    /// Include active sessions.
    #[arg(long)]
    active: bool,

    /// Include sessions currently stopping.
    #[arg(long)]
    stopping: bool,

    /// Include stopped sessions.
    #[arg(long)]
    stopped: bool,

    /// Include interrupted sessions.
    #[arg(long)]
    interrupted: bool,

    /// Include failed sessions.
    #[arg(long)]
    failed: bool,

    /// Show full UUIDs and paths instead of compact values.
    #[arg(long)]
    no_trunc: bool,
}

#[derive(Debug, ClapArgs)]
struct AttachArgs {
    /// Unique session ID prefix or full UUID.
    #[arg(value_name = "SESSION")]
    session_id: String,

    /// Print the authorized SSH command without executing it.
    #[arg(long)]
    print_only: bool,
}

#[derive(Debug, ClapArgs)]
struct SessionReferenceArgs {
    /// Unique session ID prefix or full UUID.
    #[arg(value_name = "SESSION")]
    session_id: String,
}

#[tokio::main]
async fn main() {
    let cli = FClaudeCli::parse();
    terminal::configure(cli.color);
    if let Err(error) = run(cli.into_args()).await {
        eprintln!("{} {error:#}", terminal::failure("ERROR"));
        std::process::exit(1);
    }
}

impl FClaudeCli {
    fn into_args(self) -> FClaudeArgs {
        let (mode, claude_args, print_only) = match self.command {
            Some(FClaudeCommand::Run(args)) => (Mode::Run, args.claude_args, false),
            Some(FClaudeCommand::New(args)) => (Mode::New, args.claude_args, false),
            Some(FClaudeCommand::List(args)) => (
                Mode::List(SessionListArgs {
                    statuses: args.resolved_statuses(),
                    no_trunc: args.no_trunc,
                }),
                Vec::new(),
                false,
            ),
            Some(FClaudeCommand::Attach(args)) => {
                (Mode::Attach(args.session_id), Vec::new(), args.print_only)
            }
            Some(FClaudeCommand::Stop(args)) => (Mode::Stop(args.session_id), Vec::new(), false),
            None => (Mode::Run, self.claude_args, false),
        };
        FClaudeArgs {
            home: self.home,
            account_id: self.account_id,
            yes: self.yes,
            dry_run: self.dry_run,
            print_only,
            mode,
            claude_args,
        }
    }
}

impl FClaudeListArgs {
    fn resolved_statuses(&self) -> Vec<String> {
        let mut statuses = self.statuses.clone();
        for (enabled, status) in [
            (self.starting, "starting"),
            (self.running, "running"),
            (self.active, "active"),
            (self.stopping, "stopping"),
            (self.stopped, "stopped"),
            (self.interrupted, "interrupted"),
            (self.failed, "failed"),
        ] {
            if enabled && !statuses.iter().any(|value| value == status) {
                statuses.push(status.to_string());
            }
        }
        statuses
    }
}

async fn run(args: FClaudeArgs) -> Result<()> {
    let paths = AppPaths::new(args.home.clone())?;
    match &args.mode {
        Mode::List(list_args) => list_sessions(&paths, list_args).await,
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

async fn list_sessions(paths: &AppPaths, args: &SessionListArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let sessions = ApiClient::new(server_url)?
        .list_sessions(&token, Some(TOOL_TYPE), &args.statuses)
        .await?;
    if sessions.is_empty() {
        terminal::note("No Claude sessions match the selected filters.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "STATUS", "WORKDIR", "NODE", "BACKEND"]);
    for session in sessions {
        let working_directory = session
            .workspace_local_path
            .as_deref()
            .or(session.workspace_remote_path.as_deref())
            .unwrap_or("-");
        table.row(if args.no_trunc {
            vec![
                display_cell(&session.id),
                display_cell(&session.status),
                display_cell(working_directory),
                display_cell(&session.node_id),
                display_cell(&session.runtime_backend),
            ]
        } else {
            vec![
                short_id(&session.id),
                display_cell(&session.status),
                truncate_left(&display_cell(working_directory), 44),
                short_id(&session.node_id),
                display_cell(&session.runtime_backend),
            ]
        });
    }
    table.render();
    Ok(())
}

fn display_cell(value: &str) -> String {
    value.replace(['\t', '\n', '\r'], " ")
}

fn truncate_left(value: &str, max_chars: usize) -> String {
    let characters: Vec<_> = value.chars().collect();
    if characters.len() <= max_chars {
        return value.to_string();
    }
    format!(
        "...{}",
        characters[characters.len() - (max_chars - 3)..]
            .iter()
            .collect::<String>()
    )
}

async fn attach_session(paths: &AppPaths, session_id: &str, print_only: bool) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let client = ApiClient::new(server_url)?;
    let session_id = resolve_session_id(&client, &token, session_id).await?;
    attach_with_client(&client, &token, &session_id, print_only).await
}

async fn stop_session(paths: &AppPaths, session_id: &str) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(paths).await?;
    let client = ApiClient::new(server_url)?;
    let session_id = resolve_session_id(&client, &token, session_id).await?;
    let session = client.stop_tool_session(&token, &session_id).await?;
    terminal::success_line("Claude session stop requested");
    let mut details = Details::new()
        .field("Session", session.id)
        .status("Status", session.status);
    if let Some(task_id) = session.stop_task_id {
        details = details.field("Stop task", task_id);
    }
    details.render();
    Ok(())
}

async fn resolve_session_id(client: &ApiClient, token: &str, reference: &str) -> Result<String> {
    let sessions = client.list_sessions(token, Some(TOOL_TYPE), &[]).await?;
    resolve_id(
        reference,
        "Claude session",
        sessions.iter().map(|session| session.id.as_str()),
    )
}

async fn attach_with_client(
    client: &ApiClient,
    token: &str,
    session_id: &str,
    print_only: bool,
) -> Result<()> {
    let attach = client.attach_session(token, session_id).await?;
    terminal::section("Claude Attach");
    Details::new()
        .field("Command", terminal::command(&attach.ssh_command))
        .field("Tmux", &attach.tmux_session_name)
        .render();
    if print_only {
        return Ok(());
    }
    let attach = client.wait_for_attach_authorization(token, attach).await?;
    ssh::execute_attach(&attach)
}

async fn choose_account(
    paths: &AppPaths,
    client: &ApiClient,
    token: &str,
    explicit_account_id: Option<&str>,
) -> Result<ToolAccountData> {
    if let Some(account_id) = explicit_account_id {
        let accounts = client.list_tool_accounts(token).await?;
        let account_id = resolve_id(
            account_id,
            "Claude account",
            accounts.iter().map(|account| account.id.as_str()),
        )?;
        let account = accounts
            .into_iter()
            .find(|account| account.id == account_id)
            .context("resolved Claude account disappeared from the account list")?;
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
            terminal::warning_line("Multiple active Claude accounts found.");
            let mut table = Table::new(["ID", "NAME", "REGION"]);
            for account in active {
                table.row([
                    short_id(&account.id),
                    account.display_name,
                    account.region_code,
                ]);
            }
            table.render();
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
                terminal::section("Workspace Setup");
                Details::new()
                    .field("Workspace", identity.local_path.display())
                    .render();
                terminal::note(
                    "A remote synchronization relationship is required for this directory.",
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

fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
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
    use super::{truncate_left, FClaudeCli, Mode, SessionListArgs};
    use clap::{Command, CommandFactory, Parser};

    fn parse_args(values: &[&str]) -> super::FClaudeArgs {
        FClaudeCli::try_parse_from(std::iter::once("fclaude").chain(values.iter().copied()))
            .unwrap()
            .into_args()
    }

    fn assert_documented(command: &Command, path: &str) {
        assert!(
            command.get_about().is_some() || command.get_long_about().is_some(),
            "{path} is missing command help"
        );
        for argument in command.get_arguments() {
            if matches!(argument.get_id().as_str(), "help" | "version") {
                continue;
            }
            assert!(
                argument.get_help().is_some() || argument.get_long_help().is_some(),
                "{path} argument {} is missing help",
                argument.get_id()
            );
        }
        for child in command.get_subcommands() {
            assert_documented(child, &format!("{path} {}", child.get_name()));
        }
    }

    #[test]
    fn every_fclaude_command_and_argument_has_help() {
        let command = FClaudeCli::command();
        command.clone().debug_assert();
        assert_documented(&command, "fclaude");
    }

    #[test]
    fn parses_direct_passthrough_flags() {
        let args = parse_args(&["--model", "opus"]);
        assert_eq!(args.mode, Mode::Run);
        assert_eq!(args.claude_args, vec!["--model", "opus"]);
    }

    #[test]
    fn parses_double_dash_passthrough_flags() {
        let args = parse_args(&["--", "--model", "opus"]);
        assert_eq!(args.mode, Mode::Run);
        assert_eq!(args.claude_args, vec!["--model", "opus"]);
    }

    #[test]
    fn parses_attach_mode() {
        let args = parse_args(&["attach", "01234567"]);
        assert_eq!(args.mode, Mode::Attach("01234567".into()));
    }

    #[test]
    fn parses_list_status_shortcuts() {
        let args = parse_args(&["list", "--running", "--stopped"]);
        assert_eq!(
            args.mode,
            Mode::List(SessionListArgs {
                statuses: vec!["running".into(), "stopped".into()],
                no_trunc: false,
            })
        );
    }

    #[test]
    fn parses_repeatable_explicit_list_status() {
        let args = parse_args(&["list", "--status", "active", "--status", "failed"]);
        assert_eq!(
            args.mode,
            Mode::List(SessionListArgs {
                statuses: vec!["active".into(), "failed".into()],
                no_trunc: false,
            })
        );
    }

    #[test]
    fn parses_untruncated_list_mode() {
        let args = parse_args(&["list", "--no-trunc"]);
        assert_eq!(
            args.mode,
            Mode::List(SessionListArgs {
                statuses: vec![],
                no_trunc: true,
            })
        );
    }

    #[test]
    fn keeps_workdir_suffix_when_truncated() {
        assert_eq!(
            truncate_left("/one/two/three/project", 16),
            "...three/project"
        );
    }
}
