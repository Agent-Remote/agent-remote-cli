mod api;
mod cli;
mod config;
mod dependencies;
mod doctor;
mod local_state;
mod mutagen;
mod platform;
mod secrets;
mod ssh;
mod wireguard;
mod workspace;

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::time::sleep;

use crate::api::{
    ApiClient, AuthToken, BindingStatusData, CreateSyncSessionRequest, CreateToolAccountRequest,
    CreateWorkspaceRequest, RegisterDeviceRequest, SyncSessionData, ToolAccountData, WorkspaceData,
};
use crate::cli::{
    AccountCommand, AccountDefaultCommand, Cli, Command, DepsCommand, LoginMethod, SshCommand,
    SyncCommand, WireGuardCommand,
};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::{LocalDevice, LocalState, LocalSyncSession, LocalWorkspace};
use crate::secrets::{device_token_key, user_token_key, SecretStore};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    let paths = AppPaths::new(cli.home)?;
    match cli.command {
        Command::Login(args) => login(paths, args).await,
        Command::Logout(args) => logout(paths, args.revoke_remote).await,
        Command::Status(args) => status(paths, args.online).await,
        Command::Doctor(args) => Doctor::new(paths).run(args.fix).await,
        Command::Deps(DepsCommand::Status(args)) => deps_status(paths, args.fix),
        Command::Wireguard(WireGuardCommand::Config(args)) => wireguard_config(paths, args).await,
        Command::Wireguard(WireGuardCommand::Check(args)) => wireguard_action(paths, "check", args),
        Command::Wireguard(WireGuardCommand::Up(args)) => wireguard_action(paths, "up", args),
        Command::Wireguard(WireGuardCommand::Down(args)) => wireguard_action(paths, "down", args),
        Command::Ssh(SshCommand::Check(args)) => ssh_check(paths, args).await,
        Command::Sync(SyncCommand::Ensure(args)) => sync_ensure(paths, args).await,
        Command::Sync(SyncCommand::Status(args)) => sync_status(paths, args).await,
        Command::Sync(SyncCommand::Pause(args)) => sync_action(paths, "pause", args).await,
        Command::Sync(SyncCommand::Resume(args)) => sync_action(paths, "resume", args).await,
        Command::Sync(SyncCommand::Resolve(args)) => sync_action(paths, "resolve", args).await,
        Command::Sync(SyncCommand::Reset(args)) => sync_action(paths, "reset", args).await,
        Command::Account(AccountCommand::List) => account_list(paths).await,
        Command::Account(AccountCommand::Create(args)) => account_create(paths, args).await,
        Command::Account(AccountCommand::Bind(args)) => account_bind(paths, args).await,
        Command::Account(AccountCommand::Verify(args)) => account_verify(paths, args).await,
        Command::Account(AccountCommand::Status(args)) => account_status(paths, args).await,
        Command::Account(AccountCommand::Disable(args)) => account_disable(paths, args).await,
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Set(args))) => {
            account_default_set(paths, args).await
        }
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Get(args))) => {
            account_default_get(paths, args)
        }
        Command::Account(AccountCommand::Default(AccountDefaultCommand::Clear(args))) => {
            account_default_clear(paths, args)
        }
        Command::Attach(args) => attach(paths, args).await,
    }
}

async fn login(paths: AppPaths, args: crate::cli::LoginArgs) -> Result<()> {
    paths.ensure_base_dirs()?;
    let mut config = Config::load(&paths)?;
    let server_url = args
        .server_url
        .clone()
        .or_else(|| config.server_url.clone())
        .context("missing server URL; pass --server-url or set AGENT_REMOTE_SERVER_URL")?;
    let server_url = normalize_server_url(&server_url);
    config.server_url = Some(server_url.clone());
    config.save(&paths)?;

    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    DependencyManager::new(paths.clone()).ensure_manifest()?;

    let client = ApiClient::new(server_url.clone())?;
    let user_token = match args.method {
        LoginMethod::Password => password_login(&client, &args).await?,
        LoginMethod::DeviceCode => device_code_login(&client).await?,
    };

    let secret_store = SecretStore::new(paths.clone());
    if args.skip_device_registration {
        let key = user_token_key(&server_url);
        let backend = secret_store.set_secret(&key, &user_token.access_token)?;
        state.set_kv("last_login_mode", "user_token")?;
        println!("logged in to {server_url}");
        println!("stored user token in {backend}");
        println!("token expires in {} seconds", user_token.expires_in);
        println!("device registration skipped");
        return Ok(());
    }

    let ssh_public_key = resolve_ssh_public_key(args.ssh_public_key.as_deref())?;
    let device_name = args
        .device_name
        .unwrap_or_else(platform::default_device_name);
    let platform = platform::current_platform()?;
    let request = RegisterDeviceRequest {
        name: device_name.clone(),
        platform,
        ssh_public_key,
        wireguard_public_key: args.wireguard_public_key,
    };
    let registration = client
        .register_device(&user_token.access_token, &request)
        .await
        .context("failed to register local device")?;
    let device = registration.data.device;

    state.upsert_device(&LocalDevice {
        id: device.id.clone(),
        server_url: server_url.clone(),
        name: device.name.clone(),
        platform: device.platform.clone(),
        status: device.status.clone(),
        ssh_key_id: Some(registration.data.ssh_key_id),
        wireguard_peer_id: registration.data.wireguard_peer_id,
        created_at: Some(device.created_at),
        last_seen_at: device.last_seen_at,
    })?;
    state.set_kv("last_login_mode", "device_token")?;
    config.active_device_id = Some(device.id.clone());
    config.save(&paths)?;

    let key = device_token_key(&server_url, &device.id);
    let backend = secret_store.set_secret(&key, &registration.data.device_token.access_token)?;
    let _ = secret_store.delete_secret(&user_token_key(&server_url));

    println!("logged in to {server_url}");
    println!("registered device {} ({})", device.name, device.id);
    println!(
        "stored device token in {backend}; expires in {} seconds",
        registration.data.device_token.expires_in
    );
    Ok(())
}

async fn password_login(client: &ApiClient, args: &crate::cli::LoginArgs) -> Result<AuthToken> {
    let username = match &args.username {
        Some(username) => username.clone(),
        None => prompt_line("Username: ")?,
    };
    let password = match &args.password {
        Some(password) => password.clone(),
        None => rpassword::prompt_password("Password: ")?,
    };
    client
        .login_password(&username, &password, args.totp_code.as_deref())
        .await
        .context("login failed")
}

async fn device_code_login(client: &ApiClient) -> Result<AuthToken> {
    let start = client.start_cli_login().await?;
    println!("Open: {}", start.verification_url);
    println!("Code: {}", start.user_code);
    println!("Waiting for approval...");

    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    while Instant::now() < deadline {
        match client.complete_cli_login(&start.device_code).await {
            Ok(token) => return Ok(token),
            Err(error) if error.is_pending_cli_login() => {
                sleep(Duration::from_secs(start.interval.max(1))).await;
            }
            Err(error) => return Err(error.into()),
        }
    }
    bail!("CLI login expired before approval")
}

async fn logout(paths: AppPaths, revoke_remote: bool) -> Result<()> {
    let config = Config::load(&paths)?;
    let Some(server_url) = config.server_url.clone() else {
        println!("not logged in");
        return Ok(());
    };
    let secret_store = SecretStore::new(paths.clone());
    let mut token = None;

    if let Some(device_id) = config.active_device_id.clone() {
        let key = device_token_key(&server_url, &device_id);
        token = secret_store.get_secret(&key)?;
        let _ = secret_store.delete_secret(&key);
    }
    let user_key = user_token_key(&server_url);
    if token.is_none() {
        token = secret_store.get_secret(&user_key)?;
    }
    let _ = secret_store.delete_secret(&user_key);

    if revoke_remote {
        if let Some(access_token) = token {
            let client = ApiClient::new(server_url.clone())?;
            if let Err(error) = client.logout(&access_token).await {
                eprintln!("remote logout failed: {error}");
            }
        }
    }

    let mut config = config;
    config.active_device_id = None;
    config.save(&paths)?;
    println!("logged out from {server_url}");
    Ok(())
}

async fn status(paths: AppPaths, online: bool) -> Result<()> {
    let config = Config::load(&paths)?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;

    println!("home: {}", paths.home().display());
    match &config.server_url {
        Some(server_url) => println!("server: {server_url}"),
        None => println!("server: not configured"),
    }

    let active_device = match &config.active_device_id {
        Some(device_id) => state.get_device(device_id)?,
        None => None,
    };
    match &active_device {
        Some(device) => println!("device: {} ({}, {})", device.name, device.id, device.status),
        None => println!("device: not registered"),
    }
    match state.get_kv("last_login_mode")? {
        Some(mode) => println!("login mode: {mode}"),
        None => println!("login mode: unknown"),
    }

    let token_present = config
        .server_url
        .as_ref()
        .and_then(|server_url| {
            let store = SecretStore::new(paths.clone());
            if let Some(device_id) = &config.active_device_id {
                store
                    .get_secret(&device_token_key(server_url, device_id))
                    .ok()
                    .flatten()
            } else {
                store.get_secret(&user_token_key(server_url)).ok().flatten()
            }
        })
        .is_some();
    println!(
        "token: {}",
        if token_present { "present" } else { "missing" }
    );

    if online {
        if let Some(server_url) = config.server_url {
            let client = ApiClient::new(server_url.clone())?;
            let health = client.healthz().await?;
            println!("server health: {}", health.status);
            if let Some(device) = active_device {
                let store = SecretStore::new(paths.clone());
                if let Some(token) = store.get_secret(&device_token_key(&server_url, &device.id))? {
                    let remote = client.get_device(&token, &device.id).await?;
                    println!("remote device: {}", remote.status);
                }
            }
        }
    }
    Ok(())
}

async fn wireguard_config(paths: AppPaths, args: crate::cli::WireGuardConfigArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let client = ApiClient::new(server_url)?;
    let config = client.get_wireguard_config(&token).await?;
    let output = args
        .output
        .unwrap_or_else(|| wireguard::default_config_path(&paths));
    wireguard::write_config(&output, &config)?;
    println!("wrote WireGuard config to {}", output.display());
    println!("device: {}", config.device_id);
    println!("peers: {}", config.peers.len());
    Ok(())
}

fn wireguard_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::WireGuardActionArgs,
) -> Result<()> {
    let config = args
        .config
        .unwrap_or_else(|| wireguard::default_config_path(&paths));
    wireguard::run_helper(&paths, action, &config, args.dry_run)?;
    println!("wireguard {action} ok using {}", config.display());
    Ok(())
}

async fn ssh_check(paths: AppPaths, args: crate::cli::SshCheckArgs) -> Result<()> {
    let version = ssh::check_ssh_available()?;
    println!("ssh: {version}");
    if let Some(session_id) = args.session_id {
        let (server_url, _device_id, token) = load_device_token(&paths)?;
        let attach = ApiClient::new(server_url)?
            .attach_session(&token, &session_id)
            .await?;
        println!("session: {}", attach.session_id);
        println!("node: {} {}", attach.node_id, attach.node_wireguard_ip);
        println!("tmux: {}", attach.tmux_session_name);
        println!("command: {}", attach.ssh_command);
        println!("authorization task: {}", attach.authorization_task_id);
        println!("expires in: {} seconds", attach.expires_in);
    }
    Ok(())
}

async fn attach(paths: AppPaths, args: crate::cli::AttachArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let attach = ApiClient::new(server_url)?
        .attach_session(&token, &args.session_id)
        .await?;
    println!("{}", attach.ssh_command);
    println!("tmux: {}", attach.tmux_session_name);
    println!("authorization expires in {} seconds", attach.expires_in);
    if args.print_only {
        return Ok(());
    }
    ssh::execute_attach(&attach)
}

async fn account_list(paths: AppPaths) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let accounts = ApiClient::new(server_url)?
        .list_tool_accounts(&token)
        .await?;
    if accounts.is_empty() {
        println!("tool accounts: none");
        return Ok(());
    }
    for account in accounts {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            account.id,
            account.tool_type,
            account.display_name,
            account.status,
            account.region_code
        );
    }
    Ok(())
}

async fn account_create(paths: AppPaths, args: crate::cli::AccountCreateArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let account = ApiClient::new(server_url)?
        .create_tool_account(
            &token,
            &CreateToolAccountRequest {
                tool_type: args.tool,
                display_name: args.name,
                region_code: args.region,
                timezone: args.timezone,
                locale: args.locale,
                preferred_node_tags: args.tags,
            },
        )
        .await?;
    print_tool_account(&account);
    Ok(())
}

async fn account_bind(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let binding = ApiClient::new(server_url)?
        .start_tool_account_binding(&token, &args.account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_verify(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let binding = ApiClient::new(server_url)?
        .verify_tool_account_binding(&token, &args.account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_status(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let client = ApiClient::new(server_url)?;
    let account = client.get_tool_account(&token, &args.account_id).await?;
    print_tool_account(&account);
    let binding = client
        .get_tool_account_binding_status(&token, &args.account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_disable(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let account = ApiClient::new(server_url)?
        .disable_tool_account(&token, &args.account_id)
        .await?;
    print_tool_account(&account);
    Ok(())
}

async fn account_default_set(
    paths: AppPaths,
    args: crate::cli::AccountDefaultSetArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let account = ApiClient::new(server_url.clone())?
        .get_tool_account(&token, &args.account_id)
        .await?;
    if account.tool_type != args.tool {
        bail!(
            "account {} is {}, not {}",
            account.id,
            account.tool_type,
            args.tool
        );
    }
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.set_kv(&default_account_key(&args.tool), &account.id)?;
    println!("default {} account: {}", args.tool, account.id);
    Ok(())
}

fn account_default_get(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    match state.get_kv(&default_account_key(&args.tool))? {
        Some(account_id) => println!("default {} account: {}", args.tool, account_id),
        None => println!("default {} account: not set", args.tool),
    }
    Ok(())
}

fn account_default_clear(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_kv(&default_account_key(&args.tool))?;
    println!("default {} account cleared", args.tool);
    Ok(())
}

fn print_tool_account(account: &ToolAccountData) {
    println!("account: {}", account.id);
    println!("tool: {}", account.tool_type);
    println!("name: {}", account.display_name);
    println!("status: {}", account.status);
    println!("region: {}", account.region_code);
    println!("timezone: {}", account.timezone);
    println!("locale: {}", account.locale);
    if let Some(node_id) = &account.affinity_node_id {
        println!("affinity node: {node_id}");
    }
    if !account.preferred_node_tags.is_empty() {
        println!("tags: {}", account.preferred_node_tags.join(","));
    }
}

fn print_binding_status(status: &BindingStatusData) {
    println!("binding status: {}", status.status);
    if let Some(node_id) = &status.node_id {
        println!("node: {node_id}");
    }
    if let Some(task_id) = &status.task_id {
        println!("task: {task_id}");
    }
    if let Some(binding_session_id) = &status.binding_session_id {
        println!("binding session: {binding_session_id}");
    }
    if let Some(tmux_session_name) = &status.tmux_session_name {
        println!("tmux: {tmux_session_name}");
    }
    if let Some(path) = &status.account_remote_path {
        println!("remote account path: {path}");
    }
    if let Some(command) = &status.connect_command {
        println!("command: {command}");
    }
    if let Some(verifier) = &status.verifier {
        println!("verifier: {verifier}");
    }
    if let Some(error) = &status.error {
        println!("error: {error}");
    }
}

async fn sync_ensure(paths: AppPaths, args: crate::cli::SyncEnsureArgs) -> Result<()> {
    let sync =
        ensure_workspace_sync(&paths, args.workspace.as_deref(), args.yes, args.dry_run).await?;
    println!("workspace: {}", sync.workspace_id);
    println!("sync session: {} ({})", sync.id, sync.status);
    println!("remote: {}", sync.remote_path);
    if let Some(endpoint) = sync.remote_endpoint {
        println!("endpoint: {endpoint}");
    }
    Ok(())
}

async fn sync_status(paths: AppPaths, args: crate::cli::SyncStatusArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let Some(local_workspace) =
        state.get_workspace_by_project_key(&server_url, &identity.project_key)?
    else {
        println!("workspace: not registered");
        println!("path: {}", identity.local_path.display());
        return Ok(());
    };
    let Some(local_sync) = state.get_sync_session_for_workspace(&local_workspace.id)? else {
        println!("workspace: {}", local_workspace.id);
        println!("sync session: missing");
        return Ok(());
    };
    let client = ApiClient::new(server_url.clone())?;
    let sync = client.get_sync_session(&token, &local_sync.id).await?;
    persist_sync_session(&state, &server_url, &sync)?;
    let mutagen_status = mutagen::status(&paths, &sync)?;
    println!("workspace: {}", local_workspace.id);
    println!("path: {}", local_workspace.local_path);
    println!("sync session: {} ({})", sync.id, sync.status);
    println!("conflicts: {}", sync.conflict_status);
    println!(
        "mutagen: {}",
        if mutagen_status.installed {
            "present"
        } else {
            "missing"
        }
    );
    if !mutagen_status.output.is_empty() {
        println!("{}", mutagen_status.output);
    }
    if sync.conflict_status != "none" || mutagen_status.has_conflicts {
        if args.fail_on_conflict {
            bail!("workspace sync has unresolved conflicts");
        }
        println!("sync has unresolved conflicts");
    }
    Ok(())
}

async fn sync_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::SyncActionArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let local_workspace = state
        .get_workspace_by_project_key(&server_url, &identity.project_key)?
        .context("workspace is not registered; run agent-remote sync ensure")?;
    let local_sync = state
        .get_sync_session_for_workspace(&local_workspace.id)?
        .context("sync session is missing; run agent-remote sync ensure")?;
    let client = ApiClient::new(server_url.clone())?;
    let current = client.get_sync_session(&token, &local_sync.id).await?;
    match action {
        "pause" => {
            mutagen::pause(&paths, &current, args.dry_run)?;
            let sync = client.pause_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            println!("sync paused: {}", sync.id);
        }
        "resume" => {
            let sync = client.resume_sync_session(&token, &current.id).await?;
            mutagen::resume(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            println!("sync resumed: {}", sync.id);
        }
        "resolve" => {
            mutagen::resolve(&paths, &current, args.dry_run)?;
            let sync = client.resolve_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            println!("sync resolved: {}", sync.id);
        }
        "reset" => {
            let sync = client.reset_sync_session(&token, &current.id).await?;
            mutagen::reset(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            println!("sync reset: {}", sync.id);
        }
        _ => bail!("unsupported sync action: {action}"),
    }
    Ok(())
}

async fn ensure_workspace_sync(
    paths: &AppPaths,
    workspace_path: Option<&std::path::Path>,
    assume_yes: bool,
    dry_run: bool,
) -> Result<SyncSessionData> {
    let (server_url, device_id, token) = load_device_token(paths)?;
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
                    },
                )
                .await?;
            persist_workspace(&state, &server_url, &remote)?;
            remote
        }
    };

    let mut should_create_mutagen = false;
    let sync = match state.get_sync_session_for_workspace(&workspace.id)? {
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
                    },
                )
                .await?
        }
    };
    persist_sync_session(&state, &server_url, &sync)?;
    if should_create_mutagen {
        mutagen::create(paths, &sync, dry_run)?;
    }
    Ok(sync)
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

fn load_device_token(paths: &AppPaths) -> Result<(String, String, String)> {
    let config = Config::load(paths)?;
    let server_url = config
        .server_url
        .context("not logged in: server URL is missing")?;
    let device_id = config
        .active_device_id
        .context("not logged in with a registered device")?;
    let store = SecretStore::new(paths.clone());
    let token = store
        .get_secret(&device_token_key(&server_url, &device_id))?
        .context("device token is missing; run agent-remote login")?;
    Ok((server_url, device_id, token))
}

fn default_account_key(tool: &str) -> String {
    format!("default_tool_account:{tool}")
}
fn deps_status(paths: AppPaths, fix: bool) -> Result<()> {
    let manager = DependencyManager::new(paths);
    if fix {
        manager.ensure_manifest()?;
    }
    for status in manager.check_all()? {
        println!(
            "{}: {} ({}) license: {}; notice: {}",
            status.name,
            if status.installed {
                "present"
            } else {
                "missing"
            },
            status.binary_path.display(),
            status.license,
            status.license_notice
        );
    }
    Ok(())
}

fn normalize_server_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("empty value is not allowed")
    }
    Ok(value)
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

fn resolve_ssh_public_key(explicit: Option<&std::path::Path>) -> Result<String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => platform::default_ssh_public_key_path().context(
            "missing SSH public key; pass --ssh-public-key or use --skip-device-registration",
        )?,
    };
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read SSH public key at {}", path.display()))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("SSH public key at {} is empty", path.display());
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::normalize_server_url;

    #[test]
    fn trims_trailing_slashes_from_server_url() {
        assert_eq!(
            normalize_server_url(" https://example.test/// "),
            "https://example.test"
        );
    }
}
