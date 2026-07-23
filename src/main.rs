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

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use clap::Parser;
use tokio::time::sleep;

use crate::api::{
    ApiClient, AuthToken, BindingStatusData, CreateDeveloperCredentialProfileRequest,
    CreateSyncSessionRequest, CreateToolAccountRequest, CreateWorkspaceRequest,
    DeveloperCredentialGitHubCli, DeveloperCredentialGitIdentity, DeveloperCredentialProfileData,
    DeveloperCredentialSsh, GitSyncPolicy, RegisterDeviceRequest, SyncSessionData,
    ToolAccountConfigImportFile, ToolAccountConfigImportRequest, ToolAccountData, WorkspaceData,
};
use crate::cli::{
    AccountCommand, AccountDefaultCommand, Cli, Command, CredentialsCommand, DepsCommand,
    LoginMethod, SshCommand, SyncCommand, WireGuardCommand,
};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::{LocalDevice, LocalState, LocalSyncSession, LocalWorkspace};
use crate::secrets::{device_token_key, user_token_key, SecretStore};

const CONFIG_IMPORT_MAX_FILE_BYTES: u64 = 1024 * 1024;
const CONFIG_IMPORT_MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    run(cli).await
}

async fn run(cli: Cli) -> Result<()> {
    let paths = AppPaths::new(cli.home)?;
    match cli.command {
        Command::Init(args) => init(paths, args).await,
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
        Command::Account(AccountCommand::ImportConfig(args)) => {
            account_import_config(paths, args).await
        }
        Command::Account(AccountCommand::ExportConfig(_args)) => {
            bail!("account config export is not implemented yet")
        }
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
        Command::Credentials(CredentialsCommand::List) => credentials_list(paths).await,
        Command::Credentials(CredentialsCommand::Create(args)) => {
            credentials_create(paths, args).await
        }
        Command::Credentials(CredentialsCommand::Bind(args)) => credentials_bind(paths, args).await,
        Command::Credentials(CredentialsCommand::Unbind(args)) => {
            credentials_unbind(paths, args).await
        }
        Command::Attach(args) => attach(paths, args).await,
    }
}

struct DeviceRegistrationOptions {
    device_name: Option<String>,
    ssh_public_key: Option<PathBuf>,
    wireguard_public_key: Option<String>,
    skip_device_registration: bool,
}

async fn init(paths: AppPaths, args: crate::cli::InitArgs) -> Result<()> {
    println!("agent-remote initialization");
    paths.ensure_base_dirs()?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;

    let manager = DependencyManager::new(paths.clone());
    manager.ensure_manifest()?;
    println!("checking managed dependencies...");
    for status in manager.check_all()? {
        println!(
            "{} {} at {}",
            if status.installed { "ok" } else { "warn" },
            status.name,
            status.binary_path.display()
        );
    }

    let config = Config::load(&paths)?;
    let server_url = match args.server_url.or(config.server_url) {
        Some(value) => normalize_server_url(&value),
        None if args.yes => "http://127.0.0.1:8765".to_string(),
        None => normalize_server_url(&prompt_line_default("Server URL", "http://127.0.0.1:8765")?),
    };
    let client = ApiClient::new(server_url.clone())?;
    match client.healthz().await {
        Ok(health) => println!("server reachable: {}", health.status),
        Err(error) => println!("warn server health check failed: {error}"),
    }

    println!("login with an existing agent-remote user account.");
    let login_args = crate::cli::LoginArgs {
        server_url: Some(server_url.clone()),
        method: args.method,
        username: args.username,
        password: None,
        totp_code: None,
        device_name: args.device_name.clone(),
        ssh_public_key: args.ssh_public_key.clone(),
        wireguard_public_key: args.wireguard_public_key.clone(),
        skip_device_registration: args.skip_device_registration,
    };
    let user_token = match login_args.method {
        LoginMethod::Password => password_login(&client, &login_args).await?,
        LoginMethod::DeviceCode => device_code_login(&client).await?,
    };

    let registered_device_id = finalize_login(
        paths.clone(),
        server_url.clone(),
        user_token,
        DeviceRegistrationOptions {
            device_name: args.device_name,
            ssh_public_key: init_ssh_public_key(
                args.ssh_public_key,
                args.skip_device_registration,
            )?,
            wireguard_public_key: args.wireguard_public_key,
            skip_device_registration: args.skip_device_registration,
        },
    )
    .await?;

    if !args.skip_wireguard_config && registered_device_id.is_some() {
        let should_write = args.yes
            || prompt_yes_no_default("Fetch and write WireGuard config now? [Y/n] ", true)?;
        if should_write {
            match write_default_wireguard_config(paths.clone()).await {
                Ok(()) => {}
                Err(error) => println!("warn WireGuard config not written: {error}"),
            }
        }
    }

    println!("initialization complete");
    println!("next: agent-remote status --online");
    println!("next: fclaude");
    Ok(())
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

    finalize_login(
        paths,
        server_url,
        user_token,
        DeviceRegistrationOptions {
            device_name: args.device_name,
            ssh_public_key: args.ssh_public_key,
            wireguard_public_key: args.wireguard_public_key,
            skip_device_registration: args.skip_device_registration,
        },
    )
    .await?;
    Ok(())
}

async fn finalize_login(
    paths: AppPaths,
    server_url: String,
    user_token: AuthToken,
    options: DeviceRegistrationOptions,
) -> Result<Option<String>> {
    paths.ensure_base_dirs()?;
    let mut config = Config::load(&paths)?;
    config.server_url = Some(server_url.clone());
    config.save(&paths)?;

    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    DependencyManager::new(paths.clone()).ensure_manifest()?;
    let secret_store = SecretStore::new(paths.clone());
    if options.skip_device_registration {
        let key = user_token_key(&server_url);
        let backend = secret_store.set_secret(&key, &user_token.access_token)?;
        state.set_kv("last_login_mode", "user_token")?;
        println!("logged in to {server_url}");
        println!("stored user token in {backend}");
        println!("token expires in {} seconds", user_token.expires_in);
        println!("device registration skipped");
        return Ok(None);
    }

    let ssh_public_key = resolve_ssh_public_key(options.ssh_public_key.as_deref())?;
    let device_name = options
        .device_name
        .unwrap_or_else(platform::default_device_name);
    let platform = platform::current_platform()?;
    let request = RegisterDeviceRequest {
        name: device_name.clone(),
        platform,
        ssh_public_key,
        wireguard_public_key: options.wireguard_public_key,
    };
    let registration = ApiClient::new(server_url.clone())?
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
    Ok(Some(device.id))
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
    write_wireguard_config(paths, args.output).await
}

async fn write_default_wireguard_config(paths: AppPaths) -> Result<()> {
    write_wireguard_config(paths, None).await
}

async fn write_wireguard_config(paths: AppPaths, output: Option<PathBuf>) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let client = ApiClient::new(server_url)?;
    let config = client.get_wireguard_config(&token).await?;
    let output = output.unwrap_or_else(|| wireguard::default_config_path(&paths));
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

async fn account_import_config(
    paths: AppPaths,
    args: crate::cli::AccountImportConfigArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let include = discover_claude_config_paths(args.include_resume_history)?;
    if include.is_empty() {
        println!("no local Claude config paths found");
        return Ok(());
    }
    println!("candidate paths:");
    for path in &include {
        println!("  {path}");
    }
    if args.include_resume_history {
        println!("resume history may include private prompts, transcripts, and local paths.");
    }
    if !args.yes
        && !args.dry_run
        && !prompt_yes_no("Import these files to the remote account now? [y/N] ")?
    {
        bail!("config import not confirmed");
    }
    let files = if args.dry_run {
        Vec::new()
    } else {
        collect_claude_config_files(&include)?
    };
    let result = ApiClient::new(server_url)?
        .create_tool_account_config_import(
            &token,
            &args.account,
            &ToolAccountConfigImportRequest {
                tool_type: args.tool,
                source: "local_cli".to_string(),
                include,
                exclude: vec![
                    "~/.claude.json".to_string(),
                    "~/.claude/cache".to_string(),
                    "~/.claude/logs".to_string(),
                    "~/.claude/transcripts".to_string(),
                ],
                files,
                include_resume_history: args.include_resume_history,
                dry_run: args.dry_run,
            },
        )
        .await?;
    println!("tool account: {}", result.tool_account_id);
    println!("dry run: {}", result.dry_run);
    println!("accepted:");
    for path in result.accepted {
        println!("  {path}");
    }
    println!("rejected:");
    for path in result.rejected {
        println!("  {path}");
    }
    for warning in result.warnings {
        println!("warning: {warning}");
    }
    if let Some(task_id) = result.task_id {
        println!("task: {task_id}");
    }
    if let Some(path) = result.account_remote_path {
        println!("remote account path: {path}");
    }
    if let Some(count) = result.imported_file_count {
        println!("files queued: {count}");
    }
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

async fn credentials_list(paths: AppPaths) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let profiles = ApiClient::new(server_url)?
        .list_developer_credential_profiles(&token)
        .await?;
    if profiles.is_empty() {
        println!("developer credential profiles: none");
        return Ok(());
    }
    for profile in profiles {
        print_developer_credential_profile(&profile);
    }
    Ok(())
}

async fn credentials_create(
    paths: AppPaths,
    args: crate::cli::CredentialsCreateArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let profile = ApiClient::new(server_url)?
        .create_developer_credential_profile(
            &token,
            &CreateDeveloperCredentialProfileRequest {
                display_name: args.name,
                git_identity: DeveloperCredentialGitIdentity {
                    user_name: args.git_user_name,
                    user_email: args.git_user_email,
                },
                github_cli: DeveloperCredentialGitHubCli { mode: args.gh_mode },
                ssh: DeveloperCredentialSsh {
                    mode: args.ssh_mode,
                },
            },
        )
        .await?;
    print_developer_credential_profile(&profile);
    Ok(())
}

async fn credentials_bind(paths: AppPaths, args: crate::cli::CredentialsBindArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    let profile = ApiClient::new(server_url)?
        .bind_developer_credential_profile(&token, &args.account, &args.profile)
        .await?;
    print_developer_credential_profile(&profile);
    Ok(())
}

async fn credentials_unbind(
    paths: AppPaths,
    args: crate::cli::CredentialsUnbindArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths)?;
    ApiClient::new(server_url)?
        .unbind_developer_credential_profile(&token, &args.account)
        .await?;
    println!(
        "developer credential profile unbound from account {}",
        args.account
    );
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
    println!(
        "runtime: {}",
        account.runtime_backend.as_deref().unwrap_or("not pinned")
    );
    if let Some(node_id) = &account.affinity_node_id {
        println!("affinity node: {node_id}");
    }
    if !account.preferred_node_tags.is_empty() {
        println!("tags: {}", account.preferred_node_tags.join(","));
    }
}

fn print_developer_credential_profile(profile: &DeveloperCredentialProfileData) {
    println!(
        "{}\t{}\t{}\tgh={}\tssh={}",
        profile.id, profile.display_name, profile.status, profile.github_cli_mode, profile.ssh_mode
    );
    if !profile.git_identity.is_null() {
        println!("git: {}", profile.git_identity);
    }
}

fn discover_claude_config_paths(include_resume_history: bool) -> Result<Vec<String>> {
    let home = home_dir()?;
    let claude = home.join(".claude");
    let mut paths = Vec::new();
    for relative in [
        "settings.json",
        "CLAUDE.md",
        "agents",
        "skills",
        "plugins",
        "hooks",
        "rules",
    ] {
        push_if_exists(&claude, relative, &mut paths);
    }
    for entry in std::fs::read_dir(&claude)
        .with_context(|| format!("failed to read {}", claude.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        if path.is_file()
            && path.extension().and_then(|value| value.to_str()) == Some("md")
            && path.file_name().and_then(|value| value.to_str()) != Some("CLAUDE.md")
        {
            if let Some(name) = path.file_name().and_then(|value| value.to_str()) {
                paths.push(format!("~/.claude/{name}"));
            }
        }
    }
    if include_resume_history {
        for relative in [
            "projects",
            "sessions",
            "history.jsonl",
            "file-history",
            "plans",
            "tasks",
            "session-env",
        ] {
            push_if_exists(&claude, relative, &mut paths);
        }
    }
    paths.sort();
    paths.dedup();
    Ok(paths)
}

fn push_if_exists(root: &Path, relative: &str, output: &mut Vec<String>) {
    if root.join(relative).exists() {
        output.push(format!("~/.claude/{relative}"));
    }
}

fn collect_claude_config_files(include: &[String]) -> Result<Vec<ToolAccountConfigImportFile>> {
    let home = home_dir()?;
    let mut files = Vec::new();
    let mut total_bytes = 0_u64;
    for path in include {
        let local_path = expand_claude_config_path(&home, path)?;
        if local_path.is_file() {
            push_config_file(&home, &local_path, &mut files, &mut total_bytes)?;
        } else if local_path.is_dir() {
            collect_config_dir(&home, &local_path, &mut files, &mut total_bytes)?;
        }
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    Ok(files)
}

fn collect_config_dir(
    home: &Path,
    dir: &Path,
    files: &mut Vec<ToolAccountConfigImportFile>,
    total_bytes: &mut u64,
) -> Result<()> {
    let mut entries = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read config directory {}", dir.display()))?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    entries.sort_by_key(|entry| entry.path());
    for entry in entries {
        let path = entry.path();
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            continue;
        }
        if file_type.is_dir() {
            collect_config_dir(home, &path, files, total_bytes)?;
        } else if file_type.is_file() {
            push_config_file(home, &path, files, total_bytes)?;
        }
    }
    Ok(())
}

fn push_config_file(
    home: &Path,
    path: &Path,
    files: &mut Vec<ToolAccountConfigImportFile>,
    total_bytes: &mut u64,
) -> Result<()> {
    let metadata = std::fs::metadata(path)
        .with_context(|| format!("failed to stat config file {}", path.display()))?;
    if metadata.len() > CONFIG_IMPORT_MAX_FILE_BYTES {
        bail!(
            "config file {} is larger than {} bytes",
            path.display(),
            CONFIG_IMPORT_MAX_FILE_BYTES
        );
    }
    *total_bytes += metadata.len();
    if *total_bytes > CONFIG_IMPORT_MAX_TOTAL_BYTES {
        bail!(
            "config import exceeds {} bytes; use --include-resume-history only for small histories",
            CONFIG_IMPORT_MAX_TOTAL_BYTES
        );
    }
    let content = std::fs::read(path)
        .with_context(|| format!("failed to read config file {}", path.display()))?;
    files.push(ToolAccountConfigImportFile {
        path: to_claude_import_path(home, path)?,
        content_base64: BASE64_STANDARD.encode(content),
        mode: 0o600,
    });
    Ok(())
}

fn expand_claude_config_path(home: &Path, path: &str) -> Result<PathBuf> {
    let suffix = path
        .strip_prefix("~/.claude/")
        .or_else(|| path.strip_prefix("$HOME/.claude/"))
        .context("only ~/.claude paths can be imported")?;
    if suffix
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("unsafe config import path: {path}");
    }
    Ok(home.join(".claude").join(suffix))
}

fn to_claude_import_path(home: &Path, path: &Path) -> Result<String> {
    let claude = home.join(".claude");
    let relative = path
        .strip_prefix(&claude)
        .with_context(|| format!("{} is outside {}", path.display(), claude.display()))?;
    let relative = relative
        .to_str()
        .context("Claude config path is not valid UTF-8")?
        .replace('\\', "/");
    if relative
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        bail!("unsafe config import path: {}", path.display());
    }
    Ok(format!("~/.claude/{relative}"))
}

fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME is not set")
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

fn prompt_line_default(prompt: &str, default: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{prompt} [{default}]: ");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

fn prompt_optional_line(prompt: &str) -> Result<Option<String>> {
    use std::io::{self, Write};

    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
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

fn prompt_yes_no_default(prompt: &str, default: bool) -> Result<bool> {
    use std::io::{self, Write};

    print!("{prompt}");
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn init_ssh_public_key(
    explicit: Option<PathBuf>,
    skip_device_registration: bool,
) -> Result<Option<PathBuf>> {
    if skip_device_registration {
        return Ok(explicit);
    }
    if explicit.is_some() {
        return Ok(explicit);
    }
    if let Some(default_path) = platform::default_ssh_public_key_path() {
        println!("using SSH public key {}", default_path.display());
        return Ok(Some(default_path));
    }
    let path = prompt_optional_line("SSH public key path: ")?;
    Ok(path.map(PathBuf::from))
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
