async fn init(paths: AppPaths, args: crate::cli::InitArgs) -> Result<()> {
    terminal::section("Agent Remote Setup");
    if !crate::setup::initialize(&paths)?.complete {
        bail!("local metadata preparation is incomplete; inspect setup diagnostics before retrying")
    }

    let manager = DependencyManager::new(paths.clone());
    terminal::section("Managed Dependencies");
    for status in manager.check_all()? {
        let message = format!("{} at {}", status.name, status.binary_path.display());
        if status.installed {
            terminal::success_line(message);
        } else {
            terminal::warning_line(message);
        }
    }

    let config = Config::load(&paths)?;
    let server_url = match args.server_url.or(config.server_url) {
        Some(value) => normalize_server_url(&value),
        None if args.yes => "http://127.0.0.1:8765".to_string(),
        None => normalize_server_url(&prompt_line_default("Server URL", "http://127.0.0.1:8765")?),
    };
    let client = ApiClient::new(server_url.clone())?;
    match client.healthz().await {
        Ok(health) => terminal::success_line(format!("Server reachable ({})", health.status)),
        Err(error) => terminal::warning_line(format!("Server health check failed: {error}")),
    }

    terminal::note("Sign in with an existing agent-remote user account.");
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
    let registration = DeviceRegistrationOptions {
        device_name: args.device_name,
        ssh_public_key: init_ssh_public_key(args.ssh_public_key, args.skip_device_registration)?,
        wireguard_public_key: args.wireguard_public_key,
        skip_device_registration: args.skip_device_registration,
    }
    .prepare()?;
    let user_token = match login_args.method {
        LoginMethod::Password => password_login(&client, &login_args).await?,
        LoginMethod::DeviceCode => device_code_login(&paths, &server_url, &client).await?,
    };

    let registered_device_id =
        finalize_login(paths.clone(), server_url.clone(), user_token, registration).await?;
    clear_pending_cli_login(&paths, &server_url)?;

    if !args.skip_wireguard_config && registered_device_id.is_some() {
        let should_write = args.yes
            || prompt_yes_no_default("Fetch and write WireGuard config now? [Y/n] ", true)?;
        if should_write {
            match write_default_wireguard_config(paths.clone()).await {
                Ok(()) => {}
                Err(error) => {
                    terminal::warning_line(format!("WireGuard config not written: {error}"))
                }
            }
        }
    }

    terminal::success_line("Initialization complete");
    terminal::note(format!(
        "Next: {}",
        terminal::command("agent-remote status --online")
    ));
    terminal::note(format!("Next: {}", terminal::command("fclaude")));
    Ok(())
}

async fn login(paths: AppPaths, args: crate::cli::LoginArgs) -> Result<()> {
    paths.ensure_base_dirs()?;
    let config = Config::load(&paths)?;
    let server_url = args
        .server_url
        .clone()
        .or_else(|| config.server_url.clone())
        .context("missing server URL; pass --server-url or set AGENT_REMOTE_SERVER_URL")?;
    let server_url = normalize_server_url(&server_url);
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    DependencyManager::new(paths.clone()).ensure_manifest()?;

    let client = ApiClient::new(server_url.clone())?;
    let registration = DeviceRegistrationOptions {
        device_name: args.device_name.clone(),
        ssh_public_key: args.ssh_public_key.clone(),
        wireguard_public_key: args.wireguard_public_key.clone(),
        skip_device_registration: args.skip_device_registration,
    }
    .prepare()?;
    let user_token = match args.method {
        LoginMethod::Password => password_login(&client, &args).await?,
        LoginMethod::DeviceCode => device_code_login(&paths, &server_url, &client).await?,
    };

    finalize_login(paths.clone(), server_url.clone(), user_token, registration).await?;
    clear_pending_cli_login(&paths, &server_url)?;
    Ok(())
}

async fn finalize_login(
    paths: AppPaths,
    server_url: String,
    user_token: AuthToken,
    options: auth::login::PreparedRegistration,
) -> Result<Option<String>> {
    let outcome = auth::login::finalize(&paths, &server_url, &user_token, options, None).await?;
    terminal::success_line(format!("Logged in to {server_url}"));
    if let Some(device_id) = &outcome.device_id {
        Details::new()
            .field(
                "Device",
                format!(
                    "{} ({device_id})",
                    outcome.device_name.as_deref().unwrap_or("")
                ),
            )
            .field("Credential store", outcome.backend)
            .field("Token lifetime", format!("{} seconds", outcome.expires_in))
            .render();
    } else {
        Details::new()
            .field("Credential store", outcome.backend)
            .field("Token lifetime", format!("{} seconds", outcome.expires_in))
            .field("Device", "not registered")
            .render();
    }
    Ok(outcome.device_id)
}

async fn password_login(client: &ApiClient, args: &crate::cli::LoginArgs) -> Result<AuthToken> {
    let username = match &args.username {
        Some(username) => username.clone(),
        None => prompt_line("Username: ")?,
    };
    let password = match &args.password {
        Some(password) => password.clone(),
        None => rpassword::prompt_password(terminal::prompt("Password: "))?,
    };
    client
        .login_password(&username, &password, args.totp_code.as_deref())
        .await
        .context("login failed")
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PendingCliLogin {
    server_url: String,
    completion_request_id: String,
    user_code: String,
    expires_at_unix: u64,
    interval: u64,
}

fn pending_cli_login_key(server: &str) -> String {
    format!("cli_login.pending.v1:{server}")
}

fn clear_pending_cli_login(paths: &AppPaths, server: &str) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.delete_kv(&pending_cli_login_key(server))
}

async fn device_code_login(
    paths: &AppPaths,
    server: &str,
    client: &ApiClient,
) -> Result<AuthToken> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let pending_key = pending_cli_login_key(server);
    if let Some(raw) = state.get_kv(&pending_key)? {
        let pending: PendingCliLogin = serde_json::from_str(&raw)
            .context("stored device-code completion metadata is malformed")?;
        if pending.server_url != server
            || Uuid::parse_str(&pending.completion_request_id)
                .ok()
                .is_none_or(|id| id.to_string() != pending.completion_request_id)
        {
            bail!("stored device-code completion metadata does not match this server")
        }
        if SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(true, |now| now.as_secs() >= pending.expires_at_unix)
        {
            state.delete_kv(&pending_key)?;
            bail!("CLI login expired before its completion could be recovered")
        }
        let token = client
            .recover_cli_login(&pending.completion_request_id)
            .await
            .map_err(|error| {
                if error.is_pending_cli_login() {
                    anyhow::anyhow!(
                        "CLI login completion remains pending; resume the original login"
                    )
                } else {
                    anyhow::anyhow!("CLI login completion outcome is unknown")
                }
            })?;
        drop(state);
        return Ok(token);
    }
    let completion_request_id = Uuid::new_v4().to_string();
    let start = client
        .start_cli_login(Some(&completion_request_id))
        .await?;
    terminal::section("Device Login");
    Details::new()
        .field("Open", start.verification_url)
        .field("Code", terminal::command(start.user_code.clone()))
        .status("Status", "waiting for approval")
        .render();

    state.set_kv(
        &pending_key,
        &serde_json::to_string(&PendingCliLogin {
            server_url: server.to_owned(),
            completion_request_id: completion_request_id.clone(),
            user_code: start.user_code.clone(),
            expires_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |now| now.as_secs().saturating_add(start.expires_in)),
            interval: start.interval,
        })?,
    )?;

    let deadline = Instant::now() + Duration::from_secs(start.expires_in);
    while Instant::now() < deadline {
        match client
            .complete_cli_login(&start.device_code, Some(&completion_request_id))
            .await
        {
            Ok(token) => return Ok(token),
            Err(error) if error.is_pending_cli_login() => {
                sleep(Duration::from_secs(start.interval.max(1))).await;
            }
            Err(error)
                if error.is_transport_error()
                    || error
                        .status_code()
                        .is_none_or(|status| !(400..500).contains(&status)) =>
            {
                match client.recover_cli_login(&completion_request_id).await {
                    Ok(token) => return Ok(token),
                    Err(recovery) if recovery.is_pending_cli_login() => {
                        sleep(Duration::from_secs(start.interval.max(1))).await;
                    }
                    Err(_) => return Err(error.into()),
                }
            }
            Err(error) => return Err(error.into()),
        }
    }
    drop(state);
    bail!("CLI login expired before approval")
}

async fn logout(paths: AppPaths, revoke_remote: bool) -> Result<()> {
    let outcome = auth::logout::execute(&paths, revoke_remote, None).await?;
    let Some(server_url) = &outcome.server_url else {
        terminal::note("Not logged in.");
        return Ok(());
    };
    if outcome.user.remote == auth::logout::Revocation::Unconfirmed {
        terminal::warning_line(
            "User logout could not be fully confirmed: remote revocation is unconfirmed",
        );
    }
    if outcome.device.remote == auth::logout::Revocation::Unconfirmed {
        terminal::warning_line("Remote logout failed: device revocation is unconfirmed");
    }
    if !outcome.local_complete() {
        bail!("local logout is incomplete; inspect credentials and current configuration");
    }
    terminal::success_line(format!("Logged out from {server_url}"));
    Ok(())
}

async fn status(paths: AppPaths, online: bool) -> Result<()> {
    let config = Config::load(&paths)?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;

    terminal::section("Client Status");
    let mut details = Details::new().field("Home", paths.home().display());
    details = match &config.server_url {
        Some(server_url) => details.field("Server", server_url),
        None => details.status("Server", "not configured"),
    };

    let active_device = match &config.active_device_id {
        Some(device_id) => state.get_device(device_id)?,
        None => None,
    };
    details = match &active_device {
        Some(device) => details
            .field("Device", format!("{} ({})", device.name, device.id))
            .status("Device status", device.status.clone()),
        None => details.status("Device", "not registered"),
    };
    details = match state.get_kv("last_login_mode")? {
        Some(mode) => details.field("Login mode", mode),
        None => details.status("Login mode", "unknown"),
    };

    let token_present = match (&config.server_url, &config.active_device_id) {
        (Some(server_url), Some(device_id)) => {
            has_device_token(&paths, server_url, device_id).unwrap_or(false)
        }
        (Some(server_url), None) => SecretStore::new(paths.clone())
            .get_secret(&user_token_key(server_url))
            .ok()
            .flatten()
            .is_some(),
        (None, _) => false,
    };
    details = details.status(
        "Credential",
        if token_present { "present" } else { "missing" },
    );
    details.render();

    if online {
        if let Some(server_url) = config.server_url {
            let client = ApiClient::new(server_url.clone())?;
            let health = client.healthz().await?;
            terminal::section("Live Status");
            let mut online_details = Details::new().status("Server", health.status);
            if let Some(device) = active_device {
                let (_, _, token) = load_device_token(&paths).await?;
                let remote = client.get_device(&token, &device.id).await?;
                online_details = online_details.status("Remote device", remote.status);
            }
            online_details.render();
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
    let plan = wireguard::configuration::plan(&paths, output.as_deref())?;
    let outcome = wireguard::configuration::apply(&paths, &plan).await?;
    if !outcome.complete {
        bail!("WireGuard configuration is incomplete ({}); inspect current state before confirming another attempt", outcome.code)
    }
    terminal::success_line("WireGuard configuration written");
    Details::new()
        .field("Path", outcome.output_path.display())
        .field("Device", outcome.context.active_device_id)
        .field("Peers", outcome.peer_count.unwrap_or(0))
        .render();
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
    if action == "check" {
        wireguard::check_config(&paths, &config, args.dry_run)?;
    } else {
        wireguard::run_helper(&paths, action, &config, args.dry_run)?;
    }
    terminal::success_line(format!("WireGuard {action} using {}", config.display()));
    Ok(())
}

async fn ssh_check(paths: AppPaths, args: crate::cli::SshCheckArgs) -> Result<()> {
    let version = ssh::check_ssh_available()?;
    terminal::success_line(format!("SSH available ({version})"));
    if let Some(session_id) = args.session_id {
        let (server_url, _device_id, token) = load_device_token(&paths).await?;
        let client = ApiClient::new(server_url)?;
        let session_id = resolve_session_reference(&client, &token, &session_id).await?;
        let attach = client.attach_session(&token, &session_id).await?;
        terminal::section("Attach Authorization");
        Details::new()
            .field("Session", attach.session_id)
            .field(
                "Node",
                format!("{} ({})", attach.node_id, attach.node_wireguard_ip),
            )
            .field("Tmux", attach.tmux_session_name)
            .field("Command", terminal::command(attach.ssh_command))
            .field("Task", attach.authorization_task_id)
            .field("Expires", format!("{} seconds", attach.expires_in))
            .render();
    }
    Ok(())
}

async fn attach(paths: AppPaths, args: crate::cli::AttachArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let reference = args
        .session
        .or(args.session_id)
        .context("missing session reference")?;
    let client = ApiClient::new(server_url)?;
    let session_id = resolve_session_reference(&client, &token, &reference).await?;
    let attach = client.attach_session(&token, &session_id).await?;
    terminal::section("Attach");
    Details::new()
        .field("Command", terminal::command(&attach.ssh_command))
        .field("Tmux", &attach.tmux_session_name)
        .field("Expires", format!("{} seconds", attach.expires_in))
        .render();
    if args.print_only {
        return Ok(());
    }
    let attach = client.wait_for_attach_authorization(&token, attach).await?;
    ssh::execute_attach(&paths, &attach).await
}

async fn resolve_session_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let sessions = client.list_sessions(token, None, &[]).await?;
    resolve_id(
        reference,
        "session",
        sessions.iter().map(|session| session.id.as_str()),
    )
}

async fn resolve_account_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let accounts = client.list_tool_accounts(token).await?;
    resolve_id(
        reference,
        "tool account",
        accounts.iter().map(|account| account.id.as_str()),
    )
}

async fn resolve_profile_reference(
    client: &ApiClient,
    token: &str,
    reference: &str,
) -> Result<String> {
    let profiles = client.list_developer_credential_profiles(token).await?;
    resolve_id(
        reference,
        "credential profile",
        profiles.iter().map(|profile| profile.id.as_str()),
    )
}

async fn account_list(paths: AppPaths, args: crate::cli::ListArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let accounts = ApiClient::new(server_url)?
        .list_tool_accounts(&token)
        .await?;
    if accounts.is_empty() {
        terminal::note("No tool accounts found.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "TOOL", "NAME", "STATUS", "REGION", "RUNTIME"]);
    for account in accounts {
        table.row([
            if args.no_trunc {
                account.id
            } else {
                short_id(&account.id)
            },
            account.tool_type,
            account.display_name,
            account.status,
            account.region_code,
            account.runtime_backend.unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.render();
    Ok(())
}

async fn account_create(paths: AppPaths, args: crate::cli::AccountCreateArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
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
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let binding = client
        .start_tool_account_binding(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_import_config(paths: AppPaths, args: crate::cli::AccountImportConfigArgs) -> Result<()> {
    use crate::account_import::{self, Apply, Selection, Status};
    if !(Selection{tool:args.tool.clone(),include_resume_history:args.include_resume_history,exclude_skills:args.exclude_skills}).valid() {
        bail!("configuration import currently supports only claude");
    }
    if args.status || args.forget {
        let request_id=args.request_id.as_deref().context("request ID required")?;
        let record=account_import::pending(&paths)?.items.into_iter().find(|v|v.request_id==request_id).context("original import request is not recorded in this home")?;
        let account=crate::identifiers::resolve_id(&args.account,"tool account",std::iter::once(record.account_id.as_str()))?;
        let input=Status{expected_context:record.context,account_id:account,request_id:record.request_id,expected_digest:record.digest,expected_task_id:record.task_id};
        if args.forget {
            if !args.yes && !prompt_yes_no("Forget this settled local import receipt? [y/N] ")? {bail!("receipt removal not confirmed");}
            account_import::forget(&paths,input).await?;
            terminal::success_line("Local import receipt removed");
        } else {
            let result=account_import::status(&paths,input).await?;
            Details::new().field("Request",result.request_id).field("Task",result.task_id).field("Status",result.phase).field("Files",result.file_count).render();
        }
        return Ok(());
    }
    let config=Config::load_strict(&paths)?;
    let context=crate::account_defaults::Context{home:paths.home().into(),server_url:config.server_url,active_device_id:config.active_device_id};
    let (server_url,_device_id,token)=load_device_token(&paths).await?;
    let client=ApiClient::new(server_url)?;
    let account_id=resolve_account_reference(&client,&token,&args.account).await?;
    let selection=Selection{tool:args.tool,include_resume_history:args.include_resume_history,exclude_skills:args.exclude_skills};
    let discovery=account_import::discover(&selection)?;
    if discovery.include.is_empty(){terminal::note("No supported local Claude configuration paths found.");return Ok(());}
    terminal::section("Configuration Import");
    for path in &discovery.include {println!("  {}",terminal::command(path));}
    if selection.include_resume_history {terminal::warning_line("Resume history may include private prompts, transcripts, and local paths.");}
    if args.dry_run {
        terminal::note("Checking Server policy writes an audit record; file contents are not read or uploaded.");
        let result=account_import::validate(&paths,context,&account_id,selection,discovery.source_home,discovery.include).await?;
        terminal::success_line("Configuration import preview complete");
        for path in result.accepted {println!("  {path}");}
        for path in result.rejected {terminal::warning_line(format!("Rejected: {path}"));}
        return Ok(());
    }
    let plan=account_import::prepare(&paths,context.clone(),&account_id,selection.clone(),discovery.source_home.clone()).await?;
    Details::new().field("Files",plan.manifest.len()).field("Bytes",plan.total_bytes).field("Snapshot",&plan.digest).render();
    if !args.yes && !prompt_yes_no("Import this exact file snapshot to the remote account now? [y/N] ")? {bail!("config import not confirmed");}
    let request_id=if let Some(id)=args.request_id {if !account_import::valid_uuid(&id){bail!("request ID must be a canonical nonzero UUID");}id}else{
        use rand_core::RngCore;
        let mut bytes=[0u8;16];rand_core::OsRng.fill_bytes(&mut bytes);bytes[6]=(bytes[6]&0x0f)|0x40;bytes[8]=(bytes[8]&0x3f)|0x80;uuid::Uuid::from_bytes(bytes).hyphenated().to_string()
    };
    let recovery=format!("agent-remote account import-config --account {account_id} --request-id {request_id} --status");
    terminal::note(format!("Original request: {request_id}. Recover with: {recovery}"));
    let result=account_import::apply(&paths,Apply{confirmed:true,expected_context:context,account_id:account_id.clone(),selection,expected_source_home:discovery.source_home,expected_digest:plan.digest,request_id}).await.with_context(||format!("import not confirmed; retain the original request and query: {recovery}"))?;
    terminal::success_line("Configuration import queued");
    Details::new().field("Task",&result.task_id).field("Files queued",result.file_count).render();
    let deadline=Instant::now()+CONFIG_IMPORT_WAIT_TIMEOUT;
    loop {
        let current=account_import::status(&paths,Status{expected_context:result.context.clone(),account_id:account_id.clone(),request_id:result.request_id.clone(),expected_digest:result.digest.clone(),expected_task_id:Some(result.task_id.clone())}).await?;
        match current.phase.as_str(){
            "succeeded"=>{terminal::success_line("Configuration import completed");break;},
            "failed"|"cancelled"|"expired"=>bail!("configuration import {} (task {}); query original request: {}",current.phase,current.task_id,recovery),
            _=>{},
        }
        if Instant::now()>=deadline {bail!("configuration import did not finish within {} seconds; the remote task may still continue; query: {}",CONFIG_IMPORT_WAIT_TIMEOUT.as_secs(),recovery);}
        sleep(Duration::from_secs(1)).await;
    }
    Ok(())
}

async fn account_verify(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let binding = client
        .verify_tool_account_binding(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn credentials_list(paths: AppPaths, args: crate::cli::ListArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let profiles = ApiClient::new(server_url)?
        .list_developer_credential_profiles(&token)
        .await?;
    if profiles.is_empty() {
        terminal::note("No developer credential profiles found.");
        return Ok(());
    }
    let mut table = Table::new(["ID", "NAME", "STATUS", "GITHUB CLI", "SSH"]);
    for profile in profiles {
        table.row([
            if args.no_trunc {
                profile.id
            } else {
                short_id(&profile.id)
            },
            profile.display_name,
            profile.status,
            profile.github_cli_mode,
            profile.ssh_mode,
        ]);
    }
    table.render();
    Ok(())
}

async fn credentials_create(
    paths: AppPaths,
    args: crate::cli::CredentialsCreateArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
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
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account).await?;
    let profile_id = resolve_profile_reference(&client, &token, &args.profile).await?;
    let profile = client
        .bind_developer_credential_profile(&token, &account_id, &profile_id)
        .await?;
    print_developer_credential_profile(&profile);
    Ok(())
}

async fn credentials_unbind(
    paths: AppPaths,
    args: crate::cli::CredentialsUnbindArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account).await?;
    client
        .unbind_developer_credential_profile(&token, &account_id)
        .await?;
    terminal::success_line(format!(
        "Developer credential profile unbound from account {}",
        account_id
    ));
    Ok(())
}

async fn account_status(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let account = client.get_tool_account(&token, &account_id).await?;
    print_tool_account(&account);
    let binding = client
        .get_tool_account_binding_status(&token, &account_id)
        .await?;
    print_binding_status(&binding);
    Ok(())
}

async fn account_disable(paths: AppPaths, args: crate::cli::AccountIdArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let account_id = resolve_account_reference(&client, &token, &args.account_id).await?;
    let account = client.disable_tool_account(&token, &account_id).await?;
    print_tool_account(&account);
    Ok(())
}

async fn account_default_set(
    paths: AppPaths,
    args: crate::cli::AccountDefaultSetArgs,
) -> Result<()> {
    let outcome = crate::account_defaults::set(&paths, &args.tool, &args.account_id, None, true).await?;
    let account_id = outcome.account_id.context("default account was not stored")?;
    terminal::success_line(format!(
        "Default {} account set to {}",
        args.tool, account_id
    ));
    Ok(())
}

fn account_default_get(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    match crate::account_defaults::get(&paths, &args.tool)?.account_id {
        Some(account_id) => Details::new()
            .field(format!("Default {} account", args.tool), account_id)
            .render(),
        None => terminal::note(format!("Default {} account is not set.", args.tool)),
    }
    Ok(())
}

async fn account_default_clear(paths: AppPaths, args: crate::cli::AccountDefaultGetArgs) -> Result<()> {
    crate::account_defaults::clear(&paths, &args.tool, None).await?;
    terminal::success_line(format!("Default {} account cleared", args.tool));
    Ok(())
}

fn print_tool_account(account: &ToolAccountData) {
    terminal::section("Tool Account");
    let mut details = Details::new()
        .field("Account", &account.id)
        .field("Tool", &account.tool_type)
        .field("Name", &account.display_name)
        .status("Status", account.status.clone())
        .field("Region", &account.region_code)
        .field("Timezone", &account.timezone)
        .field("Locale", &account.locale)
        .field(
            "Runtime",
            account.runtime_backend.as_deref().unwrap_or("not pinned"),
        );
    if let Some(node_id) = &account.affinity_node_id {
        details = details.field("Affinity node", node_id);
    }
    if !account.preferred_node_tags.is_empty() {
        details = details.field("Node tags", account.preferred_node_tags.join(", "));
    }
    details.render();
}

fn print_developer_credential_profile(profile: &DeveloperCredentialProfileData) {
    terminal::section("Developer Credential Profile");
    let mut details = Details::new()
        .field("Profile", &profile.id)
        .field("Name", &profile.display_name)
        .status("Status", profile.status.clone())
        .field("GitHub CLI", &profile.github_cli_mode)
        .field("SSH", &profile.ssh_mode);
    if !profile.git_identity.is_null() {
        details = details.field("Git identity", &profile.git_identity);
    }
    details.render();
}

fn print_binding_status(status: &BindingStatusData) {
    terminal::section("Account Binding");
    let mut details = Details::new().status("Status", status.status.clone());
    if let Some(node_id) = &status.node_id {
        details = details.field("Node", node_id);
    }
    if let Some(task_id) = &status.task_id {
        details = details.field("Task", task_id);
    }
    if let Some(binding_session_id) = &status.binding_session_id {
        details = details.field("Binding session", binding_session_id);
    }
    if let Some(tmux_session_name) = &status.tmux_session_name {
        details = details.field("Tmux", tmux_session_name);
    }
    if let Some(path) = &status.account_remote_path {
        details = details.field("Remote path", path);
    }
    if let Some(command) = &status.connect_command {
        details = details.field("Command", terminal::command(command));
    }
    if let Some(verifier) = &status.verifier {
        details = details.field("Verifier", verifier);
    }
    if let Some(error) = &status.error {
        details = details.field("Error", terminal::failure(error));
    }
    details.render();
}
