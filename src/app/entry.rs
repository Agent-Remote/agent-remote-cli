pub async fn run_entry() {
    let cli = Cli::parse();
    terminal::configure(cli.color);
    let json = cli.json;
    let skill = matches!(&cli.command, Command::Skill(_));
    let recovery = runtime_recovery_commands::RecoveryContext::from_command(&cli.command);
    // Keep the command tree out of Tokio's entry future on Windows' small main stack.
    if let Err(error) = Box::pin(run(cli)).await {
        if let Some(exit) = error.downcast_ref::<skill_commands::SkillExit>() {
            std::process::exit(exit.0);
        }
        if skill {
            skill_commands::print_failure(&error, json);
            std::process::exit(1);
        }
        if let Some(context) = recovery {
            context.print_failure(&error, json);
            std::process::exit(1);
        }
        if json {
            print_json_error(&error);
        } else {
            eprintln!("{} {error:#}", terminal::failure("ERROR"));
        }
        std::process::exit(1);
    }
}

fn print_json_error(error: &anyhow::Error) {
    println!("{}", json_error_value(error));
}

fn json_error_value(error: &anyhow::Error) -> serde_json::Value {
    let rendered = format!("{error:#}");
    let error_code = field_token(&rendered, "error_code").unwrap_or("control_plane_error");
    let phase = field_token(&rendered, "state").unwrap_or("unknown");
    let admission = field_token(&rendered, "admission").unwrap_or("unknown");
    let next_action = field_token(&rendered, "next_action").unwrap_or("repair");
    let next_command = field_between(&rendered, "next_command=", " stale=")
        .map(|value| value.split_once(" (").map_or(value, |(command, _)| command))
        .filter(|value| value.starts_with("agent-remote ") && value.is_ascii());
    let stale =
        field_token(&rendered, "stale").is_some_and(|value| value.eq_ignore_ascii_case("true"));
    // An error proves only explicit facts; all unobserved local state remains unknown.
    let definitely_uninstalled = matches!(phase, "uninstalled" | "absent");
    let execution_closed = matches!(admission, "closed" | "server_execution_closed");
    let installed = definitely_uninstalled.then_some(false);
    let enabled = definitely_uninstalled.then_some(false);
    let registered: Option<bool> = None;
    let available = (definitely_uninstalled || execution_closed).then_some(false);
    let connected = (definitely_uninstalled || execution_closed).then_some(false);
    let admission_value = serde_json::json!({
        "enrollment": if admission == "server_enrollment_closed" { "denied" } else { "unknown_or_denied" },
        "server_execution": if admission == "server_execution_closed" { "denied" } else { "unknown_or_denied" },
        "binding": "unknown",
        "local": match admission {
            "open" | "ready" | "closed" | "uninstalled" => admission,
            _ => "unknown",
        },
        "reason": if error_code == "login_required" || error_code == "server_profile_required" {
            "login"
        } else if admission.starts_with("server_") {
            "server"
        } else {
            "local"
        },
        "overall": admission,
    });
    serde_json::json!({
        "error_code": error_code,
        "state": {
            "phase": phase,
            "installed": installed,
            "enabled": enabled,
            "registered": registered,
            "available": available,
            "connected": connected,
        },
        "capability": {
            "configured_enabled": serde_json::Value::Null,
            "effective_enabled": serde_json::Value::Null,
            "node_execution_allowed": serde_json::Value::Null,
        },
        "admission": admission_value,
        "stale": stale,
        "next_action": next_action,
        "next_command": next_command,
    })
}

fn field_token<'a>(rendered: &'a str, field: &str) -> Option<&'a str> {
    rendered
        .split_whitespace()
        .find_map(|value| value.strip_prefix(&format!("{field}=")))
        .filter(|value| !value.is_empty())
}

fn field_between<'a>(rendered: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let value = rendered.split_once(start)?.1;
    let value = value.split_once(end).map_or(value, |(prefix, _)| prefix);
    (!value.is_empty()).then_some(value)
}

async fn run(cli: Cli) -> Result<()> {
    let json = cli.json;
    let paths = AppPaths::new(cli.home)?;
    match cli.command {
        Command::Skill(command) => Box::pin(skill_commands::run(paths, command, json)).await,
        Command::Init(args) => init(paths, args).await,
        Command::Login(args) => login(paths, args).await,
        Command::Logout(args) => logout(paths, args.revoke_remote).await,
        Command::Status(args) => status(paths, args.online).await,
        Command::Doctor(args) => Doctor::new(paths).run(args.fix).await,
        Command::Deps(DepsCommand::Status(args)) => deps_status(paths, args.fix),
        Command::Wireguard(WireGuardCommand::Config(args)) => wireguard_config(paths, args).await,
        Command::Wireguard(WireGuardCommand::Check(args)) => wireguard_action(paths, "check", args),
        Command::Wireguard(WireGuardCommand::Status) => wireguard::show_status(&paths),
        Command::Wireguard(WireGuardCommand::Up(args)) => wireguard_action(paths, "up", args),
        Command::Wireguard(WireGuardCommand::Down(args)) => wireguard_action(paths, "down", args),
        Command::Ssh(SshCommand::Check(args)) => ssh_check(paths, args).await,
        Command::Forward(args) => port_forward::run(&paths, &args, None).await,
        Command::Sync(SyncCommand::Ensure(args)) => sync_ensure(paths, args).await,
        Command::Sync(SyncCommand::Status(args)) => sync_status(paths, args).await,
        Command::Sync(SyncCommand::Pause(args)) => sync_action(paths, "pause", args).await,
        Command::Sync(SyncCommand::Resume(args)) => sync_action(paths, "resume", args).await,
        Command::Sync(SyncCommand::Resolve(args)) => sync_action(paths, "resolve", args).await,
        Command::Sync(SyncCommand::Reset(args)) => sync_action(paths, "reset", args).await,
        Command::Account(AccountCommand::List(args)) => account_list(paths, args).await,
        Command::Account(AccountCommand::Create(args)) => account_create(paths, args).await,
        Command::Account(AccountCommand::Bind(args)) => account_bind(paths, args).await,
        Command::Account(AccountCommand::ImportConfig(args)) => {
            account_import_config(paths, args).await
        }
        Command::Account(AccountCommand::Verify(args)) => account_verify(paths, args).await,
        Command::Account(AccountCommand::RecoverRuntime(args)) => {
            runtime_recovery_commands::submit(paths, args, cli.json).await
        }
        Command::Account(AccountCommand::RecoveryStatus(args)) => {
            runtime_recovery_commands::status(paths, args, cli.json).await
        }
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
        Command::Credentials(CredentialsCommand::List(args)) => credentials_list(paths, args).await,
        Command::Credentials(CredentialsCommand::Create(args)) => {
            credentials_create(paths, args).await
        }
        Command::Credentials(CredentialsCommand::Bind(args)) => credentials_bind(paths, args).await,
        Command::Credentials(CredentialsCommand::Unbind(args)) => {
            credentials_unbind(paths, args).await
        }
        Command::Device(DeviceCommand::Install(args)) => device::install(&args.source),
        Command::Device(DeviceCommand::Uninstall(args)) => device_uninstall(args),
        Command::Device(DeviceCommand::Status) => device::status(),
        Command::Device(DeviceCommand::Launch) => device::launch(&paths),
        Command::Device(DeviceCommand::Diagnose) => device::diagnose(),
        Command::Device(DeviceCommand::Revoke(args)) => device_revoke(paths, args).await,
        Command::Device(DeviceCommand::RotateToken(args)) => device_rotate_token(paths, args).await,
        Command::Node(NodeCommand::Install(args)) => node_install(paths, args).await,
        Command::EgoBrowser(command) => ego_browser::run(paths, command, json).await,
        Command::Attach(args) => attach(paths, args).await,
    }
}

