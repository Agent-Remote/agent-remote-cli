mod api;
mod cli;
mod config;
mod dependencies;
mod doctor;
mod local_state;
mod platform;
mod secrets;

use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use clap::Parser;
use tokio::time::sleep;

use crate::api::{ApiClient, AuthToken, RegisterDeviceRequest};
use crate::cli::{Cli, Command, DepsCommand, LoginMethod};
use crate::config::{AppPaths, Config};
use crate::dependencies::DependencyManager;
use crate::doctor::Doctor;
use crate::local_state::{LocalDevice, LocalState};
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
