use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "agent-remote",
    version,
    about = "Manage local agent-remote state"
)]
pub struct Cli {
    #[arg(long, env = "AGENT_REMOTE_HOME", global = true)]
    pub home: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Login(LoginArgs),
    Logout(LogoutArgs),
    Status(StatusArgs),
    Doctor(DoctorArgs),
    #[command(subcommand)]
    Deps(DepsCommand),
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    #[arg(long, env = "AGENT_REMOTE_SERVER_URL")]
    pub server_url: Option<String>,

    #[arg(long, value_enum, default_value_t = LoginMethod::Password)]
    pub method: LoginMethod,

    #[arg(long, env = "AGENT_REMOTE_USERNAME")]
    pub username: Option<String>,

    #[arg(long, env = "AGENT_REMOTE_PASSWORD", hide_env_values = true)]
    pub password: Option<String>,

    #[arg(long, env = "AGENT_REMOTE_TOTP_CODE", hide_env_values = true)]
    pub totp_code: Option<String>,

    #[arg(long)]
    pub device_name: Option<String>,

    #[arg(long)]
    pub ssh_public_key: Option<PathBuf>,

    #[arg(long)]
    pub wireguard_public_key: Option<String>,

    #[arg(long)]
    pub skip_device_registration: bool,
}

#[derive(Clone, Debug, ValueEnum)]
pub enum LoginMethod {
    Password,
    DeviceCode,
}

#[derive(Debug, Args)]
pub struct LogoutArgs {
    #[arg(long, default_value_t = true)]
    pub revoke_remote: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    #[arg(long)]
    pub online: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    #[arg(long)]
    pub fix: bool,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    Status(DepsStatusArgs),
}

#[derive(Debug, Args)]
pub struct DepsStatusArgs {
    #[arg(long)]
    pub fix: bool,
}
