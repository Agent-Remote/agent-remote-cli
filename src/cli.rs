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
    #[command(subcommand)]
    Wireguard(WireGuardCommand),
    #[command(subcommand)]
    Ssh(SshCommand),
    #[command(subcommand)]
    Sync(SyncCommand),
    #[command(subcommand)]
    Account(AccountCommand),
    #[command(subcommand)]
    Credentials(CredentialsCommand),
    Attach(AttachArgs),
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

#[derive(Debug, Subcommand)]
pub enum WireGuardCommand {
    Config(WireGuardConfigArgs),
    Check(WireGuardActionArgs),
    Up(WireGuardActionArgs),
    Down(WireGuardActionArgs),
}

#[derive(Debug, Args)]
pub struct WireGuardConfigArgs {
    #[arg(long)]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct WireGuardActionArgs {
    #[arg(long)]
    pub config: Option<PathBuf>,

    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    Check(SshCheckArgs),
}

#[derive(Debug, Args)]
pub struct SshCheckArgs {
    #[arg(long)]
    pub session_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct AttachArgs {
    #[arg(long)]
    pub session_id: String,

    #[arg(long)]
    pub print_only: bool,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    Ensure(SyncEnsureArgs),
    Status(SyncStatusArgs),
    Pause(SyncActionArgs),
    Resume(SyncActionArgs),
    Resolve(SyncActionArgs),
    Reset(SyncActionArgs),
}

#[derive(Debug, Args)]
pub struct SyncEnsureArgs {
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    #[arg(long)]
    pub yes: bool,

    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct SyncStatusArgs {
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    #[arg(long)]
    pub fail_on_conflict: bool,
}

#[derive(Debug, Args)]
pub struct SyncActionArgs {
    #[arg(long)]
    pub workspace: Option<PathBuf>,

    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    List,
    Create(AccountCreateArgs),
    Bind(AccountIdArgs),
    ImportConfig(AccountImportConfigArgs),
    ExportConfig(AccountIdArgs),
    Verify(AccountIdArgs),
    Status(AccountIdArgs),
    Disable(AccountIdArgs),
    #[command(subcommand)]
    Default(AccountDefaultCommand),
}

#[derive(Debug, Subcommand)]
pub enum AccountDefaultCommand {
    Set(AccountDefaultSetArgs),
    Get(AccountDefaultGetArgs),
    Clear(AccountDefaultGetArgs),
}

#[derive(Debug, Args)]
pub struct AccountCreateArgs {
    #[arg(long, default_value = "claude")]
    pub tool: String,

    #[arg(long)]
    pub name: String,

    #[arg(long)]
    pub region: String,

    #[arg(long)]
    pub timezone: String,

    #[arg(long, default_value = "en_US.UTF-8")]
    pub locale: String,

    #[arg(long = "tag")]
    pub tags: Vec<String>,
}

#[derive(Debug, Args)]
pub struct AccountIdArgs {
    pub account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountImportConfigArgs {
    #[arg(long, default_value = "claude")]
    pub tool: String,

    #[arg(long)]
    pub account: String,

    #[arg(long)]
    pub include_resume_history: bool,

    #[arg(long)]
    pub dry_run: bool,

    #[arg(long)]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum CredentialsCommand {
    List,
    Create(CredentialsCreateArgs),
    Bind(CredentialsBindArgs),
    Unbind(CredentialsUnbindArgs),
}

#[derive(Debug, Args)]
pub struct CredentialsCreateArgs {
    #[arg(long)]
    pub name: String,

    #[arg(long)]
    pub git_user_name: Option<String>,

    #[arg(long)]
    pub git_user_email: Option<String>,

    #[arg(long, default_value = "remote_login")]
    pub gh_mode: String,

    #[arg(long, default_value = "agent_forwarding")]
    pub ssh_mode: String,
}

#[derive(Debug, Args)]
pub struct CredentialsBindArgs {
    #[arg(long)]
    pub account: String,

    #[arg(long)]
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct CredentialsUnbindArgs {
    #[arg(long)]
    pub account: String,
}

#[derive(Debug, Args)]
pub struct AccountDefaultSetArgs {
    #[arg(long, default_value = "claude")]
    pub tool: String,

    #[arg(long)]
    pub account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountDefaultGetArgs {
    #[arg(long, default_value = "claude")]
    pub tool: String,
}
