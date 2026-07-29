use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::terminal::ColorChoice;

pub const VERSION: &str = match option_env!("AGENT_REMOTE_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Debug, Parser)]
#[command(
    name = "agent-remote",
    version = VERSION,
    about = "Manage remote AI workspaces, accounts, credentials, and connectivity",
    long_about = "Manage the local agent-remote client, authenticate devices, synchronize workspaces, configure network access, and operate remote AI tool accounts.",
    after_help = "Examples:\n  agent-remote init --server-url https://agent.example.com\n  agent-remote status --online\n  agent-remote account list\n  agent-remote sync ensure --yes\n  agent-remote doctor --fix"
)]
pub struct Cli {
    /// Override the agent-remote state and configuration directory.
    #[arg(long, env = "AGENT_REMOTE_HOME", global = true, value_name = "PATH")]
    pub home: Option<PathBuf>,

    /// Control colored output.
    #[arg(
        long,
        env = "AGENT_REMOTE_COLOR",
        global = true,
        value_enum,
        default_value_t = ColorChoice::Auto
    )]
    pub color: ColorChoice,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Configure a new client, authenticate, and optionally set up WireGuard.
    Init(InitArgs),
    /// Authenticate this client with an existing account.
    Login(LoginArgs),
    /// Remove local credentials and optionally revoke the remote token.
    Logout(LogoutArgs),
    /// Show local configuration and optional live server/device health.
    Status(StatusArgs),
    /// Diagnose local configuration, dependencies, credentials, and connectivity.
    Doctor(DoctorArgs),
    /// Inspect and repair managed command-line dependencies.
    #[command(subcommand)]
    Deps(DepsCommand),
    /// Generate and operate the managed WireGuard tunnel.
    #[command(subcommand)]
    Wireguard(WireGuardCommand),
    /// Validate SSH and inspect session attach authorization.
    #[command(subcommand)]
    Ssh(SshCommand),
    /// Create and operate synchronized project workspaces.
    #[command(subcommand)]
    Sync(SyncCommand),
    /// Create, bind, inspect, and select remote AI tool accounts.
    #[command(subcommand)]
    Account(AccountCommand),
    /// Manage reusable developer Git, GitHub CLI, and SSH profiles.
    #[command(subcommand)]
    Credentials(CredentialsCommand),
    /// Attach to a remote session by a unique ID prefix or full UUID.
    Attach(AttachArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    /// Control-plane URL.
    #[arg(long, env = "AGENT_REMOTE_SERVER_URL", value_name = "URL")]
    pub server_url: Option<String>,

    /// Authentication flow to use.
    #[arg(long, value_enum, default_value_t = LoginMethod::Password)]
    pub method: LoginMethod,

    /// Existing account username; prompted when omitted in password mode.
    #[arg(long, env = "AGENT_REMOTE_USERNAME", value_name = "USERNAME")]
    pub username: Option<String>,

    /// Friendly name for this local device.
    #[arg(long, value_name = "NAME")]
    pub device_name: Option<String>,

    /// SSH public key to register; defaults to a key from ~/.ssh.
    #[arg(long, value_name = "PATH")]
    pub ssh_public_key: Option<PathBuf>,

    /// Existing WireGuard public key to register.
    #[arg(long, value_name = "KEY")]
    pub wireguard_public_key: Option<String>,

    /// Store a user token without registering a device.
    #[arg(long)]
    pub skip_device_registration: bool,

    /// Do not fetch and write the initial WireGuard configuration.
    #[arg(long)]
    pub skip_wireguard_config: bool,

    /// Accept setup prompts using their recommended defaults.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct LoginArgs {
    /// Control-plane URL; uses the configured URL when omitted.
    #[arg(long, env = "AGENT_REMOTE_SERVER_URL", value_name = "URL")]
    pub server_url: Option<String>,

    /// Authentication flow to use.
    #[arg(long, value_enum, default_value_t = LoginMethod::Password)]
    pub method: LoginMethod,

    /// Account username; prompted when omitted in password mode.
    #[arg(long, env = "AGENT_REMOTE_USERNAME", value_name = "USERNAME")]
    pub username: Option<String>,

    /// Account password; prompted securely when omitted.
    #[arg(
        long,
        env = "AGENT_REMOTE_PASSWORD",
        hide_env_values = true,
        value_name = "PASSWORD"
    )]
    pub password: Option<String>,

    /// Current TOTP code when the account requires MFA.
    #[arg(
        long,
        env = "AGENT_REMOTE_TOTP_CODE",
        hide_env_values = true,
        value_name = "CODE"
    )]
    pub totp_code: Option<String>,

    /// Friendly name for this local device.
    #[arg(long, value_name = "NAME")]
    pub device_name: Option<String>,

    /// SSH public key to register; defaults to a key from ~/.ssh.
    #[arg(long, value_name = "PATH")]
    pub ssh_public_key: Option<PathBuf>,

    /// Existing WireGuard public key to register.
    #[arg(long, value_name = "KEY")]
    pub wireguard_public_key: Option<String>,

    /// Store a user token without registering a device.
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
    /// Keep the remote token active while removing local credentials.
    #[arg(long = "no-revoke-remote", default_value_t = true, action = clap::ArgAction::SetFalse)]
    pub revoke_remote: bool,
}

#[derive(Debug, Args)]
pub struct StatusArgs {
    /// Query live server health and the remote device record.
    #[arg(long)]
    pub online: bool,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Create missing local state and dependency metadata when possible.
    #[arg(long)]
    pub fix: bool,
}

#[derive(Debug, Subcommand)]
pub enum DepsCommand {
    /// Show managed dependency versions and optionally repair metadata.
    Status(DepsStatusArgs),
}

#[derive(Debug, Args)]
pub struct DepsStatusArgs {
    /// Create or refresh the managed dependency manifest before checking.
    #[arg(long)]
    pub fix: bool,
}

#[derive(Debug, Subcommand)]
pub enum WireGuardCommand {
    /// Fetch peer data and write a WireGuard configuration.
    Config(WireGuardConfigArgs),
    /// Validate the configuration and platform WireGuard tunnel tool.
    Check(WireGuardActionArgs),
    /// Show active interfaces, peers, handshakes, and transfer counters.
    Status,
    /// Bring the managed WireGuard tunnel up.
    Up(WireGuardActionArgs),
    /// Bring the managed WireGuard tunnel down.
    Down(WireGuardActionArgs),
}

#[derive(Debug, Args)]
pub struct WireGuardConfigArgs {
    /// Destination path; defaults inside the agent-remote home.
    #[arg(long, value_name = "PATH")]
    pub output: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct WireGuardActionArgs {
    /// Configuration path; defaults inside the agent-remote home.
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,

    /// Print the platform WireGuard command without changing tunnel state.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// Check the SSH client and optionally inspect a session attach command.
    Check(SshCheckArgs),
}

#[derive(Debug, Args)]
pub struct SshCheckArgs {
    /// Unique session ID prefix or full UUID for an online authorization check.
    #[arg(long, value_name = "ID")]
    pub session_id: Option<String>,
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("session_reference")
        .required(true)
        .multiple(false)
        .args(["session", "session_id"])
))]
pub struct AttachArgs {
    /// Unique session ID prefix or full UUID to attach to.
    #[arg(value_name = "SESSION")]
    pub session: Option<String>,

    /// Legacy form of the session reference; prefer the positional SESSION argument.
    #[arg(long, value_name = "ID")]
    pub session_id: Option<String>,

    /// Print the authorized SSH command without executing it.
    #[arg(long)]
    pub print_only: bool,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Register the current workspace and ensure its sync session exists.
    Ensure(SyncEnsureArgs),
    /// Show workspace, remote sync, Mutagen, and conflict status.
    Status(SyncStatusArgs),
    /// Pause synchronization for a workspace.
    Pause(SyncActionArgs),
    /// Resume synchronization for a workspace.
    Resume(SyncActionArgs),
    /// Mark conflicts resolved and resume synchronization.
    Resolve(SyncActionArgs),
    /// Reset the synchronization relationship.
    Reset(SyncActionArgs),
}

#[derive(Debug, Args)]
pub struct SyncEnsureArgs {
    /// Workspace directory; defaults to the current directory.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// Create the remote relationship without prompting.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Print local Mutagen actions without executing them.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Args)]
pub struct SyncStatusArgs {
    /// Workspace directory; defaults to the current directory.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// Return a non-zero exit status when conflicts are present.
    #[arg(long)]
    pub fail_on_conflict: bool,
}

#[derive(Debug, Args)]
pub struct SyncActionArgs {
    /// Workspace directory; defaults to the current directory.
    #[arg(long, value_name = "PATH")]
    pub workspace: Option<PathBuf>,

    /// Print local Mutagen actions without executing them.
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// List remote tool accounts in a compact table.
    List(ListArgs),
    /// Create a remote tool account.
    Create(AccountCreateArgs),
    /// Start an interactive remote login session for an account.
    Bind(AccountIdArgs),
    /// Import selected local Claude configuration into an account.
    ImportConfig(AccountImportConfigArgs),
    /// Verify the remote login state after binding.
    Verify(AccountIdArgs),
    /// Show account and binding details.
    Status(AccountIdArgs),
    /// Disable an account for future session scheduling.
    Disable(AccountIdArgs),
    /// Manage the locally selected default account per tool.
    #[command(subcommand)]
    Default(AccountDefaultCommand),
}

#[derive(Debug, Subcommand)]
pub enum AccountDefaultCommand {
    /// Select the default account used by tool launchers.
    Set(AccountDefaultSetArgs),
    /// Show the selected default account.
    Get(AccountDefaultGetArgs),
    /// Clear the selected default account.
    Clear(AccountDefaultGetArgs),
}

#[derive(Debug, Args)]
pub struct AccountCreateArgs {
    /// Tool type handled by this account.
    #[arg(long, default_value = "claude")]
    pub tool: String,

    /// Human-readable account name.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Scheduling region code, for example US or SG.
    #[arg(long, value_name = "CODE")]
    pub region: String,

    /// IANA timezone used inside remote sessions.
    #[arg(long, value_name = "ZONE")]
    pub timezone: String,

    /// Locale used inside remote sessions.
    #[arg(long, default_value = "en_US.UTF-8")]
    pub locale: String,

    /// Preferred node tag; repeat to provide multiple tags.
    #[arg(long = "tag", value_name = "TAG")]
    pub tags: Vec<String>,
}

#[derive(Debug, Args)]
pub struct AccountIdArgs {
    /// Unique tool account ID prefix or full UUID.
    #[arg(value_name = "ACCOUNT_ID")]
    pub account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountImportConfigArgs {
    /// Tool type whose local configuration should be discovered.
    #[arg(long, default_value = "claude")]
    pub tool: String,

    /// Unique destination tool account ID prefix or full UUID.
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub account: String,

    /// Include history that may contain prompts, transcripts, and local paths.
    #[arg(long)]
    pub include_resume_history: bool,

    /// Show discovered paths without reading or uploading file contents.
    #[arg(long)]
    pub dry_run: bool,

    /// Import without an interactive confirmation prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,
}

#[derive(Debug, Subcommand)]
pub enum CredentialsCommand {
    /// List developer credential profiles in a compact table.
    List(ListArgs),
    /// Create a reusable developer credential profile.
    Create(CredentialsCreateArgs),
    /// Bind a developer credential profile to a tool account.
    Bind(CredentialsBindArgs),
    /// Remove the developer credential profile from a tool account.
    Unbind(CredentialsUnbindArgs),
}

#[derive(Debug, Args)]
pub struct CredentialsCreateArgs {
    /// Human-readable profile name.
    #[arg(long, value_name = "NAME")]
    pub name: String,

    /// Git commit author name.
    #[arg(long, value_name = "NAME")]
    pub git_user_name: Option<String>,

    /// Git commit author email address.
    #[arg(long, value_name = "EMAIL")]
    pub git_user_email: Option<String>,

    /// GitHub CLI mode, such as remote_login or disabled.
    #[arg(long, default_value = "remote_login")]
    pub gh_mode: String,

    /// SSH mode, such as agent_forwarding or disabled.
    #[arg(long, default_value = "agent_forwarding")]
    pub ssh_mode: String,
}

#[derive(Debug, Args)]
pub struct CredentialsBindArgs {
    /// Unique tool account ID prefix or full UUID.
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub account: String,

    /// Unique developer credential profile ID prefix or full UUID.
    #[arg(long, value_name = "PROFILE_ID")]
    pub profile: String,
}

#[derive(Debug, Args)]
pub struct CredentialsUnbindArgs {
    /// Unique tool account ID prefix or full UUID.
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub account: String,
}

#[derive(Debug, Args)]
pub struct AccountDefaultSetArgs {
    /// Tool type whose default should be changed.
    #[arg(long, default_value = "claude")]
    pub tool: String,

    /// Unique tool account ID prefix or full UUID to select.
    #[arg(long, value_name = "ACCOUNT_ID")]
    pub account_id: String,
}

#[derive(Debug, Args)]
pub struct AccountDefaultGetArgs {
    /// Tool type whose default should be read or cleared.
    #[arg(long, default_value = "claude")]
    pub tool: String,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Show full UUIDs instead of compact 12-character IDs.
    #[arg(long)]
    pub no_trunc: bool,
}

#[cfg(test)]
mod tests {
    use clap::{Command, CommandFactory, Parser};

    use super::{AccountCommand, Cli, Command as CliCommand, CredentialsCommand};

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
    fn every_agent_remote_command_and_argument_has_help() {
        let command = Cli::command();
        command.clone().debug_assert();
        assert_documented(&command, "agent-remote");
    }

    #[test]
    fn attach_accepts_positional_and_legacy_session_references() {
        for values in [
            vec!["agent-remote", "attach", "b68873d48e07"],
            vec!["agent-remote", "attach", "--session-id", "b68873d48e07"],
        ] {
            let cli = Cli::try_parse_from(values).unwrap();
            let CliCommand::Attach(args) = cli.command else {
                panic!("expected attach command");
            };
            assert_eq!(
                args.session.or(args.session_id).as_deref(),
                Some("b68873d48e07")
            );
        }
    }

    #[test]
    fn compact_lists_support_full_id_opt_out() {
        let account =
            Cli::try_parse_from(["agent-remote", "account", "list", "--no-trunc"]).unwrap();
        assert!(matches!(
            account.command,
            CliCommand::Account(AccountCommand::List(args)) if args.no_trunc
        ));

        let credentials =
            Cli::try_parse_from(["agent-remote", "credentials", "list", "--no-trunc"]).unwrap();
        assert!(matches!(
            credentials.command,
            CliCommand::Credentials(CredentialsCommand::List(args)) if args.no_trunc
        ));
    }

    #[test]
    fn logout_revokes_by_default_and_supports_an_opt_out_flag() {
        let default = Cli::try_parse_from(["agent-remote", "logout"]).unwrap();
        assert!(matches!(
            default.command,
            CliCommand::Logout(args) if args.revoke_remote
        ));

        let opted_out =
            Cli::try_parse_from(["agent-remote", "logout", "--no-revoke-remote"]).unwrap();
        assert!(matches!(
            opted_out.command,
            CliCommand::Logout(args) if !args.revoke_remote
        ));
    }
}
