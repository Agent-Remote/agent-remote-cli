//! Skill library arguments; scope identities are never inferred from local paths.

mod install;
mod mutations;
mod state;
mod updates;
pub use install::*;
pub use mutations::*;
pub use state::*;
pub use updates::*;

use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum SkillCommand {
    /// Query account state history and export retained checkpoints.
    State {
        #[command(subcommand)]
        command: SkillStateCommand,
    },
    /// Discover and atomically install selected Git or local source snapshots.
    Add(SkillAddArgs),
    /// Check tracked upstream branches without uploading or changing configuration.
    Check(SkillCheckArgs),
    /// Register or activate complete source revisions.
    Update(SkillUpdateArgs),
    /// Enable a user, tool or account rule for new sessions.
    Enable(SkillRuleArgs),
    /// Disable a rule, optionally clearing enabled overrides in every scope.
    Disable(SkillDisableArgs),
    /// Pin a retained revision for a tool or account.
    Pin(SkillPinArgs),
    /// Clear the revision pin for a tool or account.
    Unpin(SkillRuleArgs),
    /// Restore selected fields to inherited rules for a tool or account.
    Inherit(SkillInheritArgs),
    /// Archive a user-library installation without deleting running session data.
    Remove(SkillRemoveArgs),
    /// Restore a retained default revision or the previous distinct activation.
    Rollback(SkillRollbackArgs),
    /// List the authenticated user's remote skill library and optional resolved rules.
    List(SkillListArgs),
    /// Inspect a library or account-local skill by name or stable UUID.
    Info(SkillInfoArgs),
    /// Inspect an original operation, optionally waiting for its targets.
    Status(SkillStatusArgs),
    /// Retry ended transient failures using the original operation's saved plans.
    Retry(SkillRetryArgs),
}

#[derive(Debug, Args)]
pub struct SkillRetryArgs {
    /// Complete UUID of the original accepted operation.
    #[arg(value_name = "OPERATION_ID", value_parser = uuid)]
    pub operation_id: String,
    #[command(flatten)]
    pub options: SkillMutationOptions,
}

#[derive(Debug, Args)]
pub struct SkillListArgs {
    /// Explain the rules for this tool.
    #[arg(long, conflicts_with = "account_id")]
    pub tool: Option<String>,
    /// Explain this account's rules; requires --effective.
    #[arg(long, value_parser = uuid, requires = "effective")]
    pub account_id: Option<String>,
    /// Request resolved rules; this does not prove a model has loaded the skill.
    #[arg(long)]
    pub effective: bool,
    /// Read the original selection saved for this session; requires --effective.
    #[arg(long, value_parser = uuid, requires = "effective", conflicts_with_all = ["account_id", "tool"])]
    pub session: Option<String>,
    /// Include the read-only system skill catalog (inherent in effective queries).
    #[arg(long)]
    pub include_system: bool,
    /// Maximum original session members per page.
    #[arg(long, requires = "session", value_parser = clap::value_parser!(u16).range(1..=200))]
    pub limit: Option<u16>,
    /// Continue after this original session member name.
    #[arg(long, requires = "session", value_parser = identifier)]
    pub cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct SkillInfoArgs {
    /// Skill name or stable UUID.
    #[arg(value_name = "SKILL", value_parser = identifier)]
    pub skill: String,
    /// Tool whose rules should be explained.
    #[arg(long, conflicts_with = "account_id")]
    pub tool: Option<String>,
    /// Complete account UUID whose rules should be explained.
    #[arg(long, value_parser = uuid)]
    pub account_id: Option<String>,
}

#[derive(Debug, Args)]
pub struct SkillStatusArgs {
    /// Complete UUID of the original accepted operation.
    #[arg(value_name = "OPERATION_ID", value_parser = uuid, required_unless_present_any = ["last", "storage"])]
    pub operation_id: Option<String>,
    /// Recover the latest locally recorded command for this Server and user login.
    #[arg(long, conflicts_with = "operation_id")]
    pub last: bool,
    /// Inspect current user storage quotas, reservations and physical deletion progress.
    #[arg(long, conflicts_with_all = ["operation_id", "last", "wait", "timeout"])]
    pub storage: bool,
    /// Wait for completion without cancelling the remote operation on timeout.
    #[arg(long)]
    pub wait: bool,
    /// Maximum local wait duration; expiry does not cancel the remote operation.
    #[arg(long, value_name = "SECONDS", default_value = "60", requires = "wait", value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub timeout: u64,
}

pub(super) fn uuid(value: &str) -> Result<String, String> {
    uuid::Uuid::parse_str(value)
        .map(|id| id.to_string())
        .map_err(|_| "expected a complete UUID".to_owned())
}

pub(super) fn identifier(value: &str) -> Result<String, String> {
    if let Ok(id) = uuid(value) {
        return Ok(id);
    }
    if !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Ok(value.to_owned());
    }
    Err("expected a skill name or complete UUID".to_owned())
}
