//! Account state selectors and independently paged immutable history.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::{identifier, uuid};
use crate::api::skill_state::{StateScope, StateSelector};

#[derive(Debug, Subcommand)]
pub enum SkillStateCommand {
    /// Review and retire eligible account history, preserving every active reference.
    Prune(StatePruneArgs),
    /// Reset selected state to its original content and advance its epoch.
    Reset(StateResetArgs),
    /// Merge unpublished-to-target state increments between two explicit revisions.
    Migrate(StateMigrateArgs),
    /// Save one conflict choice; publish atomically when the complete plan is ready.
    Resolve(StateResolveArgs),
    /// Restore a retained compatible checkpoint and advance the selected epochs.
    Restore(StateRestoreArgs),
    /// List checkpoint history and Node-only pending records with separate cursors.
    List(StateListArgs),
    /// List session publication and version migration conflicts with separate cursors.
    Conflicts(StateConflictsArgs),
    /// Inspect a checkpoint's exact source, epochs and storage location.
    Info(StateInfoArgs),
    /// Compare current state or an immutable checkpoint with its original baseline.
    Diff(StateDiffArgs),
    /// Export a retained checkpoint or an original stopped Node snapshot.
    Export(StateExportArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DirectoryScope {
    AccountDirectory,
}

#[derive(Debug, Args)]
pub struct StateScopeArgs {
    /// Skill name or stable UUID, mutually exclusive with directory scope.
    #[arg(value_name = "SKILL", value_parser = identifier, required_unless_present = "scope", conflicts_with = "scope")]
    pub skill: Option<String>,
    /// Select the complete account discovery directory.
    #[arg(long, value_enum)]
    pub scope: Option<DirectoryScope>,
    /// Complete account UUID; scope is never inferred from the local directory.
    #[arg(long, value_parser = uuid)]
    pub account_id: String,
}

impl StateScopeArgs {
    pub fn selector(&self) -> StateSelector {
        StateSelector {
            account_id: self.account_id.clone(),
            scope: if self.scope.is_some() {
                StateScope::AccountDirectory
            } else {
                StateScope::Item
            },
            skill: self.skill.clone(),
        }
    }
}

#[derive(Debug, Args)]
pub struct StateListArgs {
    #[command(flatten)]
    pub selection: StateScopeArgs,
    /// Maximum records in each independent history/pending page.
    #[arg(long, default_value = "100", value_parser = clap::value_parser!(u16).range(1..=200))]
    pub limit: u16,
    /// Continue the checkpoint page without changing account or source.
    #[arg(long, value_parser = uuid)]
    pub cursor: Option<String>,
    /// Continue the independent pending-finalization page.
    #[arg(long, value_parser = uuid)]
    pub pending_cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateInfoArgs {
    /// Complete UUID of a saved checkpoint, including an expired historical record.
    #[arg(value_name = "CHECKPOINT_ID", value_parser = uuid)]
    pub checkpoint: String,
    /// Include one page of the directory checkpoint's immutable members.
    #[arg(long)]
    pub members: bool,
    /// Maximum immutable directory members in this page.
    #[arg(long, default_value = "100", requires = "members", value_parser = clap::value_parser!(u16).range(1..=200))]
    pub limit: u16,
    /// Continue members using the previous page's next_cursor.
    #[arg(long, requires = "members", value_parser = member_cursor)]
    pub cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateConflictsArgs {
    #[command(flatten)]
    pub selection: StateScopeArgs,
    /// Maximum records in each independent conflict page.
    #[arg(long, default_value = "100", value_parser = clap::value_parser!(u16).range(1..=200))]
    pub limit: u16,
    /// Continue the session-publication conflict page.
    #[arg(long, value_parser = uuid)]
    pub cursor: Option<String>,
    /// Continue the separate migration conflict page.
    #[arg(long, value_parser = uuid)]
    pub migration_cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateDiffArgs {
    /// Skill name or stable UUID whose current branch should be compared.
    #[arg(value_name = "SKILL", value_parser = identifier, required_unless_present_any = ["scope", "checkpoint", "conflict"], conflicts_with_all = ["scope", "checkpoint", "conflict"], requires = "account_id")]
    pub skill: Option<String>,
    /// Compare the complete account directory with its directory baseline.
    #[arg(
        long,
        value_enum,
        conflicts_with_all = ["checkpoint", "conflict"],
        requires = "account_id"
    )]
    pub scope: Option<DirectoryScope>,
    /// Complete account UUID for a current-head comparison.
    #[arg(long, value_parser = uuid, required_unless_present_any = ["checkpoint", "conflict"], conflicts_with_all = ["checkpoint", "conflict"])]
    pub account_id: Option<String>,
    /// Compare the exact returned checkpoint when continuing a diff across pages.
    #[arg(long, value_parser = uuid)]
    pub checkpoint: Option<String>,
    /// Inspect the saved three sides of a publication or migration conflict.
    #[arg(long, value_parser = uuid, conflicts_with = "checkpoint")]
    pub conflict: Option<String>,
    /// Maximum changed paths in this metadata page.
    #[arg(long, default_value = "100", value_parser = clap::value_parser!(u16).range(1..=500))]
    pub limit: u16,
    /// Continue the selected checkpoint or conflict using its returned cursor verbatim.
    #[arg(long, conflicts_with_all = ["skill", "scope", "account_id"], value_parser = diff_cursor)]
    pub cursor: Option<String>,
}

#[derive(Debug, Args)]
pub struct StateExportArgs {
    /// Skill name or stable UUID that must match the selected checkpoint.
    #[arg(value_name = "SKILL", value_parser = identifier, required_unless_present = "scope", conflicts_with = "scope")]
    pub skill: Option<String>,
    /// Export an entire directory checkpoint, including cross-skill dependencies.
    #[arg(long, value_enum, requires = "account_id")]
    pub scope: Option<DirectoryScope>,
    /// For item exports, defaults to the selected checkpoint's account.
    #[arg(long, value_parser = uuid)]
    pub account_id: Option<String>,
    /// Complete UUID of a retained Server checkpoint.
    #[arg(long, value_parser = uuid, required_unless_present = "snapshot", conflicts_with = "snapshot")]
    pub checkpoint: Option<String>,
    /// Original stopped Node snapshot; requires complete account-directory scope.
    #[arg(long, value_parser = uuid, requires_all = ["scope", "account_id"], conflicts_with = "skill")]
    pub snapshot: Option<String>,
    /// Absent or empty destination for manifest.json, checkpoint.json and objects/.
    #[arg(long)]
    pub output: PathBuf,
}

fn member_cursor(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 64 || value.chars().any(char::is_control) {
        return Err("expected a member cursor from the previous page".to_owned());
    }
    Ok(value.to_owned())
}

fn diff_cursor(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 16384 || value.chars().any(char::is_control) {
        return Err("expected a diff cursor from the previous page".to_owned());
    }
    Ok(value.to_owned())
}

#[derive(Debug, Args)]
pub struct StateResetArgs {
    #[command(flatten)]
    pub selection: StateScopeArgs,
    #[command(flatten)]
    pub options: super::SkillMutationOptions,
}

#[derive(Debug, Args)]
pub struct StatePruneArgs {
    #[command(flatten)]
    pub selection: StateScopeArgs,
    /// Explicitly end waiting for unreferenced history; active protection still applies.
    #[arg(long)]
    pub all_unreferenced: bool,
    #[command(flatten)]
    pub options: super::SkillMutationOptions,
}

#[derive(Debug, Args)]
pub struct StateRestoreArgs {
    #[command(flatten)]
    pub selection: StateScopeArgs,
    /// Retained checkpoint belonging to this account, source and selected base revision.
    #[arg(long, value_parser = uuid)]
    pub checkpoint: String,
    #[command(flatten)]
    pub options: super::SkillMutationOptions,
}

#[derive(Clone, Copy, Debug, serde::Serialize, ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum ResolutionSide {
    Current,
    Incoming,
}

#[derive(Debug, Args)]
#[command(group(clap::ArgGroup::new("resolution_method").required(true).args(["use_side", "file", "directory"])))]
pub struct StateResolveArgs {
    /// Complete publication or migration conflict UUID.
    #[arg(value_name = "CONFLICT_ID", value_parser = uuid)]
    pub conflict: String,
    /// Ordinary conflict path relative to the saved discovery root.
    #[arg(long, value_parser = resolution_path, conflicts_with = "directory")]
    pub path: Option<String>,
    /// Choose a saved side, for one path or the complete conflict scope.
    #[arg(long = "use", value_enum)]
    pub use_side: Option<ResolutionSide>,
    /// Exact ordinary file replacing a file-content conflict; requires --path.
    #[arg(long, requires = "path")]
    pub file: Option<PathBuf>,
    /// Complete materialized conflict scope, not a portable checkpoint export bundle.
    #[arg(long)]
    pub directory: Option<PathBuf>,
    #[command(flatten)]
    pub options: super::SkillMutationOptions,
}

fn resolution_path(value: &str) -> Result<String, String> {
    crate::skills::manifest::validate_path(value)
        .map_err(|_| "expected a canonical relative conflict path".to_owned())?;
    Ok(value.to_owned())
}

#[derive(Debug, Args)]
pub struct StateMigrateArgs {
    /// Stable library skill name or UUID.
    #[arg(value_name = "SKILL", value_parser = identifier)]
    pub skill: String,
    /// Exact account owning both branches.
    #[arg(long, value_parser = uuid)]
    pub account_id: String,
    /// Published source revision: UUID, rN or positive registration number.
    #[arg(long, value_parser = migration_revision)]
    pub from_revision: String,
    /// Target revision: UUID, rN or positive registration number.
    #[arg(long, value_parser = migration_revision)]
    pub to_revision: String,
    #[command(flatten)]
    pub options: super::SkillMutationOptions,
}

fn migration_revision(value: &str) -> Result<String, String> {
    if let Ok(id) = uuid(value) {
        return Ok(id);
    }
    let number = value.strip_prefix('r').unwrap_or(value);
    if number.bytes().all(|b| b.is_ascii_digit()) {
        if let Ok(n) = number.parse::<i64>() {
            if n > 0 {
                return Ok(format!("r{n}"));
            }
        }
    }
    Err("expected a revision UUID or positive registration number such as r2".to_owned())
}
