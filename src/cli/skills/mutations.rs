//! Explicit library change scopes and local confirmation/wait options.

use clap::{Args, ValueEnum};

#[derive(Clone, Debug, Args)]
pub struct SkillMutationOptions {
    /// Preview the exact change without committing it or creating a mutation journal.
    #[arg(long)]
    pub dry_run: bool,
    /// Confirm the displayed change without an interactive prompt.
    #[arg(long, short = 'y')]
    pub yes: bool,
    /// Return after durable Server acceptance without waiting for deployment.
    #[arg(long, conflicts_with = "timeout")]
    pub no_wait: bool,
    /// Wait at most this many seconds after acceptance; timeout does not cancel the operation.
    #[arg(long, default_value = "60", value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..=86400))]
    pub timeout: u64,
}

#[derive(Clone, Debug, Args)]
pub struct SkillRuleArgs {
    /// Skill name or stable user-library UUID.
    #[arg(value_name = "SKILL", value_parser = super::identifier)]
    pub skill: String,
    /// Apply an override to this tool; may be repeated for several tools.
    #[arg(long, conflicts_with = "account_id")]
    pub tool: Vec<String>,
    /// Apply an override to this exact account UUID.
    #[arg(long, value_parser = super::uuid)]
    pub account_id: Option<String>,
    #[command(flatten)]
    pub options: SkillMutationOptions,
}

#[derive(Debug, Args)]
pub struct SkillDisableArgs {
    #[command(flatten)]
    pub rule: SkillRuleArgs,
    /// Disable the default and clear enabled overrides while preserving revision pins.
    #[arg(long, conflicts_with_all = ["tool", "account_id"])]
    pub all_scopes: bool,
}

#[derive(Debug, Args)]
pub struct SkillPinArgs {
    #[command(flatten)]
    pub rule: SkillRuleArgs,
    /// Retained revision UUID or library number such as r2.
    #[arg(long, value_parser = revision)]
    pub revision: String,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum SkillInheritField {
    Enabled,
    Revision,
    All,
}

#[derive(Debug, Args)]
pub struct SkillInheritArgs {
    #[command(flatten)]
    pub rule: SkillRuleArgs,
    /// Restore the enabled field, revision pin or both to inheritance.
    #[arg(long, value_enum, default_value = "all")]
    pub field: SkillInheritField,
}

#[derive(Clone, Debug, Args)]
pub struct SkillRemoveArgs {
    /// Skill name or stable user-library UUID.
    #[arg(value_name = "SKILL", value_parser = super::identifier)]
    pub skill: String,
    #[command(flatten)]
    pub options: SkillMutationOptions,
}

#[derive(Debug, Args)]
pub struct SkillRollbackArgs {
    #[command(flatten)]
    pub target: SkillRemoveArgs,
    /// Retained revision UUID or library number; omission uses activation history.
    #[arg(long, value_parser = revision)]
    pub revision: Option<String>,
}

fn revision(value: &str) -> Result<String, String> {
    if let Ok(id) = super::uuid(value) {
        return Ok(id);
    }
    if value.strip_prefix('r').is_some_and(|n| {
        !n.is_empty()
            && n.bytes().all(|b| b.is_ascii_digit())
            && n.parse::<i64>().is_ok_and(|n| n > 0)
    }) {
        return Ok(value.to_owned());
    }
    Err("expected a revision UUID or library number such as r2".to_owned())
}
