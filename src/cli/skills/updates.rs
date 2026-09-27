//! Source checks and explicit single/batch update selection.
use super::SkillMutationOptions;
use clap::Args;

#[derive(Debug, Args)]
pub struct SkillCheckArgs {
    /// Check this user-library skill; omission checks all active installations.
    #[arg(value_parser = super::identifier)]
    pub skill: Option<String>,
}

#[derive(Debug, Args)]
pub struct SkillUpdateArgs {
    /// User-library skill name or stable UUID.
    #[arg(value_parser = super::identifier, required_unless_present = "all", conflicts_with = "all")]
    pub skill: Option<String>,
    /// Update tracked branches independently; fixed and local sources are reported and skipped.
    #[arg(long, conflicts_with_all = ["reference", "from", "stage"])]
    pub all: bool,
    /// Explicitly select a branch, tag or full commit and switch upstream tracking on activation.
    #[arg(long = "ref", conflicts_with = "from")]
    pub reference: Option<String>,
    /// Complete local skill directory for an installed local source.
    #[arg(long)]
    pub from: Option<std::path::PathBuf>,
    /// Register one candidate revision without changing the default or account state.
    #[arg(long)]
    pub stage: bool,
    #[command(flatten)]
    pub options: SkillMutationOptions,
}
