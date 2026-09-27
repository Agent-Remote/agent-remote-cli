//! Source selection and atomic installation arguments.

use super::SkillMutationOptions;
use clap::Args;

#[derive(Debug, Args)]
pub struct SkillAddArgs {
    /// GitHub owner/repo, HTTPS Git repository, or local source directory.
    pub source: String,
    /// Literal branch, tag, or full commit (Git sources only).
    #[arg(long = "ref")]
    pub reference: Option<String>,
    /// Select this relative directory within the source root.
    #[arg(long, value_parser = source_subpath)]
    pub path: Option<String>,
    /// Show discovered candidates without uploading or installing.
    #[arg(long, conflicts_with_all = ["all", "skill", "dry_run", "yes", "no_wait", "timeout", "tool", "account_id"])]
    pub list: bool,
    /// Select every valid discovered skill; does not expand the installation scope.
    #[arg(long, conflicts_with = "skill")]
    pub all: bool,
    /// Select a skill name; may be repeated. --yes never substitutes for this selection.
    #[arg(long, value_parser = super::identifier)]
    pub skill: Vec<String>,
    /// Initially enable only for these tools; may be repeated.
    #[arg(long, conflicts_with = "account_id")]
    pub tool: Vec<String>,
    /// Initially enable only for this owned account.
    #[arg(long, value_parser = super::uuid)]
    pub account_id: Option<String>,
    #[command(flatten)]
    pub options: SkillMutationOptions,
}

fn source_subpath(value: &str) -> Result<String, String> {
    crate::skills::manifest::validate_path(value)
        .map(|()| value.to_owned())
        .map_err(|_| "expected a normalized relative source directory".to_owned())
}
