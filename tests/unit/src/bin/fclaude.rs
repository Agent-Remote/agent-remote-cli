// Tests for src/bin/fclaude.rs.

#[test]
fn resumed_session_explains_unapplied_arguments_without_echoing_values() {
    assert!(super::resumed_arguments_notice(&[]).is_none());
    let message =
        super::resumed_arguments_notice(&["--model".into(), "private-value".into()]).unwrap();
    assert!(message.contains("not applied"));
    assert!(message.contains("fclaude new"));
    assert!(!message.contains("private-value"));
}

use super::{compact_workdir, DeleteTarget, FClaudeCli, Mode, SessionListArgs};
use clap::{Command, CommandFactory, Parser};

fn parse_args(values: &[&str]) -> super::FClaudeArgs {
    FClaudeCli::try_parse_from(std::iter::once("fclaude").chain(values.iter().copied()))
        .unwrap()
        .into_args()
}

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
fn every_fclaude_command_and_argument_has_help() {
    let command = FClaudeCli::command();
    command.clone().debug_assert();
    assert_documented(&command, "fclaude");
}

#[test]
fn parses_direct_passthrough_flags() {
    let args = parse_args(&["--model", "opus"]);
    assert_eq!(args.mode, Mode::Run);
    assert_eq!(args.claude_args, vec!["--model", "opus"]);
}

#[test]
fn parses_double_dash_passthrough_flags() {
    let args = parse_args(&["--", "--model", "opus"]);
    assert_eq!(args.mode, Mode::Run);
    assert_eq!(args.claude_args, vec!["--model", "opus"]);
}

#[test]
fn global_options_preserve_claude_passthrough() {
    for values in [
        vec!["--model", "opus"],
        vec!["--", "stop", "prompt text"],
        vec!["prompt", "new", "stop"],
    ] {
        let expected = parse_args(&values);
        let actual = parse_args(
            &["--home", "/tmp/launcher-contract"]
                .into_iter()
                .chain(values)
                .collect::<Vec<_>>(),
        );
        assert_eq!(actual.mode, Mode::Run);
        assert_eq!(actual.claude_args, expected.claude_args);
    }
}

#[test]
fn parses_attach_mode() {
    let args = parse_args(&["attach", "01234567"]);
    assert_eq!(args.mode, Mode::Attach("01234567".into()));
}

#[test]
fn global_options_preserve_explicit_session_commands() {
    for command in [
        vec!["stop", "01234567", "--timeout", "5"],
        vec!["stop-status", "original-operation", "--wait"],
        vec!["new", "--", "--model", "sonnet"],
        vec!["delete", "01234567"],
        vec!["list", "--running"],
        vec!["attach", "01234567"],
    ] {
        let expected = parse_args(&command);
        let values: Vec<_> = ["--home", "/tmp/launcher-contract", "--color", "never"]
            .into_iter()
            .chain(command)
            .collect();
        let actual = parse_args(&values);
        assert_eq!(actual.mode, expected.mode);
        assert_eq!(actual.claude_args, expected.claude_args);
    }
}

#[test]
fn parses_single_and_bulk_delete_modes() {
    let single = parse_args(&["delete", "01234567"]);
    assert_eq!(
        single.mode,
        Mode::Delete(DeleteTarget::Session("01234567".into()))
    );

    let bulk = parse_args(&["delete", "--all"]);
    assert_eq!(bulk.mode, Mode::Delete(DeleteTarget::AllInactive));
}

#[test]
fn parses_list_status_shortcuts() {
    let args = parse_args(&["list", "--running", "--stopped"]);
    assert_eq!(
        args.mode,
        Mode::List(SessionListArgs {
            statuses: vec!["running".into(), "stopped".into()],
            no_trunc: false,
        })
    );
}

#[test]
fn parses_repeatable_explicit_list_status() {
    let args = parse_args(&["list", "--status", "active", "--status", "failed"]);
    assert_eq!(
        args.mode,
        Mode::List(SessionListArgs {
            statuses: vec!["active".into(), "failed".into()],
            no_trunc: false,
        })
    );
}

#[test]
fn parses_untruncated_list_mode() {
    let args = parse_args(&["list", "--no-trunc"]);
    assert_eq!(
        args.mode,
        Mode::List(SessionListArgs {
            statuses: vec![],
            no_trunc: true,
        })
    );
}

#[test]
fn keeps_unix_workdir_components_when_compacted() {
    assert_eq!(compact_workdir("/one/two/three/project", 16), ".../project");
}

#[test]
fn keeps_windows_drive_and_workdir_components_when_compacted() {
    assert_eq!(
        compact_workdir(r"D:\Coding\Code\Project\BilibiliShowOrder\FuckBili", 44),
        r"D:\...\Project\BilibiliShowOrder\FuckBili"
    );
}

#[test]
fn leaves_short_windows_workdir_unchanged() {
    assert_eq!(
        compact_workdir(r"C:\Users\rem\project", 44),
        r"C:\Users\rem\project"
    );
}

#[test]
fn keeps_unc_marker_and_components_when_compacted() {
    assert_eq!(
        compact_workdir(
            r"\\build-server\workspace\Project\BilibiliShowOrder\FuckBili",
            44
        ),
        r"\\...\Project\BilibiliShowOrder\FuckBili"
    );
}

#[test]
fn keeps_relative_windows_workdir_components_when_compacted() {
    assert_eq!(
        compact_workdir(r"workspace\Code\Project\BilibiliShowOrder\FuckBili", 40),
        r"...\Project\BilibiliShowOrder\FuckBili"
    );
}

#[test]
fn bounds_a_workdir_with_a_long_final_component() {
    let compacted = compact_workdir(
        r"C:\Users\rem\this-project-name-is-longer-than-the-column",
        20,
    );
    assert_eq!(compacted.chars().count(), 20);
    assert!(compacted.starts_with("..."));
}
