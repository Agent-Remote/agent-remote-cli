//! Side-effect-free command discovery for the native desktop client.
//!
//! This schema describes CLI syntax, not execution authorization or machine
//! operation support. Clap remains authoritative for validation.

use std::io::{self, Write};

use clap::{ArgAction, Command};
use serde::Serialize;

/// Exact, standalone discovery request. It must never initialize client state.
pub fn requested() -> bool {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    args.len() == 1 && args[0] == "--desktop-schema"
}

/// Print the versioned schema without reading configuration or secrets.
pub fn write(command: Command) -> io::Result<()> {
    let schema = describe(command);
    let stdout = io::stdout();
    let mut out = stdout.lock();
    serde_json::to_writer(&mut out, &schema)?;
    writeln!(out)
}

#[derive(Debug, Serialize)]
pub struct Schema {
    pub schema_version: u32,
    pub executable: String,
    pub cli_version: String,
    pub commands: Vec<CommandSchema>,
}

#[derive(Debug, Serialize)]
pub struct CommandSchema {
    pub path: Vec<String>,
    pub description: String,
    pub arguments: Vec<ArgumentSchema>,
    pub has_subcommands: bool,
    /// Explicitly declared client-host operating systems, never remote target OS.
    /// Absence is unknown, not an assertion that every platform is supported.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<&'static [&'static str]>,
}

#[derive(Debug, Serialize)]
pub struct ArgumentSchema {
    pub id: String,
    pub long: Option<String>,
    pub short: Option<char>,
    pub positional_index: Option<usize>,
    pub description: String,
    pub required: bool,
    pub global: bool,
    pub action: String,
    pub min_values: usize,
    pub max_values: Option<usize>,
    pub value_names: Vec<String>,
    pub choices: Vec<String>,
    pub defaults: Vec<String>,
    pub value_hint: String,
}

/// Walk the built Clap tree, including inherited global arguments and defaults.
pub fn describe(mut command: Command) -> Schema {
    command.build();
    let mut schema = Schema {
        schema_version: 1,
        executable: command.get_name().to_string(),
        cli_version: command
            .get_version()
            .unwrap_or(crate::cli::VERSION)
            .to_string(),
        commands: Vec::new(),
    };
    collect(&command, &[], &schema.executable, &mut schema.commands);
    schema
}

fn collect(command: &Command, path: &[String], executable: &str, output: &mut Vec<CommandSchema>) {
    if command.get_name() == "help" || command.is_hide_set() {
        return;
    }
    let arguments = command
        .get_arguments()
        .filter(|arg| {
            !arg.is_hide_set()
                && !matches!(
                    arg.get_action(),
                    ArgAction::Help
                        | ArgAction::HelpShort
                        | ArgAction::HelpLong
                        | ArgAction::Version
                )
        })
        .map(|arg| {
            let range = arg.get_num_args();
            ArgumentSchema {
                id: arg.get_id().to_string(),
                long: arg.get_long().map(str::to_owned),
                short: arg.get_short(),
                positional_index: arg.get_index(),
                description: arg.get_help().map(ToString::to_string).unwrap_or_default(),
                required: arg.is_required_set(),
                global: arg.is_global_set(),
                action: format!("{:?}", arg.get_action()),
                min_values: range.map(|r| r.min_values()).unwrap_or(0),
                max_values: range.map(|r| r.max_values()).filter(|n| *n != usize::MAX),
                value_names: arg
                    .get_value_names()
                    .unwrap_or_default()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
                choices: arg
                    .get_possible_values()
                    .into_iter()
                    .filter(|v| !v.is_hide_set())
                    .map(|v| v.get_name().to_owned())
                    .collect(),
                defaults: arg
                    .get_default_values()
                    .iter()
                    .map(|v| v.to_string_lossy().into_owned())
                    .collect(),
                value_hint: format!("{:?}", arg.get_value_hint()),
            }
        })
        .collect();
    output.push(CommandSchema {
        path: path.to_vec(),
        description: command
            .get_about()
            .map(ToString::to_string)
            .unwrap_or_default(),
        arguments,
        has_subcommands: command
            .get_subcommands()
            .any(|c| c.get_name() != "help" && !c.is_hide_set()),
        platforms: command_platforms(executable, path),
    });
    for child in command.get_subcommands() {
        let mut next = path.to_vec();
        next.push(child.get_name().to_string());
        collect(child, &next, executable, output);
    }
}

fn command_platforms(executable: &str, path: &[String]) -> Option<&'static [&'static str]> {
    if executable != "agent-remote" {
        return None;
    }
    let [group, action] = path else { return None };
    match (group.as_str(), action.as_str()) {
        // Every corresponding device.rs entry calls ensure_macos. Revoke and
        // rotate-token instead use the control plane and are intentionally absent.
        ("device", "install" | "uninstall" | "status" | "launch" | "diagnose") => Some(&["macos"]),
        // Upgrade always chooses ManagedBootstrap, which rejects non-macOS.
        // Setup/repair can use installed external scripts, so no family-wide claim.
        ("ego-browser", "upgrade") => Some(&["macos"]),
        // Explicit Windows tunnel/service + Unix wg-quick implementations and
        // platform-specific config permissions exist for these host platforms.
        ("deps", "mutagen-environment")
        | ("wireguard", "config" | "check" | "status" | "up" | "down") => {
            Some(&["linux", "macos", "windows"])
        }
        _ => None,
    }
}
