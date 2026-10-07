// Tests for src/cli.rs.

use clap::{Command, CommandFactory, Parser};

use super::{
    AccountCommand, Cli, Command as CliCommand, CredentialsCommand, DeviceCommand,
    EgoBrowserCommand,
};

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
fn forward_accepts_start_list_and_stop_forms() {
    let start =
        Cli::try_parse_from(["agent-remote", "forward", "5173", "--local-port", "auto"]).unwrap();
    let CliCommand::Forward(start) = start.command else {
        panic!("expected forward command")
    };
    assert_eq!(start.remote_port, Some(5173));
    assert_eq!(start.local_port, "auto");

    let list = Cli::try_parse_from(["agent-remote", "forward", "list"]).unwrap();
    let CliCommand::Forward(list) = list.command else {
        panic!("expected forward list command")
    };
    assert!(matches!(list.action, Some(super::ForwardAction::List)));

    let stop = Cli::try_parse_from(["agent-remote", "forward", "stop", "forward-1"]).unwrap();
    let CliCommand::Forward(stop) = stop.command else {
        panic!("expected forward stop command")
    };
    assert!(matches!(stop.action, Some(super::ForwardAction::Stop(_))));
}

#[test]
fn device_commands_require_explicit_install_source_and_support_removal() {
    let install = Cli::try_parse_from([
        "agent-remote",
        "device",
        "install",
        "--source",
        "/tmp/Agent Remote Device.app",
    ])
    .unwrap();
    assert!(matches!(
        install.command,
        CliCommand::Device(DeviceCommand::Install(args))
            if args.source == std::path::Path::new("/tmp/Agent Remote Device.app")
    ));
    assert!(Cli::try_parse_from(["agent-remote", "device", "install"]).is_err());

    let archive = Cli::try_parse_from([
        "agent-remote",
        "device",
        "install",
        "--source",
        "/tmp/agent-remote-device-macos-1.2.3.zip",
    ])
    .unwrap();
    assert!(matches!(
        archive.command,
        CliCommand::Device(DeviceCommand::Install(args))
            if args.source == std::path::Path::new(
                "/tmp/agent-remote-device-macos-1.2.3.zip"
            )
    ));

    let uninstall = Cli::try_parse_from(["agent-remote", "device", "uninstall", "--yes"]).unwrap();
    assert!(matches!(
        uninstall.command,
        CliCommand::Device(DeviceCommand::Uninstall(args)) if args.yes
    ));

    let revoke = Cli::try_parse_from([
        "agent-remote",
        "device",
        "revoke",
        "--device",
        "device-id",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        revoke.command,
        CliCommand::Device(DeviceCommand::Revoke(args))
            if args.device.as_deref() == Some("device-id") && args.yes
    ));

    let rotate = Cli::try_parse_from(["agent-remote", "device", "rotate-token", "--yes"]).unwrap();
    assert!(matches!(
        rotate.command,
        CliCommand::Device(DeviceCommand::RotateToken(args)) if args.yes
    ));
}

#[test]
fn ego_browser_commands_separate_control_from_device_authorization() {
    let register = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "register",
        "--server-url",
        "https://example.test",
        "--signer-certificate-sha256",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ])
    .unwrap();
    assert!(matches!(
        register.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::Register(args))
            if args.server_url.as_deref() == Some("https://example.test")
                && args.signer_certificate_sha256.as_deref()
                    == Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    ));

    let claim = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "claim",
        "11111111-2222-3333-4444-555555555555",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        claim.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::Claim(args))
            if args.yes && args.tool_session == "11111111-2222-3333-4444-555555555555"
    ));

    let pause = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "pause",
        "aabbccdd",
        "--generation",
        "7",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        pause.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::Pause(args))
            if args.binding.as_deref() == Some("aabbccdd") && args.generation == 7 && args.yes
    ));

    let requests = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "requests",
        "aabbccdd",
        "--no-trunc",
    ])
    .unwrap();
    assert!(matches!(
        requests.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::Requests(args))
            if args.binding == "aabbccdd" && args.no_trunc
    ));

    let cancel = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "cancel-request",
        "aabbccdd",
        "11223344",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        cancel.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::CancelRequest(args))
            if args.binding == "aabbccdd" && args.request == "11223344" && args.yes
    ));

    let delete_device = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "delete-device",
        "aabbccdd",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        delete_device.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::DeleteDevice(args))
            if args.id == "aabbccdd" && args.yes
    ));

    let delete_binding =
        Cli::try_parse_from(["agent-remote", "ego-browser", "binding-delete", "aabbccdd"]).unwrap();
    assert!(matches!(
        delete_binding.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::DeleteBinding(args))
            if args.id == "aabbccdd" && !args.yes
    ));

    let resume = Cli::try_parse_from(["agent-remote", "ego-browser", "resume"]).unwrap();
    assert!(matches!(
        resume.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::Resume(args))
            if args.binding.is_none() && args.generation == 0 && !args.yes
    ));

    let re_enroll =
        Cli::try_parse_from(["agent-remote", "ego-browser", "re-enroll", "--yes"]).unwrap();
    assert!(matches!(
        re_enroll.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::ReEnroll(args)) if args.yes
    ));

    let device_rotate =
        Cli::try_parse_from(["agent-remote", "ego-browser", "device-rotate", "--yes"]).unwrap();
    assert!(matches!(
        device_rotate.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::DeviceRotate(args)) if args.yes
    ));

    let switch_server = Cli::try_parse_from([
        "agent-remote",
        "ego-browser",
        "switch-server",
        "--server-url",
        "https://new.example.test",
        "--yes",
    ])
    .unwrap();
    assert!(matches!(
        switch_server.command,
        CliCommand::EgoBrowser(EgoBrowserCommand::SwitchServer(args))
            if args.server_url == "https://new.example.test" && args.yes
    ));
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
    let account = Cli::try_parse_from(["agent-remote", "account", "list", "--no-trunc"]).unwrap();
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

    let opted_out = Cli::try_parse_from(["agent-remote", "logout", "--no-revoke-remote"]).unwrap();
    assert!(matches!(
        opted_out.command,
        CliCommand::Logout(args) if !args.revoke_remote
    ));
}

#[test]
fn global_json_flag_is_accepted_before_or_after_lifecycle_commands() {
    let before = Cli::try_parse_from(["agent-remote", "--json", "ego-browser", "status"]).unwrap();
    assert!(before.json);
    let after = Cli::try_parse_from(["agent-remote", "ego-browser", "status", "--json"]).unwrap();
    assert!(after.json);
}
