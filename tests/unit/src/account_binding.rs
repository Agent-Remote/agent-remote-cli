use super::*;

fn input() -> AccountAttachArgs {
    AccountAttachArgs {
        account_id: "22222222-2222-4222-8222-222222222222".into(),
        binding_session: "bind-222222222222-0123456789ab".into(),
        expected_server: None,
        expected_device: None,
    }
}

fn fixture() -> BindingAttachData {
    let input = input();
    BindingAttachData {
        version: 1,
        tool_account_id: input.account_id,
        binding_session_id: input.binding_session,
        device_id: "device-1".into(),
        node_id: "33333333-3333-4333-8333-333333333333".into(),
        ssh_host: "10.77.0.2".into(),
        ssh_port: 22,
        ssh_user: "agent-remote".into(),
        tmux_session_name: "bind-tmux".into(),
        authorization_task_id: "ssh-key-sync:device-1:digest".into(),
        authorization_task_status: "succeeded".into(),
        expires_in: 300,
    }
}

#[test]
fn binding_identity_requires_exact_account_and_attempt() {
    let input = input();
    assert!(validation::binding(
        &input.binding_session,
        &input.account_id
    ));
    for value in [
        "bind-333333333333-0123456789ab",
        "bind-222222222222-0123456789ab;sh",
        "bind-222222222222-0123456789AB",
        "",
        "bind-222222222222-中文中文",
    ] {
        assert!(!validation::binding(value, &input.account_id));
    }
    assert!(!validation::binding("whatever", &"中".repeat(11)));
    assert!(!validation::account("22222222"));
}

#[test]
fn response_rejects_changed_identity_unsafe_endpoint_and_future_states() {
    let input = input();
    assert!(validation::response(&fixture(), &input, "device-1").is_ok());
    let cases: Vec<fn(&mut BindingAttachData)> = vec![
        |v| v.version = 2,
        |v| v.tool_account_id = "other".into(),
        |v| v.binding_session_id = "other".into(),
        |v| v.device_id = "other".into(),
        |v| v.node_id = "node".into(),
        |v| v.ssh_port = 0,
        |v| v.authorization_task_status = "future".into(),
        |v| v.expires_in = 0,
    ];
    for change in cases {
        let mut value = fixture();
        change(&mut value);
        assert!(validation::response(&value, &input, "device-1").is_err());
    }
    for host in [
        "-oProxyCommand=bad",
        "host@other",
        "host;sh",
        "host\nother",
        "$(bad)",
        "host/path",
    ] {
        let mut value = fixture();
        value.ssh_host = host.into();
        assert!(validation::response(&value, &input, "device-1").is_err());
    }
    for host in ["::1", "node.example.org", "127.0.0.1"] {
        let mut value = fixture();
        value.ssh_host = host.into();
        assert!(validation::response(&value, &input, "device-1").is_ok());
    }
}

#[test]
fn polling_can_change_only_status_and_ttl_and_ssh_never_forwards_agent() {
    let original = fixture();
    let mut next = original.clone();
    next.authorization_task_status = "pending".into();
    next.expires_in = 100;
    assert!(validation::same_target(&original, &next));
    next.ssh_host = "replacement.example".into();
    assert!(!validation::same_target(&original, &next));
    let converted = attach(original);
    assert!(!converted.forward_ssh_agent);
    assert!(converted.ssh_command.is_empty());
    assert_eq!(
        converted.command_args,
        [
            "agent-remote-attach",
            "--binding",
            "22222222-2222-4222-8222-222222222222",
            "--binding-session",
            "bind-222222222222-0123456789ab"
        ]
    );
    assert!(crate::ssh::is_managed_attach(
        &converted
            .command_args
            .iter()
            .map(Into::into)
            .collect::<Vec<_>>()
    ));
}
