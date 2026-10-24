use super::*;
use serde_json::{json, Value};

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";

fn input() -> ExactSessionAttach<'static> {
    ExactSessionAttach {
        session_id: SESSION,
        expected_server: "https://example.org",
        expected_device: DEVICE,
        print_only: false,
    }
}

fn data() -> Value {
    json!({"version":1,"session_id":SESSION,"tool_type":"claude","device_id":DEVICE,
        "node_id":"33333333-3333-4333-8333-333333333333","ssh_host":"::1","ssh_port":22,
        "ssh_user":"agent-remote","tmux_session_name":"claude-test","forward_ssh_agent":false,
        "authorization_task_id":"sync_ssh_keys:device:digest",
        "authorization_task_record_id":"44444444-4444-4444-8444-444444444444",
        "authorization_task_status":"succeeded","expires_in":300})
}

#[test]
fn exact_input_rejects_ambiguous_identity_and_unsafe_urls() {
    assert!(validation::input(&input()).is_ok());
    for id in [
        "11111111",
        "00000000-0000-0000-0000-000000000000",
        "11111111111141118111111111111111",
        "AAAAAAAA-1111-4111-8111-111111111111",
    ] {
        let mut value = input();
        value.session_id = id;
        assert!(validation::input(&value).is_err());
        let mut value = input();
        value.expected_device = id;
        assert!(validation::input(&value).is_err());
    }
    for url in [
        "file:///tmp/server",
        "https://user:password@example.org",
        "https://example.org?token=private",
        "https://example.org#fragment",
        "https://example.org\n",
        " https://example.org",
    ] {
        let mut value = input();
        value.expected_server = url;
        assert!(validation::input(&value).is_err());
    }
}

#[test]
fn strict_response_never_defaults_missing_fields_or_future_states() {
    let original = data();
    for field in original.as_object().unwrap().keys() {
        let mut missing = original.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(
            serde_json::from_value::<SessionAttachData>(missing).is_err(),
            "{field}"
        );
    }
    for state in ["future", "", "success"] {
        let mut value = original.clone();
        value["authorization_task_status"] = state.into();
        assert!(serde_json::from_value::<SessionAttachData>(value).is_err());
    }
    let mut extra = original.clone();
    extra["ssh_command"] = "untrusted".into();
    assert!(serde_json::from_value::<SessionAttachData>(extra).is_err());
    for (field, value) in [
        ("version", json!(2)),
        ("tool_type", json!("codex")),
        ("session_id", json!(DEVICE)),
        ("device_id", json!(SESSION)),
        ("node_id", json!("node")),
        (
            "authorization_task_record_id",
            json!("00000000-0000-0000-0000-000000000000"),
        ),
        ("ssh_host", json!("host;sh")),
        ("ssh_user", json!("-oProxyCommand=x")),
        ("ssh_port", json!(0)),
        ("tmux_session_name", json!("name\ncommand")),
        ("authorization_task_id", json!("task/other")),
        ("expires_in", json!(301)),
    ] {
        let mut next = original.clone();
        next[field] = value;
        let next: SessionAttachData = serde_json::from_value(next).unwrap();
        assert!(validation::response(&next, &input()).is_err(), "{field}");
    }
}

#[test]
fn every_target_field_including_record_uuid_and_forwarding_stays_frozen() {
    let original: SessionAttachData = serde_json::from_value(data()).unwrap();
    assert!(validation::response(&original, &input()).is_ok());
    let mut next = original.clone();
    next.authorization_task_status = AuthorizationStatus::Pending;
    next.expires_in = 1;
    assert!(validation::same_target(&original, &next));
    let changes: Vec<fn(&mut SessionAttachData)> = vec![
        |v| v.version = 2,
        |v| v.session_id = DEVICE.into(),
        |v| v.tool_type = "codex".into(),
        |v| v.device_id = SESSION.into(),
        |v| v.node_id = SESSION.into(),
        |v| v.ssh_host = "127.0.0.1".into(),
        |v| v.ssh_port = 2222,
        |v| v.ssh_user = "other".into(),
        |v| v.tmux_session_name = "other".into(),
        |v| v.forward_ssh_agent = true,
        |v| v.authorization_task_id = "other".into(),
        |v| v.authorization_task_record_id = SESSION.into(),
    ];
    for change in changes {
        let mut next = original.clone();
        change(&mut next);
        assert!(!validation::same_target(&original, &next));
    }
    let converted = attach(original);
    assert!(converted.ssh_command.is_empty());
    assert_eq!(
        converted.command_args,
        [
            "agent-remote-attach",
            "--session",
            SESSION,
            "--expected-device",
            DEVICE
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
