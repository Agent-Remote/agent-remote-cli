use super::*;

fn peer() -> DbusPeerObservation {
    DbusPeerObservation {
        sender: ":1.42".into(),
        uid: 1000,
        pid: 4242,
        start_time_ticks: 987654,
    }
}

fn observation() -> CallerObservation {
    CallerObservation {
        peer: peer(),
        authorization: PolkitAuthorizationObservation {
            action: POLKIT_ACTION.into(),
            subject_kind: "unix-process".into(),
            subject_uid: 1000,
            subject_pid: 4242,
            subject_start_time_ticks: 987654,
            result: "yes".into(),
            challenge: false,
            checked_at_unix: 1_000,
            expires_at_unix: 1_030,
        },
    }
}

#[test]
fn status_is_explicitly_unavailable_without_a_native_broker() {
    let status = status();
    assert_eq!(status.version, 1);
    assert_eq!(status.transport, "dbus-system");
    assert_eq!(status.state, "unavailable");
    assert_eq!(status.installation, "not_installed");
    assert_eq!(status.authorization, "unavailable");
    assert_eq!(status.authentication, "unavailable");
    assert_eq!(status.execution, "unavailable");
    assert_eq!(status.reason, "native_broker_unavailable");
}

#[test]
fn authentication_binds_sender_uid_pid_and_process_start() {
    let first = authenticate(&observation(), 1_001).unwrap();
    assert_eq!(first.sender, ":1.42");
    assert_eq!(first.caller_sha256.len(), 64);

    let mut changed = observation();
    changed.peer.sender = ":1.43".into();
    changed.authorization.subject_pid = changed.peer.pid;
    let second = authenticate(&changed, 1_001).unwrap();
    assert_ne!(first.caller_sha256, second.caller_sha256);

    let mut reused_pid = observation();
    reused_pid.peer.start_time_ticks += 1;
    assert_eq!(
        authenticate(&reused_pid, 1_001).unwrap_err().0,
        "wireguard_linux_broker_identity_mismatch"
    );
}

#[test]
fn same_uid_without_an_independent_polkit_grant_is_never_authorized() {
    let mut unauthorized = observation();
    unauthorized.authorization.result = "no".into();
    assert_eq!(
        authenticate(&unauthorized, 1_001).unwrap_err().0,
        "wireguard_linux_broker_unauthorized"
    );

    let mut challenge = observation();
    challenge.authorization.challenge = true;
    assert_eq!(
        authenticate(&challenge, 1_001).unwrap_err().0,
        "wireguard_linux_broker_unauthorized"
    );
}

#[test]
fn authorization_must_bind_exact_process_and_short_lived_result() {
    let mut mismatch = observation();
    mismatch.authorization.subject_uid = 0;
    assert_eq!(
        authenticate(&mismatch, 1_001).unwrap_err().0,
        "wireguard_linux_broker_identity_mismatch"
    );

    let mut expired = observation();
    expired.authorization.expires_at_unix = 1_001;
    assert_eq!(
        authenticate(&expired, 1_001).unwrap_err().0,
        "wireguard_linux_broker_authorization_expired"
    );

    let mut long_lived = observation();
    long_lived.authorization.expires_at_unix = 1_031;
    assert_eq!(
        authenticate(&long_lived, 1_001).unwrap_err().0,
        "wireguard_linux_broker_unauthorized"
    );
}

#[test]
fn sender_and_observation_shape_are_strict() {
    for sender in ["org.example.Client", ":2.1", ":1.", ":1.42/extra"] {
        let mut invalid = observation();
        invalid.peer.sender = sender.into();
        assert_eq!(
            authenticate(&invalid, 1_001).unwrap_err().0,
            "wireguard_linux_broker_invalid_observation"
        );
    }

    let mut invalid = observation();
    invalid.peer.pid = 0;
    assert_eq!(
        authenticate(&invalid, 1_001).unwrap_err().0,
        "wireguard_linux_broker_invalid_observation"
    );

    let mut value = serde_json::to_value(observation()).unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<CallerObservation>(value).is_err());
}

#[test]
fn dbus_wire_envelope_never_carries_a_caller_identity() {
    let request = ExecuteWireRequest {
        version: WIRE_PROTOCOL_VERSION,
        request_id: "a".repeat(64),
        plan_sha256: "b".repeat(64),
        target_scope_sha256: "c".repeat(64),
        action: "up".into(),
        logical_name: "agent-remote".into(),
        config: super::super::inspection::ConfigBinding {
            file_identity: "d".repeat(64),
            content_sha256: "e".repeat(64),
            public_key: "A".repeat(43) + "=",
        },
        config_bytes: b"[Interface]\n".to_vec(),
    };
    let value = serde_json::to_value(request).unwrap();
    assert!(value.get("caller_sha256").is_none());
    assert!(value.get("uid").is_none());
    assert_eq!(value["version"], WIRE_PROTOCOL_VERSION);
    assert_eq!(
        value["config_bytes"],
        serde_json::json!([91, 73, 110, 116, 101, 114, 102, 97, 99, 101, 93, 10])
    );
}

#[test]
fn status_wire_rejects_unknown_or_wrong_identity() {
    let mut value = serde_json::to_value(StatusWire {
        version: PROTOCOL_VERSION,
        platform: "linux".into(),
        transport: "dbus-system".into(),
        bus_name: BUS_NAME.into(),
        interface: INTERFACE.into(),
        object_path: OBJECT_PATH.into(),
        polkit_action: POLKIT_ACTION.into(),
        state: "unavailable".into(),
        installation: "not_installed".into(),
        authorization: "unavailable".into(),
        authentication: "unavailable".into(),
        execution: "unavailable".into(),
        reason: "native_broker_unavailable".into(),
    })
    .unwrap();
    value["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<StatusWire>(value).is_err());
}
