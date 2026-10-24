use super::*;

#[test]
fn launchctl_parser_accepts_only_bounded_expected_service_facts() {
    let output = b"system/dev.agentremote.wireguard.broker = {\n\tstate = running\n\tpid = 42\n}\n";
    assert_eq!(parse_launchctl(output), LaunchdState::Running);
    let stopped = b"system/dev.agentremote.wireguard.broker = {\n\tstate = stopped\n}\n";
    assert_eq!(parse_launchctl(stopped), LaunchdState::Stopped);
    assert_eq!(
        parse_launchctl(b"system/other = {\n\tstate = running\n}"),
        LaunchdState::Invalid
    );
    assert_eq!(
        parse_launchctl(b"system/dev.agentremote.wireguard.broker = {\n\tstate = running\n\xff"),
        LaunchdState::Invalid
    );
    assert_eq!(
        parse_launchctl(b"system/dev.agentremote.wireguard.broker = {\n\tstate = crashed\n}"),
        LaunchdState::Invalid
    );
}

#[test]
fn identity_parser_requires_fixed_bundle_id_and_a_pinned_non_adhoc_identity() {
    let team = "TeamIdentifier=TEAM123456";
    let valid = format!(
        "Executable=/Library/PrivilegedHelperTools/dev.agentremote.wireguard.broker\nIdentifier=dev.agentremote.wireguard.broker\n{team}\nAuthority=Agent Remote Community\n"
    );
    if EXPECTED_TEAM_IDENTIFIER == Some("TEAM123456") {
        assert!(identity_matches(&valid));
    } else {
        assert!(!identity_matches(&valid));
    }
    assert!(!identity_matches(
        "Identifier=dev.agentremote.wireguard.broker\nAuthority=adhoc\nTeamIdentifier=TEAM123456\n"
    ));
    assert!(!identity_matches(
        "Identifier=other.bundle\nAuthority=Agent Remote Community\nTeamIdentifier=TEAM123456\n"
    ));
}

#[test]
fn bridge_projection_never_grants_execution_or_native_ipc() {
    for state in [
        BrokerState::NotInstalled,
        BrokerState::Running,
        BrokerState::Stopped,
        BrokerState::Invalid,
        BrokerState::Unknown,
    ] {
        let projection = Observation {
            state,
            installation: FactState::Unknown,
            launchd: LaunchdState::Unknown,
            identity: FactState::Unknown,
            protocol: FactState::Unknown,
            authentication: FactState::Unknown,
        }
        .bridge_projection();
        assert_eq!(projection.protocol, "unsupported");
        assert_eq!(projection.authentication, "unavailable");
        assert_eq!(projection.execution, "unavailable");
    }
}

#[test]
fn bridge_projection_reports_native_channel_only_after_both_facts_are_confirmed() {
    let projection = Observation {
        state: BrokerState::Running,
        installation: FactState::Confirmed,
        launchd: LaunchdState::Running,
        identity: FactState::Confirmed,
        protocol: FactState::Confirmed,
        authentication: FactState::Confirmed,
    }
    .bridge_projection();
    assert_eq!(projection.protocol, "unix_socket");
    assert_eq!(projection.authentication, "kernel_peer");
    assert_eq!(projection.execution, "available");
}

fn permit(now: u64) -> ExecutionPermit {
    ExecutionPermit {
        version: IPC_PROTOCOL_VERSION,
        permit_id: "a".repeat(64),
        caller_sha256: "b".repeat(64),
        request_sha256: "c".repeat(64),
        broker_instance_sha256: "d".repeat(64),
        issued_at_unix: now,
        expires_at_unix: now + 30,
    }
}

#[test]
fn execution_permit_is_bound_to_caller_request_broker_and_single_use() {
    let mut guard = PermitReplayGuard::default();
    let accepted_permit = permit(100);
    guard
        .consume(
            &accepted_permit,
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            100,
        )
        .unwrap();
    assert_eq!(
        guard
            .consume(
                &accepted_permit,
                &"b".repeat(64),
                &"c".repeat(64),
                &"d".repeat(64),
                100
            )
            .unwrap_err()
            .to_string(),
        "wireguard_macos_broker_permit_replayed"
    );
    let mut changed = permit(100);
    changed.request_sha256 = "e".repeat(64);
    assert_eq!(
        validate_permit(
            &changed,
            &"b".repeat(64),
            &"c".repeat(64),
            &"d".repeat(64),
            100
        )
        .unwrap_err()
        .to_string(),
        "wireguard_macos_broker_permit_invalid"
    );
}

#[test]
fn execution_permit_expiry_and_shape_fail_closed() {
    let expired = permit(100);
    assert!(validate_permit(
        &expired,
        &"b".repeat(64),
        &"c".repeat(64),
        &"d".repeat(64),
        130
    )
    .is_err());
    let mut malformed = permit(100);
    malformed.permit_id.replace_range(..1, "G");
    assert!(validate_permit(
        &malformed,
        &"b".repeat(64),
        &"c".repeat(64),
        &"d".repeat(64),
        100
    )
    .is_err());
}

#[test]
fn ipc_envelope_rejects_unknown_fields_and_status_never_contains_permit() {
    let request = IpcRequest {
        version: IPC_PROTOCOL_VERSION,
        method: "status".into(),
        request_id: None,
        plan_sha256: None,
        caller_sha256: None,
        request_sha256: None,
        target_scope_sha256: None,
        action: None,
        logical_name: None,
        config_file_identity: None,
        config_content_sha256: None,
        config_public_key: None,
        config_b64: None,
    };
    let mut object = serde_json::to_value(request).unwrap();
    object["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<IpcRequest>(object).is_err());
    let response = IpcResponse {
        version: IPC_PROTOCOL_VERSION,
        ok: true,
        error: None,
        broker_instance_sha256: Some("d".repeat(64)),
        permit: None,
        operation_id: None,
        target_state: None,
    };
    let encoded = serde_json::to_value(response).unwrap();
    assert!(encoded.get("permit").is_some());
    assert!(encoded["permit"].is_null());
}
