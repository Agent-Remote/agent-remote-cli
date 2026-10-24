use base64::{engine::general_purpose::STANDARD, Engine};

use super::*;

fn key() -> String {
    crate::wireguard::public_key_from_private(&STANDARD.encode([7; 32])).unwrap()
}

fn present() -> TargetObservation {
    let identity = if cfg!(target_os = "linux") {
        TargetIdentity::LinuxInterface {
            name: "client".into(),
            index: 12,
            namespace: "a".repeat(64),
            public_key: Some(key()),
        }
    } else if cfg!(target_os = "macos") {
        TargetIdentity::MacosInterface {
            name: "utun12".into(),
            index: 12,
            mapping_identity: "a".repeat(64),
            socket_identity: "b".repeat(64),
            public_key: Some(key()),
        }
    } else {
        TargetIdentity::WindowsService {
            service_name: "WireGuardTunnel$client".into(),
            binary_path: r"C:\WireGuard\wireguard.exe".into(),
            config_path: r"C:\WireGuard\client.conf".into(),
            config_identity: Some("a".repeat(64)),
            service_state: 4,
            start_type: 2,
            account: "LocalSystem".into(),
            public_key: Some(key()),
        }
    };
    TargetObservation {
        logical_name: "client".into(),
        state: TargetState::Present,
        reason: None,
        status_state: "observed".into(),
        identity: Some(identity),
    }
}

fn set_key(observation: &mut TargetObservation, key: Option<String>) {
    match observation.identity.as_mut().unwrap() {
        TargetIdentity::LinuxInterface { public_key, .. }
        | TargetIdentity::MacosInterface { public_key, .. }
        | TargetIdentity::WindowsService { public_key, .. } => *public_key = key,
    }
}
fn empty(state: TargetState, reason: Option<TargetReason>) -> TargetObservation {
    TargetObservation {
        logical_name: "client".into(),
        state,
        reason,
        status_state: "not_queried".into(),
        identity: None,
    }
}

#[test]
fn observed_target_allows_unconfigured_keys_and_partial_queries_without_claiming_success() {
    let mut observed = present();
    assert!(valid(&observed));
    set_key(&mut observed, None);
    assert!(valid(&observed));
    observed.reason = Some(TargetReason::TargetNotInStatus);
    assert!(valid(&observed));
    for status in [
        "tool_missing",
        "tool_not_executable",
        "query_failed",
        "timed_out",
        "output_too_large",
        "invalid_output",
    ] {
        observed.status_state = status.into();
        observed.reason = Some(TargetReason::StatusUnavailable);
        assert!(valid(&observed));
    }
}

#[test]
fn inconsistent_present_reason_status_or_key_is_rejected() {
    for (status, reason) in [
        ("not_queried", None),
        ("unknown", None),
        ("query_failed", None),
        ("query_failed", Some(TargetReason::StatusUnavailable)),
        ("observed", Some(TargetReason::StatusUnavailable)),
        ("observed", Some(TargetReason::TargetNotInStatus)),
        ("observed", Some(TargetReason::NativeQueryFailed)),
    ] {
        let mut observation = present();
        observation.status_state = status.into();
        observation.reason = reason;
        assert!(!valid(&observation), "accepted {status} {reason:?}");
    }
    for key in [
        "bad".into(),
        STANDARD.encode([0; 32]),
        format!("{}\n", key()),
    ] {
        let mut observation = present();
        set_key(&mut observation, Some(key));
        assert!(!valid(&observation));
    }
    let mut observation = present();
    observation.identity = None;
    assert!(!valid(&observation));
}

#[test]
fn unknown_absent_conflict_and_invalid_names_have_exact_platform_combinations() {
    let unknown = empty(TargetState::Unknown, Some(TargetReason::NativeQueryFailed));
    assert!(valid(&unknown));
    assert!(!valid(&empty(TargetState::Unknown, None)));
    for reason in [
        TargetReason::MappingMissing,
        TargetReason::MappingUnsafe,
        TargetReason::MappingStale,
    ] {
        assert_eq!(
            valid(&empty(TargetState::Unknown, Some(reason))),
            cfg!(target_os = "macos")
        );
    }
    assert_eq!(
        valid(&empty(TargetState::Absent, None)),
        !cfg!(target_os = "macos")
    );
    for reason in [
        TargetReason::InterfaceNotWireguard,
        TargetReason::ServiceInvalid,
    ] {
        assert_eq!(
            valid(&empty(TargetState::Conflict, Some(reason))),
            cfg!(target_os = "linux") && reason == TargetReason::InterfaceNotWireguard
                || cfg!(windows) && reason == TargetReason::ServiceInvalid
        );
    }
    assert!(!valid(&empty(TargetState::Conflict, None)));
    let mut changed = empty(TargetState::Unknown, Some(TargetReason::TargetChanged));
    assert_eq!(valid(&changed), cfg!(unix));
    for status in ["observed", "query_failed", "tool_missing"] {
        changed.status_state = status.into();
        assert!(valid(&changed));
    }
    let mut invalid = empty(TargetState::Unknown, Some(TargetReason::InvalidName));
    assert!(!valid(&invalid));
    invalid.logical_name.clear();
    assert!(valid(&invalid));
    invalid.status_state = "observed".into();
    assert!(!valid(&invalid));
    for name in ["", "bad/name", "client\n", ".."] {
        let mut observation = present();
        observation.logical_name = name.into();
        assert!(!valid(&observation));
    }
    let mut unknown_key = unknown.clone();
    unknown_key.identity = present().identity;
    assert!(!valid(&unknown_key));
    let mut unknown_status = unknown;
    unknown_status.status_state = "observed".into();
    assert!(!valid(&unknown_status));
}

#[test]
fn identity_native_bounds_and_foreign_platform_variants_are_rejected() {
    let mut observation = present();
    match observation.identity.as_mut().unwrap() {
        TargetIdentity::LinuxInterface { index, .. }
        | TargetIdentity::MacosInterface { index, .. } => *index = 0,
        TargetIdentity::WindowsService { service_state, .. } => *service_state = 0,
    }
    assert!(!valid(&observation));
    let mut observation = present();
    match observation.identity.as_mut().unwrap() {
        TargetIdentity::LinuxInterface { namespace, .. } => *namespace = "A".repeat(64),
        TargetIdentity::MacosInterface {
            socket_identity, ..
        } => *socket_identity = "not-digest".into(),
        TargetIdentity::WindowsService {
            config_identity, ..
        } => *config_identity = Some("not-digest".into()),
    }
    assert!(!valid(&observation));
    let mut observation = present();
    match observation.identity.as_mut().unwrap() {
        TargetIdentity::LinuxInterface { name, .. } => *name = "other".into(),
        TargetIdentity::MacosInterface { name, .. } => *name = "utun01".into(),
        TargetIdentity::WindowsService { service_name, .. } => {
            *service_name = "WireGuardTunnel$other".into()
        }
    }
    assert!(!valid(&observation));
    let mut observation = present();
    observation.identity = Some(if cfg!(target_os = "linux") {
        TargetIdentity::MacosInterface {
            name: "utun12".into(),
            index: 12,
            mapping_identity: "a".repeat(64),
            socket_identity: "b".repeat(64),
            public_key: None,
        }
    } else {
        TargetIdentity::LinuxInterface {
            name: "client".into(),
            index: 12,
            namespace: "a".repeat(64),
            public_key: None,
        }
    });
    assert!(!valid(&observation));
}

#[cfg(windows)]
#[test]
fn service_metadata_rejects_invalid_executables_paths_accounts_and_states() {
    for field in [
        "executable",
        "relative",
        "parent",
        "non_normalized",
        "control",
        "account",
        "account_size",
        "start",
        "state",
    ] {
        let mut observation = present();
        let Some(TargetIdentity::WindowsService {
            binary_path,
            config_path,
            account,
            start_type,
            service_state,
            ..
        }) = &mut observation.identity
        else {
            unreachable!()
        };
        match field {
            "executable" => *binary_path = r"C:\WireGuard\wrong.dll".into(),
            "relative" => *config_path = "client.conf".into(),
            "parent" => *config_path = r"C:\WireGuard\..\client.conf".into(),
            "non_normalized" => *config_path = r"C:\WireGuard\.\client.conf".into(),
            "control" => *account = "SYSTEM\n".into(),
            "account" => account.clear(),
            "account_size" => *account = "a".repeat(513),
            "start" => *start_type = 5,
            _ => *service_state = 8,
        }
        assert!(!valid(&observation), "accepted {field}");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_index_is_a_positive_kernel_signed_index() {
    let mut observation = present();
    let Some(TargetIdentity::LinuxInterface { index, .. }) = &mut observation.identity else {
        unreachable!()
    };
    *index = i32::MAX as u32 + 1;
    assert!(!valid(&observation));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_interface_name_is_a_canonical_u32_utun() {
    for invalid in [
        "utun",
        "utun-1",
        "utun+1",
        "utun01",
        "utun4294967296",
        "other12",
    ] {
        let mut observation = present();
        let Some(TargetIdentity::MacosInterface { name, .. }) = &mut observation.identity else {
            unreachable!()
        };
        *name = invalid.into();
        assert!(!valid(&observation));
    }
}
