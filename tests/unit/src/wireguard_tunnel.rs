use super::*;
use serde_json::json;

fn config(state: &'static str) -> ConfigInspection {
    ConfigInspection {
        path: PathBuf::from("/client.conf"),
        state,
        addresses: vec![],
        dns: vec![],
        mtu: None,
        peer_count: Some(0),
        unsupported_directives: vec![],
    }
}
fn binding() -> ConfigBinding {
    ConfigBinding {
        file_identity: "a".repeat(64),
        content_sha256: "b".repeat(64),
        public_key: "expected-public-key".into(),
    }
}
fn target(state: &str, identity: serde_json::Value) -> TargetObservation {
    serde_json::from_value(json!({"logical_name":"client","state":state,"reason":null,"status_state":"available","identity":identity})).unwrap()
}
fn interface(key: serde_json::Value) -> serde_json::Value {
    json!({"kind":"linux_interface","name":"client","index":12,"namespace":"c".repeat(64),"public_key":key})
}
#[test]
fn up_and_down_distinguish_absence_unknown_conflict_and_present_identity() {
    let config = config("ready");
    let binding = binding();
    for (action, state, expected) in [
        (Action::Up, "absent", vec!["execution_bridge_required"]),
        (
            Action::Up,
            "unknown",
            vec!["target_unknown", "execution_bridge_required"],
        ),
        (
            Action::Down,
            "unknown",
            vec!["target_unknown", "execution_bridge_required"],
        ),
        (
            Action::Down,
            "absent",
            vec!["target_absent", "execution_bridge_required"],
        ),
        (
            Action::Up,
            "conflict",
            vec!["target_conflict", "execution_bridge_required"],
        ),
    ] {
        assert_eq!(
            issues(
                action,
                &config,
                Some(&binding),
                &[],
                &target(state, json!(null))
            ),
            expected
        );
    }
    let present = target("present", interface(json!(binding.public_key)));
    assert_eq!(
        issues(Action::Up, &config, Some(&binding), &[], &present),
        vec!["target_already_present", "execution_bridge_required"]
    );
    assert_eq!(
        issues(Action::Down, &config, Some(&binding), &[], &present),
        vec!["execution_bridge_required"]
    );
    let other = target("present", interface(json!("other-key")));
    assert_eq!(
        issues(Action::Down, &config, Some(&binding), &[], &other),
        vec!["config_target_mismatch", "execution_bridge_required"]
    );
    let unobserved = target("present", interface(json!(null)));
    assert_eq!(
        issues(Action::Down, &config, Some(&binding), &[], &unobserved),
        vec!["target_key_unobserved", "execution_bridge_required"]
    );
}

#[test]
fn service_config_identity_is_required_independently_of_its_name_and_key() {
    let config = config("ready");
    let binding = binding();
    for identity in [
        json!(null),
        json!("d".repeat(64)),
        json!(binding.file_identity),
    ] {
        let observed = target(
            "present",
            json!({"kind":"windows_service","service_name":"WireGuardTunnel$client","binary_path":"C:\\wireguard.exe","config_path":"C:\\client.conf","config_identity":identity,"service_state":4,"start_type":2,"account":"LocalSystem","public_key":binding.public_key}),
        );
        let result = issues(Action::Down, &config, Some(&binding), &[], &observed);
        if identity == json!(binding.file_identity) {
            assert_eq!(result, vec!["execution_bridge_required"]);
        } else {
            assert_eq!(
                result,
                vec!["service_config_mismatch", "execution_bridge_required"]
            );
        }
    }
}

#[test]
fn ready_bridge_removes_only_the_bridge_blocker() {
    let config = config("ready");
    let binding = binding();
    let absent = target("absent", json!(null));
    assert!(issues_for_bridge(Action::Up, &config, Some(&binding), &[], &absent, true).is_empty());

    let unknown = target("unknown", json!(null));
    assert_eq!(
        issues_for_bridge(Action::Up, &config, Some(&binding), &[], &unknown, true),
        vec!["target_unknown"]
    );

    let present = target("present", interface(json!(binding.public_key)));
    assert_eq!(
        issues_for_bridge(Action::Up, &config, Some(&binding), &[], &present, true),
        vec!["target_already_present"]
    );
}
