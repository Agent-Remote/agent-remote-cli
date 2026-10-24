use super::*;

fn binding(bytes: &[u8]) -> ConfigBinding {
    ConfigBinding {
        file_identity: "11".repeat(32),
        content_sha256: format!("{:x}", Sha256::digest(bytes)),
        public_key: "A".repeat(43) + "=",
    }
}

fn request(bytes: Vec<u8>) -> BrokerExecutionRequest {
    BrokerExecutionRequest {
        request_id: "22".repeat(32),
        plan_sha256: "33".repeat(32),
        target_scope_sha256: "44".repeat(32),
        action: Action::Up,
        logical_name: "agent-remote".into(),
        config: binding(&bytes),
        config_bytes: bytes,
    }
}

#[test]
fn status_is_fail_closed_without_a_native_service() {
    let status = status();
    assert!(matches!(status.state, "unsupported" | "unavailable"));
    assert_eq!(status.execution, "unavailable");
}

#[test]
fn request_validation_binds_configuration_bytes_to_reviewed_digest() {
    let value = request(b"[Interface]\nPrivateKey = x\n".to_vec());
    assert!(validate_request(&value).is_err());
}

#[test]
fn malformed_request_does_not_dispatch_to_platform() {
    let mut value = request(vec![1, 2, 3]);
    value.request_id = "not-a-digest".into();
    assert_eq!(execute(value).unwrap_err().0, "wireguard_execution_invalid");
}
