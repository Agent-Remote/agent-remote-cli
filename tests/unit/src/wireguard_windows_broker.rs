// Tests for src/wireguard/windows_broker.rs.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use sha2::{Digest, Sha256};

use super::{
    decode_broker_frame, decode_request_frame, encode_broker_frame, encode_request_frame,
    issue_permit, pipe_name, request_sha256, validate_broker_envelope, validate_request,
    BrokerWorkerEnvelope, CallerIdentity, WorkerAction, WorkerLifetime, WorkerRequest,
    MAX_WORKER_LIFETIME, PROTOCOL_VERSION,
};

fn digest(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .flat_map(|byte| {
            [
                b"0123456789abcdef"[(byte >> 4) as usize],
                b"0123456789abcdef"[(byte & 0xf) as usize],
            ]
        })
        .map(char::from)
        .collect()
}

fn identity() -> CallerIdentity {
    CallerIdentity {
        process_id: 7,
        session_id: 9,
        user_sid_sha256: "a".repeat(64),
        caller_sha256: "b".repeat(64),
    }
}

fn request(identity: &CallerIdentity, bytes: &[u8]) -> WorkerRequest {
    WorkerRequest {
        protocol_version: PROTOCOL_VERSION,
        request_id: "c".repeat(64),
        caller_sha256: identity.caller_sha256.clone(),
        action: "up".into(),
        config_sha256: digest(bytes),
        config_b64: STANDARD.encode(bytes),
        expires_at_unix_ms: 1_000 + 1_000,
    }
}

#[test]
fn pipe_name_is_local_and_strictly_bounded() {
    assert_eq!(
        pipe_name("test-01").unwrap(),
        r"\\.\pipe\AgentRemote-WireGuard-v1-test-01"
    );
    assert!(pipe_name("").is_err());
    assert!(pipe_name("contains space").is_err());
    assert!(pipe_name(&"x".repeat(65)).is_err());
}

#[test]
fn request_binds_os_identity_and_config_bytes() {
    let observed = identity();
    let valid = validate_request(request(&observed, b"[Interface]\n"), &observed, 1_000).unwrap();
    assert_eq!(valid.action, WorkerAction::Up);
    assert_eq!(valid.config_bytes.as_slice(), b"[Interface]\n");
    let mut altered = request(&observed, b"[Interface]\n");
    altered.caller_sha256 = "d".repeat(64);
    assert!(validate_request(altered, &observed, 1_000).is_err());
}

#[test]
fn request_rejects_expiry_and_config_digest_changes() {
    let observed = identity();
    assert!(validate_request(request(&observed, b"x"), &observed, 2_001).is_err());
    let mut altered = request(&observed, b"x");
    altered.config_b64 = STANDARD.encode(b"changed");
    assert!(validate_request(altered, &observed, 1_000).is_err());
    let mut too_far = request(&observed, b"x");
    too_far.expires_at_unix_ms = 1_000 + MAX_WORKER_LIFETIME.as_millis() as u64 + 1;
    assert!(validate_request(too_far, &observed, 1_000).is_err());
}

#[test]
fn worker_lifetime_allows_one_request_only() {
    let started = Instant::now();
    let mut lifetime = WorkerLifetime::new(started, Duration::from_secs(1)).unwrap();
    assert!(!lifetime.expired(started));
    lifetime.accept(started + Duration::from_millis(1)).unwrap();
    assert!(lifetime.accept(started + Duration::from_millis(2)).is_err());
    assert!(WorkerLifetime::new(started, MAX_WORKER_LIFETIME + Duration::from_millis(1)).is_err());
}

#[test]
fn request_frame_is_canonical_and_bounded() {
    let observed = identity();
    let request = request(&observed, b"[Interface]\n");
    let frame = encode_request_frame(&request).unwrap();
    assert_eq!(decode_request_frame(&frame).unwrap(), request);
    let mut altered = frame.clone();
    altered.push(b' ');
    assert!(decode_request_frame(&altered).is_err());
    assert_eq!(request_sha256(&request).unwrap().len(), 64);
}

#[test]
fn request_constructor_binds_observed_identity_and_config_digest() {
    let observed = identity();
    let request = super::WorkerRequest::new(
        &observed,
        "c".repeat(64),
        WorkerAction::Down,
        b"[Interface]\n",
        1_500,
    )
    .unwrap();
    assert_eq!(request.caller_sha256, observed.caller_sha256);
    assert_eq!(request.action, "down");
    assert_eq!(request.config_sha256, digest(b"[Interface]\n"));
}

#[test]
fn permit_requires_durable_submission_and_is_single_use() {
    let observed = identity();
    let source = request(&observed, b"[Interface]\n");
    let validated = validate_request(source.clone(), &observed, 1_000).unwrap();
    let request_digest = request_sha256(&source).unwrap();
    let target_digest = "e".repeat(64);
    assert!(issue_permit(
        &validated,
        &observed,
        &request_digest,
        &target_digest,
        false,
        1_000,
    )
    .is_err());
    let mut permit = issue_permit(
        &validated,
        &observed,
        &request_digest,
        &target_digest,
        true,
        1_000,
    )
    .unwrap();
    let claims = permit.consume(&validated, &observed, 1_001).unwrap();
    assert_eq!(claims.request_id, validated.request_id);
    assert_eq!(claims.target_scope_sha256, target_digest);
    assert!(permit.is_consumed());
    assert!(permit.consume(&validated, &observed, 1_002).is_err());
}

#[test]
fn permit_rebinds_to_process_token_identity_and_request() {
    let observed = identity();
    let source = request(&observed, b"x");
    let validated = validate_request(source.clone(), &observed, 1_000).unwrap();
    let mut permit = issue_permit(
        &validated,
        &observed,
        &request_sha256(&source).unwrap(),
        &"e".repeat(64),
        true,
        1_000,
    )
    .unwrap();
    let mut different = observed.clone();
    different.caller_sha256 = "f".repeat(64);
    assert!(permit.consume(&validated, &different, 1_001).is_err());
    assert!(!permit.is_consumed());
    assert!(permit.consume(&validated, &observed, 1_001).is_ok());
}

#[test]
fn broker_envelope_binds_reviewed_plan_target_and_config_identity() {
    let observed = identity();
    let worker = request(&observed, b"[Interface]\n");
    let envelope = BrokerWorkerEnvelope {
        protocol_version: PROTOCOL_VERSION,
        worker,
        plan_sha256: "1".repeat(64),
        target_scope_sha256: "2".repeat(64),
        logical_name: "agent-remote".into(),
        config_file_identity: "3".repeat(64),
        config_content_sha256: digest(b"[Interface]\n"),
        config_public_key: STANDARD.encode([7u8; 32]),
    };
    let frame = encode_broker_frame(&envelope).unwrap();
    assert_eq!(decode_broker_frame(&frame).unwrap(), envelope);
    let validated = validate_broker_envelope(envelope, &observed, 1_000).unwrap();
    assert_eq!(validated.logical_name, "agent-remote");
    assert_eq!(validated.target_scope_sha256, "2".repeat(64));
}
