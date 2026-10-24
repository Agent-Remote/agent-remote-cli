use super::*;

const BROKER: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const CALLER: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REQUEST: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
const SECRET: &[u8] = b"test-broker-secret";

fn challenge(now: u64) -> AuthChallenge {
    new_challenge(BROKER, now).unwrap()
}

#[test]
fn challenge_response_binds_exact_context_and_round_trips() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    verify_response(&challenge, &response, CALLER, REQUEST, SECRET, 100).unwrap();
    verify_response(&challenge, &response, CALLER, REQUEST, SECRET, 129).unwrap();
}

#[test]
fn response_rejects_expiry_and_clock_skew() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    assert_eq!(
        verify_response(&challenge, &response, CALLER, REQUEST, SECRET, 131)
            .unwrap_err()
            .0,
        "wireguard_authentication_expired"
    );
    assert_eq!(
        verify_response(&challenge, &response, CALLER, REQUEST, SECRET, 99)
            .unwrap_err()
            .0,
        "wireguard_authentication_expired"
    );
}

#[test]
fn response_rejects_context_secret_and_proof_changes() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    for (caller, request, secret) in [
        (
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            REQUEST,
            SECRET,
        ),
        (
            CALLER,
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            SECRET,
        ),
        (CALLER, REQUEST, b"other-secret".as_slice()),
    ] {
        let error = verify_response(&challenge, &response, caller, request, secret, 100)
            .unwrap_err()
            .0;
        assert!(
            matches!(
                error,
                "wireguard_authentication_mismatch" | "wireguard_authentication_failed"
            ),
            "unexpected error {error}"
        );
    }
    let mut forged = response.clone();
    let replacement = if forged.proof_sha256.starts_with('0') {
        "1"
    } else {
        "0"
    };
    forged.proof_sha256.replace_range(..1, replacement);
    assert_eq!(
        verify_response(&challenge, &forged, CALLER, REQUEST, SECRET, 100)
            .unwrap_err()
            .0,
        "wireguard_authentication_failed"
    );
}

#[test]
fn malformed_json_and_unknown_fields_fail_closed() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    let mut object = serde_json::to_value(response).unwrap();
    object["unexpected"] = serde_json::json!(true);
    assert!(serde_json::from_value::<AuthResponse>(object).is_err());
    let mut invalid = challenge.clone();
    invalid.nonce.replace_range(..1, "G");
    assert_eq!(
        make_response(&invalid, CALLER, REQUEST, SECRET)
            .unwrap_err()
            .0,
        "wireguard_authentication_invalid"
    );
}

#[test]
fn challenge_ids_are_single_use_with_bounded_replay_guard() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    let mut guard = ChallengeReplayGuard::default();
    guard.register(&challenge, 100).unwrap();
    guard
        .consume(&challenge, &response, CALLER, REQUEST, SECRET, 100)
        .unwrap();
    assert_eq!(
        guard
            .consume(&challenge, &response, CALLER, REQUEST, SECRET, 100)
            .unwrap_err()
            .0,
        "wireguard_authentication_replayed"
    );
}

#[test]
fn unissued_or_altered_challenge_cannot_be_consumed() {
    let challenge = challenge(100);
    let response = make_response(&challenge, CALLER, REQUEST, SECRET).unwrap();
    let mut guard = ChallengeReplayGuard::default();
    assert_eq!(
        guard
            .consume(&challenge, &response, CALLER, REQUEST, SECRET, 100)
            .unwrap_err()
            .0,
        "wireguard_authentication_unknown_challenge"
    );
    guard.register(&challenge, 100).unwrap();
    let mut altered = challenge.clone();
    let replacement = if altered.nonce.starts_with('f') {
        "e"
    } else {
        "f"
    };
    altered.nonce.replace_range(..1, replacement);
    let altered_response = make_response(&altered, CALLER, REQUEST, SECRET).unwrap();
    assert_eq!(
        guard
            .consume(&altered, &altered_response, CALLER, REQUEST, SECRET, 100)
            .unwrap_err()
            .0,
        "wireguard_authentication_mismatch"
    );
}

#[test]
fn challenge_generation_rejects_invalid_broker_identity() {
    assert_eq!(
        new_challenge("not-a-digest", 100).unwrap_err().0,
        "wireguard_authentication_invalid"
    );
}

#[test]
fn proof_matches_standard_hmac_sha256_vector() {
    let challenge = AuthChallenge {
        protocol_version: PROTOCOL_VERSION,
        challenge_id: "a".repeat(64),
        nonce: "b".repeat(64),
        expires_at_unix: 130,
        broker_instance_sha256: "c".repeat(64),
    };
    let actual = encode_hex(&proof(&challenge, &"d".repeat(64), &"e".repeat(64), b"key"));
    assert_eq!(
        actual,
        "97a97a286409e692e0f62673d127c5872fb55072cfd666fc4cb66b771d05ffef"
    );
}
