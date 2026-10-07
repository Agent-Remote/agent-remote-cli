// Tests for src/doctor.rs.

use super::{classify_broker_credential, BrokerCredential, BrokerCredentialState};

const SERVER_URL: &str = "https://control.example.test";
const DEVICE_ID: &str = "2cb933ce-b922-4ed7-b479-6ded90f09d2d";
const OTHER_DEVICE_ID: &str = "b79126b5-5ae7-4f8f-8515-f365bffac72d";

fn credential(server_url: &str, device_id: &str) -> BrokerCredential {
    BrokerCredential {
        schema_version: 1,
        server_url: server_url.to_string(),
        device_id: device_id.to_string(),
        access_token: "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG".to_string(),
        expires_at_unix: u64::MAX,
    }
}

#[test]
fn matching_broker_credential_is_healthy() {
    let credential = credential(SERVER_URL, DEVICE_ID);
    assert_eq!(
        classify_broker_credential(SERVER_URL, DEVICE_ID, Some(&credential), true),
        BrokerCredentialState::Matching
    );
}

#[test]
fn mismatched_broker_credential_is_reported() {
    let credential = credential(SERVER_URL, OTHER_DEVICE_ID);
    assert_eq!(
        classify_broker_credential(SERVER_URL, DEVICE_ID, Some(&credential), true),
        BrokerCredentialState::BindingMismatch
    );
}

#[test]
fn required_broker_credential_cannot_fall_back_to_legacy_storage() {
    assert_eq!(
        classify_broker_credential(SERVER_URL, DEVICE_ID, None, true),
        BrokerCredentialState::MissingRequired
    );
}

#[test]
fn optional_broker_credential_uses_legacy_storage() {
    assert_eq!(
        classify_broker_credential(SERVER_URL, DEVICE_ID, None, false),
        BrokerCredentialState::MissingOptional
    );
}
