// Tests for src/broker_credentials.rs.

use super::BrokerCredential;
#[cfg(target_os = "macos")]
use super::{load_community_credential, store_community_credential};
#[cfg(target_os = "macos")]
use crate::config::AppPaths;

const DEVICE_ID: &str = "2cb933ce-b922-4ed7-b479-6ded90f09d2d";
const TOKEN: &str = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG";

#[test]
fn validates_a_bounded_https_origin_credential() {
    let credential = BrokerCredential {
        schema_version: 1,
        server_url: "https://control.example.test:8443".to_string(),
        device_id: DEVICE_ID.to_string(),
        access_token: TOKEN.to_string(),
        expires_at_unix: 1_100,
    };
    credential.validate_at(1_000).unwrap();
    let encoded = serde_json::to_vec(&credential).unwrap();
    assert_eq!(
        serde_json::from_slice::<BrokerCredential>(&encoded).unwrap(),
        credential
    );
}

#[test]
fn rejects_endpoint_overrides_expired_tokens_and_unknown_fields() {
    for server_url in [
        "http://control.example.test",
        "https://user@control.example.test",
        "https://control.example.test/api",
        "https://control.example.test?next=evil",
        "https://control.example.test/",
    ] {
        let credential = BrokerCredential {
            schema_version: 1,
            server_url: server_url.to_string(),
            device_id: DEVICE_ID.to_string(),
            access_token: TOKEN.to_string(),
            expires_at_unix: 1_100,
        };
        assert!(
            credential.validate_at(1_000).is_err(),
            "accepted {server_url}"
        );
    }
    let expired = BrokerCredential {
        schema_version: 1,
        server_url: "https://control.example.test".to_string(),
        device_id: DEVICE_ID.to_string(),
        access_token: TOKEN.to_string(),
        expires_at_unix: 999,
    };
    assert!(expired.validate_at(1_000).is_err());
    let unknown = format!(
        r#"{{"schema_version":1,"server_url":"https://control.example.test","device_id":"{DEVICE_ID}","access_token":"{TOKEN}","expires_at_unix":1100,"endpoint":"https://evil.test"}}"#
    );
    assert!(serde_json::from_str::<BrokerCredential>(&unknown).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn community_credential_file_is_owner_only_and_round_trips() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let data = br#"{"schema_version":1}"#;
    store_community_credential(&paths, data).unwrap();

    let path = paths.home().join("device-broker-credential.json");
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(
        load_community_credential(&paths).unwrap(),
        Some(data.to_vec())
    );

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_community_credential(&paths).is_err());
}
