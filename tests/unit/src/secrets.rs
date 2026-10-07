// Tests for src/secrets.rs.

use tempfile::tempdir;

use crate::config::AppPaths;

use super::{device_token_key, wireguard_private_key_key, SecretBackend, SecretStore};

#[test]
fn file_secret_roundtrip() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let store = SecretStore::file_only(paths);
    let key = device_token_key("https://example.test", "dev_1");
    let backend = store.set_secret(&key, "token-value").unwrap();
    assert_eq!(backend, SecretBackend::File);
    assert_eq!(
        store.get_secret(&key).unwrap().as_deref(),
        Some("token-value")
    );
    store.delete_secret(&key).unwrap();
    assert!(store.get_secret(&key).unwrap().is_none());
}

#[test]
fn wireguard_private_key_is_scoped_to_server_and_device() {
    assert_ne!(
        wireguard_private_key_key("https://one.test", "device-1"),
        wireguard_private_key_key("https://two.test", "device-1")
    );
    assert_ne!(
        wireguard_private_key_key("https://one.test", "device-1"),
        wireguard_private_key_key("https://one.test", "device-2")
    );
}
