// Tests for src/auth.rs.

use tempfile::tempdir;

use crate::config::AppPaths;
use crate::local_state::LocalState;

use crate::secrets::{device_token_key, SecretStore};

use super::{device_token_refresh_key, has_device_token, record_refresh_time};

#[test]
fn stores_non_secret_refresh_time() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    record_refresh_time(&paths, "https://example.test", "device-1", 3600).unwrap();

    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    assert!(state
        .get_kv(&device_token_refresh_key(
            "https://example.test",
            "device-1"
        ))
        .unwrap()
        .is_some());
}

#[test]
fn detects_a_device_token_in_the_standard_secret_store() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    SecretStore::new(paths.clone())
        .set_secret(
            &device_token_key("https://example.test", "device-1"),
            "device-token",
        )
        .unwrap();

    assert!(has_device_token(&paths, "https://example.test", "device-1").unwrap());
    assert!(!has_device_token(&paths, "https://example.test", "device-2").unwrap());
}
