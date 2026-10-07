// Tests for src/config.rs.

use tempfile::tempdir;

use super::{AppPaths, Config};

#[test]
fn saves_and_loads_config() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("agent-remote"));
    let config = Config {
        server_url: Some("https://example.test".to_string()),
        active_device_id: Some("dev_1".to_string()),
    };
    config.save(&paths).unwrap();

    let loaded = Config::load(&paths).unwrap();
    assert_eq!(loaded.server_url.as_deref(), Some("https://example.test"));
    assert_eq!(loaded.active_device_id.as_deref(), Some("dev_1"));
}
