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

#[test]
fn stale_login_cannot_overwrite_a_new_configuration() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let before = Config::default();
    let newer = Config {
        server_url: Some("https://new.example".into()),
        active_device_id: Some("new-device".into()),
    };
    newer.save(&paths).unwrap();
    assert!(before.save_if_unchanged(&paths, &before).is_err());
    assert_eq!(Config::load(&paths).unwrap(), newer);
    let old_file = std::fs::File::open(paths.config_path()).unwrap();
    before.save(&paths).unwrap();
    use std::io::Read;
    let mut text = String::new();
    (&old_file).read_to_string(&mut text).unwrap();
    assert!(
        text.contains("new.example"),
        "save truncated the previous file instead of replacing it"
    );
    assert_eq!(Config::load(&paths).unwrap(), before);
}

#[test]
fn existing_home_lock_does_not_prepare_directories_and_serializes_existing_writers() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().to_owned());
    let guard = super::write_lock_existing(&paths).unwrap();
    assert!(dir.path().join("config-write.lock").is_file());
    assert!(!paths.bin_dir().exists());
    assert!(!paths.secrets_dir().exists());
    assert!(!paths.config_path().exists());
    assert!(super::write_lock_existing(&paths).is_err());
    drop(guard);
    let existing = super::write_lock(&paths).unwrap();
    assert!(super::write_lock_existing(&paths).is_err());
    drop(existing);
    assert!(super::write_lock_existing(&paths).is_ok());
}
#[test]
fn existing_home_lock_does_not_create_an_absent_home() {
    let dir = tempdir().unwrap();
    let paths = AppPaths::from_home(dir.path().join("absent"));
    assert!(super::write_lock_existing(&paths).is_err());
    assert!(!paths.home().exists());
}
#[cfg(unix)]
#[test]
fn existing_home_lock_rejects_redirected_home_and_lock_leaf() {
    use std::os::unix::fs::symlink;
    let dir = tempdir().unwrap();
    let outside = dir.path().join("outside");
    std::fs::create_dir(&outside).unwrap();
    let link = dir.path().join("link");
    symlink(&outside, &link).unwrap();
    assert!(super::write_lock_existing(&AppPaths::from_home(link)).is_err());
    assert!(!outside.join("config-write.lock").exists());
    let paths = AppPaths::from_home(dir.path().to_owned());
    let sentinel = outside.join("sentinel");
    std::fs::write(&sentinel, "untouched").unwrap();
    symlink(&sentinel, dir.path().join("config-write.lock")).unwrap();
    assert!(super::write_lock_existing(&paths).is_err());
    assert_eq!(std::fs::read_to_string(sentinel).unwrap(), "untouched");
}
