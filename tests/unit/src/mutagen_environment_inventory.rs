use super::*;
use std::fs;

fn number(tag: u32, mut value: u64, output: &mut Vec<u8>) {
    integer(u64::from(tag) << 3, output);
    while value >= 128 {
        output.push((value as u8) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
fn integer(mut value: u64, output: &mut Vec<u8>) {
    while value >= 128 {
        output.push((value as u8) | 128);
        value >>= 7;
    }
    output.push(value as u8);
}
fn bytes(tag: u32, value: &[u8], output: &mut Vec<u8>) {
    integer((u64::from(tag) << 3) | 2, output);
    integer(value.len() as u64, output);
    output.extend(value);
}
fn fixture(kind: &str, paused: bool) -> (String, Vec<u8>) {
    fixture_with_configuration(kind, paused, &[])
}
fn fixture_with_configuration(kind: &str, paused: bool, configuration: &[u8]) -> (String, Vec<u8>) {
    let id = format!(
        "{}_{}",
        if kind == "sync" { "sync" } else { "fwrd" },
        "a".repeat(43)
    );
    let mut session = Vec::new();
    bytes(1, id.as_bytes(), &mut session);
    number(2, 1, &mut session);
    bytes(3, &[8, 1], &mut session);
    number(5, 18, &mut session);
    number(6, 1, &mut session);
    let mut endpoint = Vec::new();
    if kind == "forward" {
        number(7, 1, &mut endpoint);
    }
    bytes(
        5,
        if kind == "sync" {
            b"/fixture"
        } else {
            b"tcp:127.0.0.1:1234"
        },
        &mut endpoint,
    );
    bytes(7, &endpoint, &mut session);
    bytes(8, &endpoint, &mut session);
    bytes(9, configuration, &mut session);
    if kind == "sync" {
        if paused {
            number(10, 1, &mut session);
        }
        bytes(14, b"Local-project", &mut session);
    } else {
        bytes(10, &[], &mut session);
        bytes(11, &[], &mut session);
        bytes(12, b"Forwarded-port", &mut session);
        if paused {
            number(14, 1, &mut session);
        }
    }
    (id, session)
}
fn put(root: &Path, kind: &str, paused: bool) -> PathBuf {
    let (id, data) = fixture(kind, paused);
    let directory = root.join(if kind == "sync" {
        "sessions"
    } else {
        "forwarding/sessions"
    });
    fs::create_dir_all(&directory).unwrap();
    let path = directory.join(id);
    fs::write(&path, data).unwrap();
    path
}

#[test]
fn inventories_paused_sync_and_forward_without_daemon_or_writes() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "sync", true);
    put(temp.path(), "forward", false);
    let result = read(temp.path()).unwrap();
    assert_eq!(result.sessions.len(), 2);
    assert_eq!(result.sessions[0].kind, "sync");
    assert!(result.sessions[0].paused);
    assert_eq!(result.sessions[1].kind, "forward");
    assert!(!result.sessions[1].paused);
    assert!(result.namespace_fingerprint.is_some());
    assert!(!temp.path().join("daemon").exists());
    assert_eq!(result.fingerprint, read(temp.path()).unwrap().fingerprint);
}

#[test]
fn missing_namespace_does_not_create_any_ancestor() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("missing/deep");
    let result = read(&path).unwrap();
    assert!(result.sessions.is_empty());
    assert!(result.namespace_fingerprint.is_none());
    assert!(!temp.path().join("missing").exists());
    fs::write(temp.path().join("file"), b"not a directory").unwrap();
    assert!(read(&temp.path().join("file/deep")).is_err());
}

#[test]
fn all_configuration_bytes_bind_the_review_without_secret_projection() {
    let temp = tempfile::tempdir().unwrap();
    let path = put(temp.path(), "sync", false);
    let original = read(temp.path()).unwrap();
    let mut data = fs::read(&path).unwrap();
    let mut label = Vec::new();
    bytes(1, b"private-label", &mut label);
    bytes(2, b"synthetic-secret-value", &mut label);
    bytes(13, &label, &mut data);
    fs::write(&path, &data).unwrap();
    let altered = read(temp.path()).unwrap();
    assert_ne!(original.fingerprint, altered.fingerprint);
    assert_ne!(
        original.sessions[0].configuration_fingerprint,
        altered.sessions[0].configuration_fingerprint
    );
    assert!(!serde_json::to_string(&altered.sessions)
        .unwrap()
        .contains("synthetic-secret-value"));
    fs::create_dir(temp.path().join("daemon")).unwrap();
    fs::write(temp.path().join("daemon/daemon.lock"), b"ignored").unwrap();
    assert_eq!(altered.fingerprint, read(temp.path()).unwrap().fingerprint);
}

#[test]
fn blocks_future_unknown_duplicate_and_malformed_protobuf() {
    for (tag, value) in [(2, 2), (10, 1), (90, 1)] {
        let (_, mut data) = fixture("sync", false);
        number(tag, value, &mut data);
        // Explicit duplicate paused values must not silently use first/last semantics.
        if tag == 10 {
            number(10, 0, &mut data);
        }
        assert!(decode(&data, "sync").is_err());
    }
    for tail in [
        &[0x80][..],
        &[0x0a, 0xff, 0xff, 0xff, 0xff, 0x7f][..],
        &[0x0b][..],
    ] {
        let (_, mut data) = fixture("sync", false);
        data.extend(tail);
        assert!(decode(&data, "sync").is_err());
    }
    let (_, mut data) = fixture("sync", false);
    let mut unknown = Vec::new();
    number(99, 1, &mut unknown);
    bytes(11, &unknown, &mut data);
    assert!(decode(&data, "sync").is_err());
    let (_, mut data) = fixture("sync", false);
    let mut invalid_enum = Vec::new();
    number(11, 9, &mut invalid_enum);
    bytes(11, &invalid_enum, &mut data);
    assert!(decode(&data, "sync").is_err());
}

#[test]
fn rejects_filename_identity_mismatch_and_file_size_limit() {
    let temp = tempfile::tempdir().unwrap();
    let path = put(temp.path(), "sync", false);
    let different = path.with_file_name(format!("sync_{}", "b".repeat(43)));
    fs::rename(&path, &different).unwrap();
    assert_eq!(
        read(temp.path()).err().unwrap().code(),
        "sync_mutagen_inventory_invalid"
    );
    fs::rename(&different, &path).unwrap();
    fs::File::create(path)
        .unwrap()
        .set_len(FILE_LIMIT + 1)
        .unwrap();
    assert_eq!(
        read(temp.path()).err().unwrap().code(),
        "sync_mutagen_inventory_limit"
    );
}

#[test]
fn bounds_even_ignored_directory_entries() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("sessions")).unwrap();
    for index in 0..=SESSION_LIMIT {
        fs::write(temp.path().join(format!("sessions/ignored-{index}")), []).unwrap();
    }
    assert_eq!(
        read(temp.path()).err().unwrap().code(),
        "sync_mutagen_inventory_limit"
    );
}

#[test]
fn bounds_combined_configuration_bytes() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir(temp.path().join("sessions")).unwrap();
    let mut configuration = Vec::new();
    for _ in 0..15 {
        bytes(32, &vec![b'x'; 65536], &mut configuration);
    }
    let (_, template) = fixture_with_configuration("sync", true, &configuration);
    assert!(template.len() < FILE_LIMIT as usize);
    for index in 0..36 {
        let id = format!("sync_{index:043}");
        let mut value = template.clone();
        // The identifier is the first standard protobuf length-delimited field.
        value[2..50].copy_from_slice(id.as_bytes());
        fs::write(temp.path().join("sessions").join(id), value).unwrap();
    }
    assert_eq!(
        read(temp.path()).err().unwrap().code(),
        "sync_mutagen_inventory_limit"
    );
}

#[cfg(unix)]
#[test]
fn inaccessible_ancestor_is_not_an_empty_namespace() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let directory = temp.path().join("denied");
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o0)).unwrap();
    let result = read(&directory.join("missing"));
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn rejects_symlink_hardlink_fifo_and_linked_namespace() {
    use std::os::unix::fs::symlink;
    for kind in ["symlink", "hardlink", "fifo"] {
        let temp = tempfile::tempdir().unwrap();
        let path = put(temp.path(), "sync", false);
        let saved = temp.path().join("saved");
        fs::rename(&path, &saved).unwrap();
        match kind {
            "symlink" => symlink(&saved, &path).unwrap(),
            "hardlink" => fs::hard_link(&saved, &path).unwrap(),
            _ => {
                use std::os::unix::ffi::OsStrExt;
                let path = std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
        }
        assert!(read(temp.path()).is_err());
    }
    let temp = tempfile::tempdir().unwrap();
    let namespace = temp.path().join("namespace");
    symlink(temp.path(), &namespace).unwrap();
    assert!(read(&namespace).is_err());
}
