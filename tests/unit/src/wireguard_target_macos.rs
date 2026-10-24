use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::os::unix::net::UnixListener;

fn fixture() -> (tempfile::TempDir, UnixListener) {
    let dir = tempfile::Builder::new()
        .prefix("ar-wg-")
        .tempdir_in("/tmp")
        .unwrap();
    std::fs::write(dir.path().join("wg0.name"), b"utun123\n").unwrap();
    let socket = UnixListener::bind(dir.path().join("utun123.sock")).unwrap();
    (dir, socket)
}

#[test]
fn mapping_and_socket_are_bound_to_actual_utun_and_metadata() {
    let (dir, _socket) = fixture();
    let first = inspect_at(dir.path(), "wg0", |name| {
        assert_eq!(name, "utun123");
        Some(12)
    })
    .unwrap();
    assert!(
        matches!(&first,TargetIdentity::MacosInterface {name,index:12,mapping_identity,socket_identity,public_key:None} if name=="utun123" && mapping_identity.len()==64 && socket_identity.len()==64 && mapping_identity!=socket_identity)
    );
    std::fs::remove_file(dir.path().join("wg0.name")).unwrap();
    std::fs::write(dir.path().join("wg0.name"), b"utun123\n").unwrap();
    let second = inspect_at(dir.path(), "wg0", |_| Some(12)).unwrap();
    assert_ne!(first, second);
}

#[test]
fn missing_stale_and_unsafe_mappings_are_distinct_and_never_absent() {
    let (dir, _socket) = fixture();
    assert_eq!(
        inspect_at(dir.path(), "missing", |_| Some(12)).unwrap_err(),
        TargetReason::MappingMissing
    );
    assert_eq!(
        inspect_at(dir.path(), "wg0", |_| None).unwrap_err(),
        TargetReason::MappingStale
    );
    for bad in [
        "../utun123\n",
        "utun001\n",
        "en0\n",
        "utun123\nextra",
        "utun123\0",
    ] {
        std::fs::write(dir.path().join("wg0.name"), bad).unwrap();
        assert_eq!(
            inspect_at(dir.path(), "wg0", |_| Some(12)).unwrap_err(),
            TargetReason::MappingUnsafe
        );
    }
    std::fs::remove_file(dir.path().join("wg0.name")).unwrap();
    symlink("elsewhere", dir.path().join("wg0.name")).unwrap();
    assert_eq!(
        inspect_at(dir.path(), "wg0", |_| Some(12)).unwrap_err(),
        TargetReason::MappingUnsafe
    );
}

#[test]
fn wrong_socket_type_and_writable_mapping_are_rejected() {
    let (dir, socket) = fixture();
    drop(socket);
    std::fs::remove_file(dir.path().join("utun123.sock")).unwrap();
    std::fs::write(dir.path().join("utun123.sock"), b"not a socket").unwrap();
    assert_eq!(
        inspect_at(dir.path(), "wg0", |_| Some(12)).unwrap_err(),
        TargetReason::MappingUnsafe
    );
    std::fs::set_permissions(
        dir.path().join("wg0.name"),
        std::fs::Permissions::from_mode(0o666),
    )
    .unwrap();
    assert_eq!(
        inspect_at(dir.path(), "wg0", |_| Some(12)).unwrap_err(),
        TargetReason::MappingUnsafe
    );
}
