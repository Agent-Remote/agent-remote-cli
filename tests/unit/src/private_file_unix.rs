use super::sync_directory;
use cap_std::fs::Dir;

#[cfg(target_os = "linux")]
#[test]
fn sync_accepts_a_linux_path_only_capability_directory() {
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = tempfile::tempdir().unwrap();
    let handle = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY)
        .open(temporary.path())
        .unwrap();
    assert_eq!(
        handle.sync_all().unwrap_err().raw_os_error(),
        Some(libc::EBADF)
    );
    let directory = Dir::from_std_file(handle);
    sync_directory(&directory).unwrap();
}

#[test]
fn sync_uses_the_pinned_directory_after_its_path_is_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let original = temporary.path().join("original");
    let moved = temporary.path().join("moved");
    std::fs::create_dir(&original).unwrap();
    let directory = Dir::open_ambient_dir(&original, cap_std::ambient_authority()).unwrap();
    std::fs::rename(&original, &moved).unwrap();
    std::fs::write(&original, b"replacement is not a directory").unwrap();
    sync_directory(&directory).unwrap();
}

#[test]
fn sync_does_not_hide_an_invalid_directory_handle() {
    let file = tempfile::tempfile().unwrap();
    let invalid = Dir::from_std_file(file);
    assert!(sync_directory(&invalid).is_err());
}
