// Tests for src/attachments/archive.rs.

use super::*;

#[test]
fn files_and_directories_keep_unicode_and_do_not_modify_the_source() {
    let directory = tempfile::tempdir().unwrap();
    let nested = directory.path().join("中文 folder");
    std::fs::create_dir(&nested).unwrap();
    std::fs::write(nested.join("space file.txt"), b"contents").unwrap();
    let archive = pack(
        ClipboardPayload::Files(vec![nested.clone()]),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(archive.names, ["0-中文 folder"]);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(archive.file.metadata().unwrap().nlink(), 0);
    }
    let mut zip = zip::ZipArchive::new(archive.file.try_clone().unwrap()).unwrap();
    let mut text = String::new();
    zip.by_name("0-中文 folder/space file.txt")
        .unwrap()
        .read_to_string(&mut text)
        .unwrap();
    assert_eq!(text, "contents");
    drop(zip);
    drop(archive);
    assert_eq!(
        std::fs::read(nested.join("space file.txt")).unwrap(),
        b"contents"
    );
}

#[test]
fn images_have_a_verified_archive_and_cancellation_stops_packing() {
    let payload = ClipboardPayload::Image {
        bytes: b"\x89PNG\r\nimage".to_vec(),
        extension: "png",
    };
    let archive = pack(payload.clone(), Arc::new(AtomicBool::new(false))).unwrap();
    let mut bytes = Vec::new();
    archive
        .file
        .try_clone()
        .unwrap()
        .read_to_end(&mut bytes)
        .unwrap();
    assert_eq!(archive.sha256, format!("{:x}", Sha256::digest(&bytes)));
    assert_eq!(archive.size, bytes.len() as u64);
    assert!(pack(payload, Arc::new(AtomicBool::new(true))).is_err());
}

#[test]
fn deep_directories_use_bounded_stack_and_fail_cleanly_at_the_limit() {
    let source = tempfile::tempdir().unwrap();
    let mut path = source.path().to_path_buf();
    for _ in 0..63 {
        path.push("d");
        std::fs::create_dir(&path).unwrap();
    }
    std::fs::write(path.join("file"), b"deep").unwrap();
    let payload = ClipboardPayload::Files(vec![source.path().to_path_buf()]);
    assert!(pack(payload.clone(), Arc::new(AtomicBool::new(false))).is_ok());
    path.push("d");
    std::fs::create_dir(&path).unwrap();
    std::fs::write(path.join("too-deep"), b"deep").unwrap();
    assert!(pack(payload, Arc::new(AtomicBool::new(false))).is_err());
}

#[cfg(unix)]
#[test]
fn links_are_rejected_without_reading_them() {
    use std::os::unix::fs::symlink;
    let source = tempfile::tempdir().unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    let link = source.path().join("link");
    symlink(outside.path(), &link).unwrap();
    assert!(pack(
        ClipboardPayload::Files(vec![link]),
        Arc::new(AtomicBool::new(false))
    )
    .is_err());
}
