//! The receiver runs on the Linux Node; local senders remain platform independent.
#[cfg(unix)]
#[test]
fn receiver_accepts_verified_archives_and_cleans_scoped_files() {
    let result = std::process::Command::new("python3")
        .arg("tests/attachment_receiver_test.py")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}
