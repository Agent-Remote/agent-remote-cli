// Tests for src/attachments/paths.rs.

use super::*;
#[test]
fn windows_quotes_unc_and_unicode_preserve_backslashes() {
    assert_eq!(
        tokens(r#""C:\Users\中文\a file.txt" "D:\two.txt""#).unwrap(),
        [r"C:\Users\中文\a file.txt", r"D:\two.txt"]
    );
    assert_eq!(
        tokens(r#""\\server\share\a file""#).unwrap(),
        [r"\\server\share\a file"]
    );
    assert_eq!(
        tokens("'/tmp/it'\\''s a file' /tmp/next\\ file").unwrap(),
        ["/tmp/it's a file", "/tmp/next file"]
    );
}
#[tokio::test]
async fn multiple_files_and_uris_resolve_as_one_atomic_drop() {
    let root = tempfile::tempdir().unwrap();
    let first = root.path().join("中文 file.txt");
    let second = root.path().join("second.txt");
    for path in [&first, &second] {
        std::fs::write(path, b"test").unwrap();
    }
    let input = format!("'{}' '{}'", first.display(), second.display());
    assert_eq!(
        parse_dropped_paths(&input).await,
        Some(vec![first.clone(), second.clone()])
    );
    let uri = reqwest::Url::from_file_path(&first).unwrap();
    assert_eq!(
        parse_dropped_paths(uri.as_str()).await,
        Some(vec![first.clone()])
    );
    #[cfg(unix)]
    assert_eq!(
        parse_dropped_paths(&first.to_string_lossy().replace(' ', "\\ ")).await,
        Some(vec![first])
    );
    assert!(parse_dropped_paths(&format!("{input} /no-such-drop-path"))
        .await
        .is_none());
    assert!(parse_dropped_paths("Cargo.toml").await.is_none());
    assert!(parse_dropped_paths("file://remote-host/etc/passwd")
        .await
        .is_none());
}
#[test]
fn uri_validation_rejects_remote_authorities_and_corruption() {
    assert_eq!(decode_uri("file:///tmp/a%20b"), Some("/tmp/a b".into()));
    assert_eq!(
        decode_uri("file:///C:/Users/a%20b"),
        Some("C:/Users/a b".into())
    );
    for path in [
        "file://localhost-evil/a",
        "file://remote/a",
        "file:///tmp/%00",
        "file:///tmp/%xy",
        "file:///tmp/a#fragment",
    ] {
        assert!(decode_uri(path).is_none(), "{path}");
    }
}
