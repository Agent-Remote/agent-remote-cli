use std::sync::atomic::AtomicBool;

use super::{SecretBackend, SecretStore, SecretValue, StrictSecretError};
use crate::config::AppPaths;

fn fixture() -> (tempfile::TempDir, SecretStore) {
    let temporary = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(temporary.path().join("home"));
    paths.ensure_base_dirs().unwrap();
    (temporary, SecretStore::file_only(paths))
}

#[tokio::test]
async fn strict_file_roundtrip_preserves_exact_value_and_restricts_file() {
    let (_temporary, store) = fixture();
    let cancel = AtomicBool::new(false);
    assert!(store.read_strict("test", &cancel).await.unwrap().is_none());
    assert_eq!(
        store
            .write_strict(
                "test",
                &SecretValue::new("exact value".into()).unwrap(),
                &cancel
            )
            .await
            .unwrap(),
        SecretBackend::File
    );
    assert_eq!(
        store
            .read_strict("test", &cancel)
            .await
            .unwrap()
            .unwrap()
            .as_str(),
        "exact value"
    );
    crate::platform::validate_private_file(
        &std::fs::File::open(store.secret_path("test")).unwrap(),
    )
    .unwrap();
    store
        .write_strict(
            "test",
            &SecretValue::new("refreshed".into()).unwrap(),
            &cancel,
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .read_strict("test", &cancel)
            .await
            .unwrap()
            .unwrap()
            .as_str(),
        "refreshed"
    );
}

#[tokio::test]
async fn strict_cancellation_never_writes() {
    let (_temporary, store) = fixture();
    let cancel = AtomicBool::new(true);
    assert_eq!(
        store.read_strict("test", &cancel).await.err(),
        Some(StrictSecretError::Canceled)
    );
    assert_eq!(
        store
            .write_strict("test", &SecretValue::new("value".into()).unwrap(), &cancel)
            .await
            .err(),
        Some(StrictSecretError::Canceled)
    );
    assert!(!store.secret_path("test").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_boundary_retains_caller_guard_when_future_is_aborted() {
    use std::sync::{atomic::Ordering, Arc};
    struct Guard(Arc<AtomicBool>);
    impl Drop for Guard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }
    let dropped = Arc::new(AtomicBool::new(false));
    let guard = Guard(dropped.clone());
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let task = tokio::spawn(async move {
        let _guard = guard;
        super::blocking_credential_operation(move || {
            entered_tx.send(()).unwrap();
            release_rx
                .recv_timeout(std::time::Duration::from_secs(2))
                .unwrap();
        });
    });
    entered_rx.await.unwrap();
    task.abort();
    tokio::time::sleep(std::time::Duration::from_millis(30)).await;
    assert!(!dropped.load(Ordering::Acquire));
    release_tx.send(()).unwrap();
    let _ = task.await;
    assert!(dropped.load(Ordering::Acquire));
}

#[tokio::test]
async fn strict_rejects_empty_invalid_utf8_and_oversize_files() {
    let (_temporary, store) = fixture();
    let cancel = AtomicBool::new(false);
    for bytes in [
        Vec::new(),
        vec![0xff],
        vec![b'a'; super::MAX_SECRET_BYTES + 1],
    ] {
        let path = store.secret_path("test");
        std::fs::write(&path, bytes).unwrap();
        crate::platform::set_private_file_permissions(&std::fs::File::open(path).unwrap()).unwrap();
        assert_eq!(
            store.read_strict("test", &cancel).await.err(),
            Some(StrictSecretError::Invalid)
        );
    }
}

#[cfg(unix)]
#[tokio::test]
async fn strict_rejects_symlink_hardlink_fifo_and_broad_permissions() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let (temporary, store) = fixture();
    let cancel = AtomicBool::new(false);
    let source = temporary.path().join("source");
    std::fs::write(&source, "credential").unwrap();
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o600)).unwrap();
    let path = store.secret_path("test");
    symlink(&source, &path).unwrap();
    assert!(store.read_strict("test", &cancel).await.is_err());
    assert!(store
        .write_strict(
            "test",
            &SecretValue::new("replacement".into()).unwrap(),
            &cancel
        )
        .await
        .is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::hard_link(&source, &path).unwrap();
    assert_eq!(
        store.read_strict("test", &cancel).await.err(),
        Some(StrictSecretError::Invalid)
    );
    std::fs::remove_file(&path).unwrap();
    let fifo = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(tokio::time::timeout(
        std::time::Duration::from_secs(2),
        store.read_strict("test", &cancel)
    )
    .await
    .unwrap()
    .is_err());
    std::fs::remove_file(&path).unwrap();
    std::fs::write(&path, "credential").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert_eq!(
        store.read_strict("test", &cancel).await.err(),
        Some(StrictSecretError::Invalid)
    );
    assert_eq!(std::fs::read_to_string(source).unwrap(), "credential");
}

#[cfg(unix)]
#[tokio::test]
async fn strict_rejects_linked_home_and_secrets_directory() {
    use std::os::unix::fs::symlink;
    let (temporary, store) = fixture();
    let alias = temporary.path().join("alias");
    symlink(store.paths.home(), &alias).unwrap();
    let linked = SecretStore::file_only(AppPaths::from_home(alias.join(".")));
    assert!(linked
        .read_strict("test", &AtomicBool::new(false))
        .await
        .is_err());
    std::fs::remove_dir(store.paths.secrets_dir()).unwrap();
    symlink(temporary.path(), store.paths.secrets_dir()).unwrap();
    assert!(store
        .read_strict("test", &AtomicBool::new(false))
        .await
        .is_err());
}
