use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::lock_at;

#[tokio::test]
async fn same_binding_is_serialized_and_other_bindings_are_independent() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("locks");
    let cancel = AtomicBool::new(false);
    let first = lock_at(&root, "https://one.test", "device", &cancel)
        .await
        .unwrap();
    let pending = lock_at(&root, "https://one.test", "device", &cancel);
    tokio::pin!(pending);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut pending)
            .await
            .is_err()
    );
    let other = tokio::time::timeout(
        Duration::from_secs(1),
        lock_at(&root, "https://two.test", "device", &cancel),
    )
    .await
    .unwrap()
    .unwrap();
    drop(other);
    drop(first);
    assert!(tokio::time::timeout(Duration::from_secs(1), pending)
        .await
        .unwrap()
        .is_ok());
}

#[tokio::test]
async fn canceled_wait_releases_no_other_holders() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("locks");
    let cancel = AtomicBool::new(false);
    let first = lock_at(&root, "server", "device", &cancel).await.unwrap();
    let future = async {
        tokio::time::sleep(Duration::from_millis(30)).await;
        cancel.store(true, Ordering::Release);
    };
    let (result, ()) = tokio::join!(lock_at(&root, "server", "device", &cancel), future);
    assert!(result.is_err());
    drop(first);
    assert!(lock_at(&root, "server", "device", &AtomicBool::new(false))
        .await
        .is_ok());
}

#[cfg(unix)]
#[tokio::test]
async fn unsafe_lock_roots_fail_without_following_links() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("locks");
    symlink(temporary.path(), &root).unwrap();
    assert!(lock_at(&root, "server", "device", &AtomicBool::new(false))
        .await
        .is_err());
    std::fs::remove_file(&root).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
    assert!(lock_at(&root, "server", "device", &AtomicBool::new(false))
        .await
        .is_err());
}
