// Tests for src/attachments/transfer.rs.

use super::*;

fn transfer() -> Transfer {
    Transfer {
        receipt: Receipt {
            endpoint: Endpoint {
                host: "127.0.0.1".into(),
                port: 1,
                user: "test".into(),
            },
            account: "/account".into(),
            session: "session".into(),
            lease: unique_id(),
        },
        visible_account: "/account".into(),
        journal: Mutex::new(None),
    }
}

#[test]
fn stale_sessions_recover_but_foreign_and_invalid_receipts_do_not() {
    let transfer = transfer();
    let mut receipt = transfer.receipt.clone();
    receipt.session = "previous-session".into();
    assert!(transfer.can_recover(&receipt));
    receipt.session = "../escape".into();
    assert!(!transfer.can_recover(&receipt));
    receipt.session = "valid".into();
    receipt.lease = "../escape".into();
    assert!(!transfer.can_recover(&receipt));
    receipt.lease = unique_id();
    receipt.endpoint.port += 1;
    assert!(!transfer.can_recover(&receipt));
}

#[tokio::test]
async fn recovery_skips_live_receipts_and_leaves_other_accounts_untouched() {
    let temporary = tempfile::tempdir().unwrap();
    let paths = AppPaths::from_home(temporary.path().to_path_buf());
    let transfer = transfer();
    let live = Transfer::write_receipt(&paths, transfer.receipt.clone()).unwrap();
    let probe = File::options()
        .read(true)
        .write(true)
        .open(&live.path)
        .unwrap();
    assert!(probe.try_lock().is_err());
    drop(probe);
    let mut other = transfer.receipt.clone();
    other.lease = unique_id();
    other.account = "/another-account".into();
    let foreign = Transfer::write_receipt(&paths, other).unwrap();
    let foreign_path = foreign.path.clone();
    drop(foreign);
    tokio::time::timeout(Duration::from_secs(1), transfer.recover(&paths))
        .await
        .unwrap()
        .unwrap();
    assert!(live.path.exists());
    assert!(foreign_path.exists());
    let own_path = live.path.clone();
    drop(live);
    let unlocked = File::options()
        .read(true)
        .write(true)
        .open(own_path)
        .unwrap();
    unlocked.try_lock().unwrap();
}
