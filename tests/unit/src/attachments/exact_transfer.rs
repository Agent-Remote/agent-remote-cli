use super::*;
use crate::api::AttachSessionData;
use serde_json::json;

const NODE: &str = "11111111-1111-4111-8111-111111111111";
const SESSION: &str = "22222222-2222-4222-8222-222222222222";
const DEVICE: &str = "33333333-3333-4333-8333-333333333333";
const KEY: &str = "44444444-4444-4444-8444-444444444444";
const LEASE: &str = "55555555-5555-4555-8555-555555555555";

fn attach() -> AttachSessionData {
    AttachSessionData {
        session_id: SESSION.into(),
        node_id: NODE.into(),
        node_wireguard_ip: "127.0.0.1".into(),
        ssh_host: "127.0.0.1".into(),
        ssh_port: 22,
        ssh_user: "agent".into(),
        tmux_session_name: "session".into(),
        command_args: vec![],
        ssh_command: String::new(),
        forward_ssh_agent: false,
        authorization_task_id: "task".into(),
        authorization_task_status: "succeeded".into(),
        expires_in: 30,
    }
}

#[test]
fn exact_transfer_requires_canonical_session_device_and_endpoint() {
    let transfer = Transfer::new(&attach(), DEVICE).unwrap();
    assert_eq!(transfer.session_id, SESSION);
    assert_eq!(transfer.expected_device_id, DEVICE);

    let mut bad = attach();
    bad.session_id = "session".into();
    assert!(Transfer::new(&bad, DEVICE).is_err());
    assert!(Transfer::new(&attach(), "device").is_err());
    bad = attach();
    bad.ssh_user = "-agent".into();
    assert!(Transfer::new(&bad, DEVICE).is_err());
}

#[test]
fn lease_offer_validation_rejects_expired_or_aliased_values() {
    let future = "2099-01-02T03:04:05.000000Z";
    assert!(future_rfc3339(future));
    assert!(!future_rfc3339("2000-01-02T03:04:05Z"));
    assert!(!future_rfc3339("2099-99-02T03:04:05Z"));

    let mut value = json!({
        "version": 1,
        "operation": "lease_offer",
        "node_id": NODE,
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "ssh_key_id": KEY,
        "lease_id": LEASE,
        "expires_at": future,
        "max_bytes": 1024,
        "max_entries": 2
    });
    let offer: LeaseOffer = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(offer.lease_id, LEASE);
    value["account_path"] = json!("/secret");
    assert!(serde_json::from_value::<LeaseOffer>(value).is_err());
}

#[test]
fn remote_paths_are_absolute_and_cannot_escape() {
    assert!(safe_remote_path(
        "/account/.agent-remote-attachments/session/lease/batch/file.png"
    ));
    for value in [
        "relative/path",
        "/account/../secret",
        "/account/.",
        "/account/a\n",
    ] {
        assert!(!safe_remote_path(value), "accepted {value:?}");
    }
}

#[test]
fn pending_receipt_is_private_and_exactly_bound() {
    let home = tempfile::tempdir().unwrap();
    let paths = crate::config::AppPaths::from_home(home.path().to_path_buf());
    let transfer = Transfer::new(&attach(), DEVICE).unwrap();
    let path = write_pending_receipt(&paths, &transfer, LEASE).unwrap();
    let value: PendingReceipt = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(value.version, 1);
    assert_eq!(value.node_id, NODE);
    assert_eq!(value.session_id, SESSION);
    assert_eq!(value.expected_device_id, DEVICE);
    assert_eq!(value.lease_id, LEASE);
    assert_eq!(value.status, "pending");
    assert_eq!(value.removed_batches, 0);
    assert!(value.receipt_id.is_none());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
}

#[test]
fn cleanup_receipt_accepts_node_and_key_identity_projection() {
    let value: CleanupReceipt = serde_json::from_value(json!({
        "version": 1,
        "operation": "cleanup_receipt",
        "node_id": NODE,
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "ssh_key_id": KEY,
        "lease_id": LEASE,
        "status": "cleaned",
        "removed_batches": 1,
        "receipt_id": "66666666-6666-4666-8666-666666666666"
    }))
    .unwrap();
    assert_eq!(value.node_id, NODE);
    assert_eq!(value.ssh_key_id, KEY);
}
