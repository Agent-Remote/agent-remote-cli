use super::*;
use serde_json::json;

const SESSION: &str = "11111111-1111-4111-8111-111111111111";
const DEVICE: &str = "22222222-2222-4222-8222-222222222222";
const LEASE: &str = "33333333-3333-4333-8333-333333333333";
const BATCH: &str = "44444444-4444-4444-8444-444444444444";
const RECEIPT: &str = "55555555-5555-4555-8555-555555555555";

fn open() -> OpenFrame {
    serde_json::from_value(json!({
        "version": 1,
        "operation": "open",
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "lease_id": LEASE
    }))
    .unwrap()
}

fn upload() -> UploadFrame {
    serde_json::from_value(json!({
        "version": 1,
        "operation": "upload",
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "lease_id": LEASE,
        "batch_id": BATCH,
        "kind": "image",
        "name": "screenshot.png",
        "size": 4,
        "sha256": "a".repeat(64)
    }))
    .unwrap()
}

#[test]
fn exact_frames_bind_session_device_and_lease() {
    assert!(validate_open(&open(), SESSION, DEVICE, LEASE));
    assert!(validate_upload(&upload(), SESSION, DEVICE, LEASE));

    let mut changed = open();
    changed.expected_device_id = SESSION.to_owned();
    assert!(!validate_open(&changed, SESSION, DEVICE, LEASE));
    let mut changed = upload();
    changed.session_id = DEVICE.to_owned();
    assert!(!validate_upload(&changed, SESSION, DEVICE, LEASE));
    let mut changed = upload();
    changed.lease_id = DEVICE.to_owned();
    assert!(!validate_upload(&changed, SESSION, DEVICE, LEASE));
}

#[test]
fn upload_rejects_paths_limits_and_bad_digests() {
    for name in [
        "../secret",
        "folder/file",
        "folder\\file",
        ".",
        "..",
        "bad\nname",
    ] {
        let mut frame = upload();
        frame.name = name.to_owned();
        assert!(
            !validate_upload(&frame, SESSION, DEVICE, LEASE),
            "accepted {name:?}"
        );
    }
    let mut frame = upload();
    frame.size = 0;
    assert!(!validate_upload(&frame, SESSION, DEVICE, LEASE));
    frame.size = MAX_BATCH_BYTES + 1;
    assert!(!validate_upload(&frame, SESSION, DEVICE, LEASE));
    frame.size = 1;
    frame.sha256 = "not-a-digest".to_owned();
    assert!(!validate_upload(&frame, SESSION, DEVICE, LEASE));
}

#[test]
fn strict_decoding_rejects_unknown_fields_and_future_versions() {
    let mut value = json!({
        "version": 1,
        "operation": "open",
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "lease_id": LEASE
    });
    value["account"] = json!("/account");
    assert!(serde_json::from_value::<OpenFrame>(value).is_err());

    let mut future = json!({
        "version": 2,
        "operation": "open",
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "lease_id": LEASE
    });
    let frame: OpenFrame = serde_json::from_value(future.take()).unwrap();
    assert!(!validate_open(&frame, SESSION, DEVICE, LEASE));
}

#[test]
fn cleanup_receipt_unknown_is_not_success() {
    let receipt: CleanupReceipt = serde_json::from_value(json!({
        "version": 1,
        "operation": "cleanup_receipt",
        "session_id": SESSION,
        "expected_device_id": DEVICE,
        "lease_id": LEASE,
        "status": "unknown",
        "removed_batches": 0,
        "receipt_id": RECEIPT
    }))
    .unwrap();
    assert!(validate_receipt(&receipt, SESSION, DEVICE, LEASE));
    assert_eq!(receipt.status, CleanupStatus::Unknown);
    assert!(!matches!(receipt.status, CleanupStatus::Cleaned));

    let mut wrong = receipt;
    wrong.lease_id = DEVICE.to_owned();
    assert!(!validate_receipt(&wrong, SESSION, DEVICE, LEASE));
}
