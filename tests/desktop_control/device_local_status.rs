use serde_json::json;
use tempfile::tempdir;

#[test]
fn device_local_status_is_advertised_as_a_read_only_local_operation() {
    let temp = tempdir().unwrap();
    let (ok, value) = super::invoke(
        &temp.path().join("absent"),
        &super::request("capabilities", json!({})),
    );
    assert!(ok, "{value}");
    let operation = value["result"]["operations"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["method"] == "device.local.status")
        .expect("device.local.status capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "none");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn device_local_status_rejects_unknown_fields_before_initializing_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "device.local.status",
            json!({"expected_home":home.clone(),"unexpected":true}),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!home.exists());
}
