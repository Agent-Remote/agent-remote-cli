use serde_json::json;
use tempfile::tempdir;

#[test]
fn device_local_plan_is_advertised_as_read_only() {
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
        .find(|item| item["method"] == "device.local.plan")
        .expect("device.local.plan capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "none");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn device_local_plan_rejects_unknown_fields_without_initializing_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "device.local.plan",
            json!({"expected_home":home.clone(),"action":"diagnose","unexpected":true}),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!home.exists());
}
