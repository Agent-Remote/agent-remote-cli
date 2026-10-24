use serde_json::json;
use tempfile::tempdir;

#[test]
fn ego_browser_status_is_advertised_as_a_user_read_operation() {
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
        .find(|item| item["method"] == "ego_browser.status")
        .expect("ego_browser.status capability");
    assert_eq!(operation["effect"], "read");
    assert_eq!(operation["credential"], "user");
    assert!(operation.get("confirmation").is_none());
}

#[test]
fn ego_browser_status_rejects_unknown_fields_before_initializing_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "ego_browser.status",
            json!({"expected_context":{"home":home.clone(),"server_url":null,"active_device_id":null,"unexpected":true}}),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!home.exists());
}

#[test]
fn ego_browser_status_requires_a_configured_server_without_claiming_local_installation() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "ego_browser.status",
            json!({"expected_context":{"home":home.clone(),"server_url":null,"active_device_id":null}}),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "authentication_required");
    assert!(!home.exists());
}
