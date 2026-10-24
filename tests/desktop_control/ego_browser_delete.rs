use serde_json::json;
use tempfile::tempdir;

#[test]
fn delete_plan_requires_exact_target_generation_shape() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "ego_browser.delete.plan",
            json!({
                "expected_context": {"home": home.clone(), "server_url": null, "active_device_id": null},
                "target": "device", "id": "device-1", "generation": 2, "binding_generation": 1
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "invalid_params");
    assert!(!home.exists());
}

#[test]
fn delete_control_requires_explicit_confirmation_before_configuration() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, value) = super::invoke(
        &home,
        &super::request(
            "ego_browser.delete.control",
            json!({
                "confirmed": false,
                "expected_context": {"home": home.clone(), "server_url": "https://server.example", "active_device_id": null},
                "target": "binding", "id": "binding-1", "generation": 2, "binding_generation": 2
            }),
        ),
    );
    assert!(!ok);
    assert_eq!(value["error"]["code"], "confirmation_required");
    assert!(!home.exists());
}
