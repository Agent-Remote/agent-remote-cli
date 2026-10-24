use serde_json::json;
use tempfile::tempdir;

#[test]
fn device_mutations_require_confirmation_and_reject_unknown_fields_before_io() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("device-home");
    let context = json!({
        "home": home,
        "server_url": "https://server.example",
        "active_device_id": "device-test"
    });

    let (ok, response) = super::invoke(
        &home,
        &super::request(
            "device.revoke",
            json!({"confirmed":false,"expected_context":context.clone(),"device_id":"device-test"}),
        ),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "confirmation_required");
    assert!(!home.exists());

    let (ok, response) = super::invoke(
        &home,
        &super::request(
            "device.rotate_token",
            json!({"confirmed":true,"expected_context":context,"device_id":"device-test","unexpected":"secret"}),
        ),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());
}

#[test]
fn device_status_rejects_wrong_context_shape_without_initializing_home() {
    let temp = tempdir().unwrap();
    let home = temp.path().join("absent");
    let (ok, response) = super::invoke(
        &home,
        &super::request(
            "device.status",
            json!({"expected_context":{"home":home.clone(),"server_url":null,"active_device_id":null}}),
        ),
    );
    assert!(!ok);
    assert_eq!(response["error"]["code"], "authentication_required");
    assert!(!home.exists());
}
