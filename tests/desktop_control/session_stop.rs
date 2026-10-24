use super::*;

fn context(home: &std::path::Path) -> Value {
    json!({
        "home": home,
        "server_url": "http://127.0.0.1:9",
        "active_device_id": "33333333-3333-4333-8333-333333333333"
    })
}

fn stop(home: &std::path::Path) -> Value {
    json!({
        "confirmed": true,
        "schema_version": 1,
        "expected_context": context(home),
        "session_id": "44444444-4444-4444-8444-444444444444",
        "expected_node_id": "33333333-3333-4333-8333-333333333333",
        "expected_runtime_backend": "native",
        "reason": "user_requested"
    })
}

#[test]
fn stop_validates_confirmation_and_full_binding_before_io() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let mut denied = stop(&home);
    denied["confirmed"] = json!(false);
    let (_, response) = invoke(&home, &request("sessions.stop", denied));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());

    let mut invalid = stop(&home);
    invalid["expected_runtime_backend"] = json!("native\nother");
    let (_, response) = invoke(&home, &request("sessions.stop", invalid));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());
}

#[test]
fn stop_status_requires_original_context_and_uuid() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let input = json!({
        "request_id": "not-a-uuid",
        "expected_context": context(&home),
        "wait": false,
        "timeout": 1
    });
    let (_, response) = invoke(&home, &request("sessions.stop.request", input));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());
}
