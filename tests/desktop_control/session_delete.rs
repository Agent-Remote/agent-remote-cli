use super::*;

fn context(home: &std::path::Path) -> Value {
    json!({
        "home": home,
        "server_url": "http://127.0.0.1:9",
        "active_device_id": "33333333-3333-4333-8333-333333333333"
    })
}

fn delete(home: &std::path::Path) -> Value {
    let ids = vec![
        "44444444-4444-4444-8444-444444444444".to_string(),
        "55555555-5555-4555-8555-555555555555".to_string(),
    ];
    let selection = json!({
        "tool_type": "claude",
        "statuses": ["failed", "interrupted", "stopped"],
        "project_key": Value::Null
    });
    let value = json!({
        "confirmed": true,
        "schema_version": 1,
        "expected_context": context(home),
        "tool_type": "claude",
        "session_ids": ids,
        "selection": selection,
        "selection_digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        "intent_fingerprint": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
        "reason": "user_requested"
    });
    value
}

#[test]
fn delete_validates_confirmation_and_frozen_collection_before_io() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let mut denied = delete(&home);
    denied["confirmed"] = json!(false);
    let (_, response) = invoke(&home, &request("sessions.delete", denied));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());

    let mut invalid = delete(&home);
    invalid["session_ids"][0] = json!("not-a-uuid");
    let (_, response) = invoke(&home, &request("sessions.delete", invalid));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());
}

#[test]
fn delete_status_requires_original_context_and_uuid() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("absent");
    let input = json!({
        "request_id": "not-a-uuid",
        "expected_context": context(&home),
        "wait": false,
        "timeout": 1
    });
    let (_, response) = invoke(&home, &request("sessions.delete.request", input));
    assert_eq!(response["error"]["code"], "invalid_params");
    assert!(!home.exists());
}
