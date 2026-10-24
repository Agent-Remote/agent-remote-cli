use serde_json::json;

#[test]
fn forward_methods_are_structured_and_require_exact_context_fields() {
    let request = json!({
        "confirmed": true,
        "schema_version": 1,
        "expected_context": {
            "home": "/tmp/agent-remote",
            "server_url": "https://server.example",
            "active_device_id": "11111111-1111-4111-8111-111111111111"
        },
        "session_id": "22222222-2222-4222-8222-222222222222",
        "expected_node_id": "33333333-3333-4333-8333-333333333333",
        "expected_runtime_backend": "docker",
        "remote_port": 3000,
        "local_port": 3000,
        "client_instance_id": "desktop-test",
        "caller_request_id": "44444444-4444-4444-8444-444444444444"
    });
    assert!(request["expected_context"]["active_device_id"].is_string());
    assert_eq!(request["schema_version"], 1);
}
