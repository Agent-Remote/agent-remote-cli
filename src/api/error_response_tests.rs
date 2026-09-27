//! Shared error parsing must preserve Skill guards reached through ordinary session APIs.

use reqwest::StatusCode;
use serde_json::{json, Value};

use super::ApiError;

fn pending_error() -> Value {
    json!({
        "schema_version": 1, "operation_id": null, "status": "failed",
        "committed": false, "retryable": false, "data": null,
        "errors": [{"code": "STATE_PENDING", "message": "session skill state is not fully retained",
            "object_id": null, "details": {"private_diagnostic": "must-not-be-rendered"}}]
    })
}

#[test]
fn ordinary_api_preserves_versioned_skill_rejections() {
    for status in [
        StatusCode::CONFLICT,
        StatusCode::FORBIDDEN,
        StatusCode::PAYLOAD_TOO_LARGE,
    ] {
        let error = ApiError::from_error_response(status, pending_error().to_string());
        assert_eq!(error.status_code(), Some(status.as_u16()));
        assert_eq!(error.code(), Some("STATE_PENDING"));
        assert_eq!(error.message(), "session skill state is not fully retained");
        assert!(!error.to_string().contains("must-not-be-rendered"));
    }
}

#[test]
fn ordinary_api_keeps_existing_error_contract() {
    let error = ApiError::from_error_response(
        StatusCode::UNAUTHORIZED,
        json!({"error":{"code":"AUTH_EXPIRED","message":"sign in again"},"request_id":"request"})
            .to_string(),
    );
    assert_eq!(error.code(), Some("AUTH_EXPIRED"));
    assert_eq!(error.message(), "sign in again");
    assert_eq!(error.status_code(), Some(401));
}

#[test]
fn malformed_skill_error_cannot_be_presented_as_authoritative_rejection() {
    for fault in [
        "version",
        "committed",
        "success",
        "data",
        "empty",
        "code",
        "message",
        "operation",
        "field",
    ] {
        let mut body = pending_error();
        match fault {
            "version" => body["schema_version"] = json!(2),
            "committed" => body["committed"] = json!(true),
            "success" => body["status"] = json!("ready"),
            "data" => body["data"] = json!({"private": "must-not-be-rendered"}),
            "empty" => body["errors"] = json!([]),
            "code" => body["errors"][0]["code"] = json!("STATE_PENDING\u{1b}[2J"),
            "message" => body["errors"][0]["message"] = json!("must-not-be-rendered\n"),
            "operation" => body["operation_id"] = json!("not-an-operation"),
            "field" => {
                body.as_object_mut().unwrap().remove("committed");
            }
            _ => unreachable!(),
        }
        let error = ApiError::from_error_response(StatusCode::CONFLICT, body.to_string());
        assert_eq!(error.code(), None, "{fault}");
        assert!(
            !error.to_string().contains("must-not-be-rendered"),
            "{fault}"
        );
        assert_eq!(error.status_code(), Some(409));
    }
}
