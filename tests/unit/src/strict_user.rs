use super::*;

fn session(expires: u64, session_expires: u64) -> SecretValue {
    SecretValue::new(
        serde_json::json!({
            "version":1,"refresh_at":50,"expires_at":expires,
            "session_expires_at":session_expires,
            "token":{"access_token":"user-access","refresh_token":"private-refresh",
                "token_type":"bearer","expires_in":100,"refresh_expires_in":1000}
        })
        .to_string(),
    )
    .unwrap()
}

#[test]
fn reads_raw_without_session_migration() {
    let value = access_token(SecretValue::new("raw-user".into()).unwrap(), 100).unwrap();
    assert_eq!(value.as_str(), "raw-user");
}

#[test]
fn expired_refresh_schedule_does_not_expire_access() {
    assert_eq!(
        access_token(session(200, 1000), 100).unwrap().as_str(),
        "user-access"
    );
}

#[test]
fn either_expiration_requires_explicit_login() {
    assert!(access_token(session(100, 1000), 100).is_err());
    assert!(access_token(session(200, 100), 100).is_err());
}

#[test]
fn malformed_session_does_not_downgrade_to_raw_token() {
    assert!(access_token(SecretValue::new("{malformed".into()).unwrap(), 100).is_err());
}
