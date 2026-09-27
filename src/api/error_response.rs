//! Ordinary API routes can reject a request through the shared Skill retention/admission guards.

use super::{skills::SkillResult, ErrorEnvelope, ErrorPayload};

pub(super) fn decode(body: &str) -> Option<ErrorPayload> {
    if let Ok(envelope) = serde_json::from_str::<ErrorEnvelope>(body) {
        return Some(envelope.error);
    }
    let envelope: SkillResult<serde::de::IgnoredAny> = serde_json::from_str(body).ok()?;
    if envelope.schema_version != 1
        || envelope.status != "failed"
        || envelope.committed
        || envelope.data.is_some()
        || envelope.errors.len() != 1
        || envelope
            .operation_id
            .as_ref()
            .is_some_and(|id| uuid::Uuid::parse_str(id).is_err())
    {
        return None;
    }
    let error = envelope.errors.into_iter().next()?;
    if error.code.is_empty()
        || error.code.len() > 128
        || !error
            .code
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
        || error.message.trim().is_empty()
        || error.message.len() > 4096
        || error.message.chars().any(char::is_control)
    {
        return None;
    }
    // Details may carry content diagnostics; launcher errors need only the code and message.
    Some(ErrorPayload {
        code: error.code,
        message: error.message,
    })
}
