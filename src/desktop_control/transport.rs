use std::io::{self, Read, Write};

use super::{error_response, handle, valid_id, Failure, Request, VERSION};

const MAX_REQUEST: u64 = 64 * 1024;
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

/// Read one JSON request through EOF, then emit a terminal JSONL event.
/// Opt-in callers receive a bounded `started` event first; device-code login
/// may then emit its single bounded approval progress event.
/// Errors never include raw request bytes, credentials, or upstream diagnostics.
pub async fn run_stdio() -> i32 {
    let mut bytes = Vec::new();
    let response = match io::stdin().take(MAX_REQUEST + 1).read_to_end(&mut bytes) {
        Ok(_) if bytes.len() as u64 <= MAX_REQUEST => {
            let stream = stream_request(&bytes);
            if stream.is_some() && !write_started(stream.as_ref().unwrap()) {
                return 1;
            }
            handle(&bytes).await
        }
        _ => error_response(None, Failure::new("invalid_request")),
    };
    let success = response["type"] == "result";
    let Ok(mut encoded) = serde_json::to_vec(&response) else {
        return 1;
    };
    let oversized = encoded.len() >= MAX_RESPONSE;
    if oversized {
        let fallback = error_response(
            response["request_id"].as_str(),
            Failure::new("response_too_large"),
        );
        let Ok(value) = serde_json::to_vec(&fallback) else {
            return 1;
        };
        encoded = value;
    }
    encoded.push(b'\n');
    if io::stdout().lock().write_all(&encoded).is_err() || !success || oversized {
        1
    } else {
        0
    }
}

/// Return the parsed request only when it is valid enough to correlate an
/// optional progress stream. Invalid JSON, IDs, and protocol versions receive
/// the normal terminal error without a progress record.
fn stream_request(bytes: &[u8]) -> Option<Request> {
    let request = serde_json::from_slice::<Request>(bytes).ok()?;
    (request.stream_events && request.protocol_version == VERSION && valid_id(&request.request_id))
        .then_some(request)
}

fn write_started(request: &Request) -> bool {
    let event = serde_json::json!({
        "protocol_version": VERSION,
        "request_id": request.request_id,
        "type": "progress",
        "phase": "started",
        "progress": {
            "operation": request.method,
            "stage": "started"
        }
    });
    let Ok(mut bytes) = serde_json::to_vec(&event) else {
        return false;
    };
    // Progress records are bounded independently of the terminal response.
    if bytes.len() > 4096 {
        return false;
    }
    bytes.push(b'\n');
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|_| stdout.flush())
        .is_ok()
}

pub(super) fn approval(request: &Request, progress: serde_json::Value) -> Result<(), Failure> {
    let event = serde_json::json!({"protocol_version":VERSION,"request_id":request.request_id,
        "type":"progress","phase":"awaiting_approval","progress":progress});
    let mut bytes =
        serde_json::to_vec(&event).map_err(|_| Failure::new("login_outcome_unknown"))?;
    // Only the allowlisted code/link metadata reaches this stream, once per request.
    if bytes.len() > 4096 {
        return Err(Failure::new("login_outcome_unknown"));
    }
    bytes.push(b'\n');
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&bytes)
        .and_then(|_| stdout.flush())
        .map_err(|_| Failure::new("login_outcome_unknown"))
}
