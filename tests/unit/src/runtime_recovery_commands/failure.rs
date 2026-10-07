// Tests for src/runtime_recovery_commands/failure.rs.

use super::*;

#[test]
fn only_explicit_client_rejections_prove_this_submission_rejected() {
    for status in [None, Some(200), Some(204), Some(302), Some(500), Some(503)] {
        assert_eq!(
            RecoveryFailure::submission(status).acceptance(true),
            "unknown"
        );
    }
    for status in [400, 401, 403, 404, 409, 422, 429] {
        assert_eq!(
            RecoveryFailure::submission(Some(status)).acceptance(true),
            "rejected"
        );
    }
    assert_eq!(
        RecoveryFailure::Preparation.acceptance(true),
        "not_submitted"
    );
    assert_eq!(RecoveryFailure::Preparation.acceptance(false), "unknown");
    assert_eq!(
        RecoveryFailure::StatusUnavailable.acceptance(false),
        "unknown"
    );
}
