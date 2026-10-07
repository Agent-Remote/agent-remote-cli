// Tests for src/api/runtime_recovery.rs.

use super::*;

#[test]
fn recovery_never_accepts_a_different_original_or_terminal_shape() {
    let account = "11111111-1111-4111-8111-111111111111";
    let key = "22222222-2222-4222-8222-222222222222";
    let original = format!("migrate_tool_account_runtime:{account}:{key}");
    let mut data = RuntimeRecovery {
        binding: RecoveryBinding {
            version: 1,
            action: None,
            task_id: format!("recover_tool_account_runtime:{account}:{key}"),
            task_record_id: "33333333-3333-4333-8333-333333333333".into(),
            original_task_id: original.clone(),
            original_task_record_id: "44444444-4444-4444-8444-444444444444".into(),
            node_id: key.into(),
            user_id: key.into(),
            tool_account_id: account.into(),
            tool_type: "claude".into(),
            source_runtime_backend: "docker_sandbox".into(),
            target_runtime_backend: "native".into(),
        },
        status: RecoveryStatus::Succeeded,
    };
    assert!(data.validate(account, key, Some(&original), None).is_ok());
    assert!(data.validate(account, key, Some("other"), None).is_err());
    assert!(data
        .validate(
            account,
            key,
            Some(&original),
            Some(RecoveryAction::VerifySource)
        )
        .is_err());
    data.binding.action = Some(RecoveryAction::VerifySource);
    assert!(data.validate(account, key, None, None).is_err());
    data.binding.version = 2;
    data.binding.action = Some(RecoveryAction::VerifySource);
    assert!(data.validate(account, key, Some(&original), None).is_err());
    assert!(data
        .validate(
            account,
            key,
            Some(&original),
            Some(RecoveryAction::VerifySource)
        )
        .is_ok());
    assert!(data.validate(account, key, None, None).is_ok());
    data.binding.action = Some(RecoveryAction::RepairSource);
    assert!(data.validate(account, key, None, None).is_err());
    data.binding.version = 3;
    assert!(data
        .validate(
            account,
            key,
            Some(&original),
            Some(RecoveryAction::RepairSource)
        )
        .is_ok());
    assert!(data
        .validate(
            account,
            key,
            Some(&original),
            Some(RecoveryAction::VerifySource)
        )
        .is_err());
    assert!(data.validate(account, key, None, None).is_ok());
    let mut wire = serde_json::to_value(&data.binding).unwrap();
    wire["action"] = serde_json::Value::Null;
    assert!(serde_json::from_value::<RecoveryBinding>(wire).is_err());
    data.binding.task_record_id = data.binding.original_task_record_id.clone();
    assert!(data
        .validate(
            account,
            key,
            Some(&original),
            Some(RecoveryAction::VerifySource)
        )
        .is_err());
    assert!(serde_json::from_str::<RecoveryStatus>("\"ready\"").is_err());
    assert!(!canonical_uuid("00000000-0000-0000-0000-000000000000"));
}
