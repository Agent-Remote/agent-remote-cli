// Tests for src/ego_browser.rs.

use anyhow::anyhow;
use tempfile::tempdir;

use super::{
    candidate_matches_selection, canonical_full_uuid, classify_switch_local_identity,
    close_local_admission, device_store_dir, ensure_device_store_dir, forget_this_mac,
    load_local_device_metadata, load_pending_revocation, load_trust_confirmation,
    local_admission_path, local_admission_state, local_binding_is_connected,
    local_bridge_installation_exists, local_device_is_registered, map_api_error_fields,
    map_operational_error, next_switch_server_stage, parse_lifecycle_binding_selection,
    pending_revocation_next_command, project_status_state, reconcile_switch_server_progress,
    reject_pending_revocation, render_status_json, resolve_local_handoff_target,
    select_bridge_installer, select_candidate_with_interactivity,
    select_lifecycle_binding_with_interactivity, set_local_admission_state,
    trust_confirmation_matches, trust_confirmation_path, validate_local_active_binding_handoff,
    write_pending_revocation, write_trust_confirmation, BridgeInstallerSource, BridgeTrustEvidence,
    LocalActiveBindingHandoff, LocalAdmissionRecord, LocalAdmissionSnapshot, LocalDeviceMetadata,
    LocalTrustConfirmation, PendingRevocation, SwitchLocalIdentity, SwitchServerStage,
};
#[cfg(unix)]
use super::{
    managed_device_client_at_root, migrate_legacy_device_store_paths,
    move_store_files_transactionally,
};
use crate::api::{EgoBrowserBindingCandidateData, EgoBrowserBindingData, EgoBrowserDeviceData};
use crate::cli::EgoBrowserForgetArgs;
use crate::config::{AppPaths, Config};
use crate::identifiers::short_id;
use crate::local_state::LocalState;

#[test]
fn canonicalizes_full_uuid_variants_before_delegation() {
    assert_eq!(
        canonical_full_uuid("149AEF7A-BA99-4BD5-A0E9-BAF1A2635C09"),
        Some("149aef7a-ba99-4bd5-a0e9-baf1a2635c09".to_string())
    );
    assert_eq!(
        canonical_full_uuid("149aef7aba994bd5a0e9baf1a2635c09"),
        Some("149aef7a-ba99-4bd5-a0e9-baf1a2635c09".to_string())
    );
}

#[test]
fn missing_bridge_setup_selects_the_authenticated_bootstrap() {
    assert_eq!(
        select_bridge_installer("setup", Vec::new()).unwrap(),
        BridgeInstallerSource::ManagedBootstrap
    );
}

#[cfg(unix)]
#[test]
fn existing_bridge_setup_selects_only_the_current_release_installer() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let installer = directory.path().join("current/installer/install-macos.sh");
    std::fs::create_dir_all(installer.parent().unwrap()).unwrap();
    std::fs::write(&installer, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o500)).unwrap();

    assert_eq!(
        select_bridge_installer("setup", [installer.clone()]).unwrap(),
        BridgeInstallerSource::Installed(installer)
    );
}

#[cfg(unix)]
#[test]
fn retained_release_device_client_rejects_links_and_unsafe_modes() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let directory = tempdir().unwrap();
    let root = directory.path().join("managed");
    let bin = root
        .join("releases")
        .join(crate::bridge_release::MANAGED_BRIDGE_VERSION)
        .join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    for path in [
        root.as_path(),
        root.join("releases").as_path(),
        root.join("releases")
            .join(crate::bridge_release::MANAGED_BRIDGE_VERSION)
            .as_path(),
        bin.as_path(),
    ] {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let client = bin.join("ego-browser-device");
    std::fs::write(&client, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o500)).unwrap();
    assert_eq!(managed_device_client_at_root(&root), Some(client.clone()));

    let hard_link = bin.join("ego-browser-device.hard-link");
    std::fs::hard_link(&client, &hard_link).unwrap();
    assert_eq!(managed_device_client_at_root(&root), None);
    std::fs::remove_file(hard_link).unwrap();

    std::fs::set_permissions(&client, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(managed_device_client_at_root(&root), None);
    std::fs::remove_file(&client).unwrap();
    let outside = directory.path().join("outside-device-client");
    std::fs::write(&outside, b"#!/bin/sh\nexit 0\n").unwrap();
    symlink(&outside, &client).unwrap();
    assert_eq!(managed_device_client_at_root(&root), None);
}

#[cfg(unix)]
#[test]
fn bridge_upgrade_always_selects_the_fixed_profile_bootstrap() {
    use std::os::unix::fs::PermissionsExt;

    let directory = tempdir().unwrap();
    let installer = directory.path().join("current/installer/install-macos.sh");
    std::fs::create_dir_all(installer.parent().unwrap()).unwrap();
    std::fs::write(&installer, b"#!/bin/sh\nexit 0\n").unwrap();
    std::fs::set_permissions(&installer, std::fs::Permissions::from_mode(0o500)).unwrap();

    assert_eq!(
        select_bridge_installer("upgrade", [installer]).unwrap(),
        BridgeInstallerSource::ManagedBootstrap
    );
}

#[test]
fn maps_server_enrollment_admission_errors_to_the_enrollment_next_step() {
    let rendered = format!(
        "{:#}",
        map_api_error_fields(Some(503), "EGO_BROWSER_ENROLLMENT_DISABLED", "setup")
    );
    assert!(rendered.contains("error_code=admission_disabled"));
    assert!(rendered.contains("admission=server_enrollment_closed"));
    assert!(rendered.contains("next_action=request_enrollment_admission"));
}

#[test]
fn maps_server_execution_admission_errors_to_the_execution_next_step() {
    let rendered = format!(
        "{:#}",
        map_api_error_fields(
            Some(503),
            "EGO_BROWSER_EXECUTION_ADMISSION_DISABLED",
            "connect"
        )
    );
    assert!(rendered.contains("error_code=admission_disabled"));
    assert!(rendered.contains("admission=server_execution_closed"));
    assert!(rendered.contains("next_action=request_execution_admission"));
}

#[test]
fn maps_missing_admission_split_to_a_stable_capability_error() {
    let rendered = format!(
        "{:#}",
        map_api_error_fields(Some(200), "SERVER_CAPABILITY_UNAVAILABLE", "setup")
    );
    assert!(rendered.contains("error_code=server_capability_unavailable"));
    assert!(rendered.contains("next_action=repair"));
}

#[test]
fn normalizes_new_server_error_families_without_leaking_raw_codes() {
    let expired = map_api_error_fields(Some(401), "AUTH_TOKEN_EXPIRED", "upgrade").to_string();
    assert!(expired.contains("error_code=login_required"));
    assert!(expired.contains("next_command=agent-remote login"));
    let idempotency = format!(
        "{:#}",
        map_api_error_fields(Some(409), "EGO_BROWSER_IDEMPOTENCY_CONFLICT", "setup")
    );
    assert!(idempotency.contains("error_code=operation_conflict"));
    assert!(idempotency.contains("next_action=retry"));

    let join_code = format!(
        "{:#}",
        map_api_error_fields(Some(410), "NODE_JOIN_CODE_REPLAYED", "setup")
    );
    assert!(join_code.contains("error_code=node_join_code_error"));
    assert!(!join_code.contains("NODE_JOIN_CODE_REPLAYED"));

    let unknown = format!(
        "{:#}",
        map_api_error_fields(Some(500), "UNTRUSTED_SERVER_DETAIL", "setup")
    );
    assert!(unknown.contains("error_code=control_plane_error"));
    assert!(!unknown.contains("UNTRUSTED_SERVER_DETAIL"));
}

#[test]
fn preserves_only_the_stable_missing_installer_code() {
    let rendered = format!(
        "{:#}",
        map_operational_error(anyhow!("bridge_installer_unavailable: missing"), "setup")
    );
    assert!(rendered.contains("error_code=bridge_installer_unavailable"));
    assert!(rendered.contains("next_action=install_bridge"));
    assert!(!rendered.contains("missing"));
}

#[test]
fn maps_claim_and_resume_device_failures_to_lifecycle_fields() {
    let claim = format!(
        "{:#}",
        map_operational_error(
            anyhow!("independent Device Client failed (admission_disabled)"),
            "claim"
        )
    );
    assert!(claim.contains("error_code=admission_disabled"));
    assert!(claim.contains("admission=server_execution_closed"));
    assert!(claim.contains("next_action=request_execution_admission"));

    let resume = format!(
        "{:#}",
        map_operational_error(
            anyhow!("independent Device Client failed (device_revoked)"),
            "resume"
        )
    );
    assert!(resume.contains("error_code=device_revoked"));
    assert!(resume.contains("next_action=forget"));

    let origin = format!(
        "{:#}",
        map_operational_error(
            anyhow!("independent Device Client failed (identity_origin_conflict)"),
            "setup"
        )
    );
    assert!(origin.contains("error_code=identity_origin_conflict"));
    assert!(origin.contains("next_action=forget"));
}

#[test]
fn validates_owner_only_binding_handoff_shape_before_use() {
    let valid = LocalActiveBindingHandoff {
        version: 1,
        binding_id: "11111111-2222-3333-4444-555555555555".to_owned(),
        generation: 4,
        device_id: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee".to_owned(),
        task_space_label: "agent-remote:11111111-2222-3333-4444-555555555555".to_owned(),
        authorization_mode: "ego_browser_script_full_trust".to_owned(),
        user_confirmation: true,
    };
    assert!(validate_local_active_binding_handoff(&valid).is_ok());

    let mut invalid = valid;
    invalid.user_confirmation = false;
    assert!(validate_local_active_binding_handoff(&invalid).is_err());
}

#[test]
fn setup_retry_closes_existing_local_admission_before_mutation() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    set_local_admission_state(&paths, "ready").unwrap();
    close_local_admission(&paths).unwrap();
    assert_eq!(local_admission_state(&paths).unwrap(), "closed");
}

#[test]
fn open_local_admission_requires_matching_handoff_and_metadata() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let store = device_store_dir(&paths);
    ensure_device_store_dir(&store).unwrap();

    std::fs::write(
        store.join("ego-browser-credential.json"),
        serde_json::json!({
            "version": 1,
            "device_id": "device-open",
            "server_url": "https://control.example",
            "token": "egbc_test-token",
            "credential_id": "credential-open",
            "release_profile": "community-local-trust",
            "credential_profile": "community_file",
            "expires_at_unix": 4_000_000_000_u64,
            "revision": 1,
            "device_generation": 7
        })
        .to_string(),
    )
    .unwrap();
    std::fs::write(
        store.join("ego-browser-active-binding.json"),
        serde_json::json!({
            "version": 1,
            "binding_id": "binding-open",
            "generation": 11,
            "device_id": "device-open",
            "task_space_label": "agent-remote:11111111-2222-3333-4444-555555555555",
            "authorization_mode": "ego_browser_script_full_trust",
            "user_confirmation": true
        })
        .to_string(),
    )
    .unwrap();
    crate::platform::set_owner_only_permissions(&store.join("ego-browser-credential.json"))
        .unwrap();
    crate::platform::set_owner_only_permissions(&store.join("ego-browser-active-binding.json"))
        .unwrap();

    set_local_admission_state(&paths, "open").unwrap();
    let record = serde_json::from_slice::<serde_json::Value>(
        &std::fs::read(local_admission_path(&paths)).unwrap(),
    )
    .unwrap();
    assert_eq!(record["device_id"], "device-open");
    assert_eq!(record["device_generation"], 7);
    assert_eq!(record["binding_id"], "binding-open");
    assert_eq!(record["binding_generation"], 11);

    std::fs::write(
        store.join("ego-browser-active-binding.json"),
        serde_json::json!({
            "version": 1,
            "binding_id": "binding-open",
            "generation": 11,
            "device_id": "different-device",
            "task_space_label": "agent-remote:11111111-2222-3333-4444-555555555555",
            "authorization_mode": "ego_browser_script_full_trust",
            "user_confirmation": true
        })
        .to_string(),
    )
    .unwrap();
    crate::platform::set_owner_only_permissions(&store.join("ego-browser-active-binding.json"))
        .unwrap();
    assert!(set_local_admission_state(&paths, "open").is_err());
}

#[test]
fn unknown_legacy_admission_projection_fails_closed() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state
        .set_kv("ego-browser-local-admission", "unexpected")
        .unwrap();
    assert!(local_admission_state(&paths).is_err());
}

#[test]
fn malformed_shared_admission_is_not_hidden_by_legacy_projection() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    state.set_kv("ego-browser-local-admission", "open").unwrap();
    let admission_path = local_admission_path(&paths);
    ensure_device_store_dir(&device_store_dir(&paths)).unwrap();
    std::fs::write(&admission_path, b"{not-json").unwrap();
    crate::platform::set_owner_only_permissions(&admission_path).unwrap();
    assert!(local_admission_state(&paths).is_err());
}

#[test]
fn local_handoff_target_uses_exact_generation_without_server_lookup() {
    let handoff = LocalActiveBindingHandoff {
        version: 1,
        binding_id: "binding-local".to_owned(),
        generation: 9,
        device_id: "device-local".to_owned(),
        task_space_label: "agent-remote:11111111-2222-3333-4444-555555555555".to_owned(),
        authorization_mode: "ego_browser_script_full_trust".to_owned(),
        user_confirmation: true,
    };
    let args = crate::cli::EgoBrowserLifecycleArgs {
        binding: None,
        generation: 0,
        binding_generation: Some(9),
        yes: true,
    };
    assert_eq!(
        resolve_local_handoff_target(&handoff, &args, "open").unwrap(),
        ("binding-local".to_owned(), 9)
    );
    let stale = crate::cli::EgoBrowserLifecycleArgs {
        binding_generation: Some(8),
        ..args
    };
    let error = resolve_local_handoff_target(&handoff, &stale, "open")
        .unwrap_err()
        .to_string();
    assert!(error.contains("error_code=binding_generation_stale"));
    assert!(error.contains("admission=open"));
}

#[test]
fn trust_confirmation_round_trips_as_owner_only_state() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let confirmation = LocalTrustConfirmation {
        version: 2,
        profile_id: "community-local-trust".to_owned(),
        profile_version: "0.1.12".to_owned(),
        bridge_version: "0.1.12".to_owned(),
        signer_certificate_sha256: "a".repeat(64),
    };
    write_trust_confirmation(&paths, &confirmation).unwrap();
    assert_eq!(load_trust_confirmation(&paths).unwrap(), Some(confirmation));
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(trust_confirmation_path(&paths))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn legacy_trust_confirmation_requires_the_exact_new_profile_tuple() {
    let evidence = BridgeTrustEvidence {
        profile_id: "community-local-trust".to_owned(),
        profile_version: "0.1.12".to_owned(),
        bridge_version: "0.1.12".to_owned(),
        signer_certificate_sha256: "a".repeat(64),
    };
    let legacy = LocalTrustConfirmation {
        version: 1,
        profile_id: evidence.profile_id.clone(),
        profile_version: String::new(),
        bridge_version: String::new(),
        signer_certificate_sha256: evidence.signer_certificate_sha256.clone(),
    };
    assert!(!trust_confirmation_matches(&legacy, &evidence));
    let current = LocalTrustConfirmation {
        version: 2,
        profile_id: evidence.profile_id.clone(),
        profile_version: evidence.profile_version.clone(),
        bridge_version: evidence.bridge_version.clone(),
        signer_certificate_sha256: evidence.signer_certificate_sha256.clone(),
    };
    assert!(trust_confirmation_matches(&current, &evidence));
    for changed in [
        BridgeTrustEvidence {
            profile_version: "0.1.13".to_owned(),
            ..evidence.clone()
        },
        BridgeTrustEvidence {
            bridge_version: "0.1.13".to_owned(),
            ..evidence.clone()
        },
        BridgeTrustEvidence {
            signer_certificate_sha256: "b".repeat(64),
            ..evidence.clone()
        },
    ] {
        assert!(!trust_confirmation_matches(&current, &changed));
    }
}

#[test]
fn trust_confirmation_rejects_uppercase_or_wrong_pin() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let path = trust_confirmation_path(&paths);
    paths.ensure_base_dirs().unwrap();
    std::fs::write(
        &path,
        serde_json::json!({
            "version": 1,
            "release_profile": "community-local-trust",
            "signer_certificate_sha256": "A".repeat(64)
        })
        .to_string(),
    )
    .unwrap();
    crate::platform::set_owner_only_permissions(&path).unwrap();
    assert!(load_trust_confirmation(&paths).is_err());
}

#[test]
fn status_installation_projection_uses_managed_local_artifacts() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    assert!(!local_bridge_installation_exists(&paths));
    let bin = paths.home().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(bin.join("ego-browser-device"), b"shim").unwrap();
    assert!(local_bridge_installation_exists(&paths));
}

#[test]
fn status_projection_requires_local_installation_and_ready_supervisor() {
    let removed = project_status_state(false, true, true, true, false, true);
    assert!(!removed.installed);
    assert!(removed.registered);
    assert!(!removed.enabled);
    assert!(!removed.available);
    assert!(!removed.connected);

    let closed = project_status_state(true, true, true, false, false, true);
    assert!(closed.enabled);
    assert!(!closed.available);
    assert!(!closed.connected);

    let unregistered = project_status_state(true, false, true, true, false, false);
    assert!(unregistered.enabled);
    assert!(!unregistered.registered);
    assert!(!unregistered.available);

    let execution_closed = project_status_state(true, true, false, true, false, false);
    assert!(execution_closed.enabled);
    assert!(!execution_closed.available);

    let ready = project_status_state(true, true, true, true, false, false);
    assert!(ready.available);
    assert!(!ready.connected);

    let open = project_status_state(true, true, true, true, false, true);
    assert!(open.available);
    assert!(open.connected);
}

#[test]
fn status_projection_pending_revocation_closes_execution() {
    let pending = project_status_state(true, true, true, true, true, true);
    assert!(pending.enabled);
    assert!(!pending.available);
    assert!(!pending.connected);
}

fn binding_candidate(tool_session_id: &str) -> EgoBrowserBindingCandidateData {
    EgoBrowserBindingCandidateData {
        tool_session_id: tool_session_id.to_owned(),
        tool_type: "claude".to_owned(),
        tool_account_id: "account-local".to_owned(),
        workspace_id: "workspace-local".to_owned(),
        project_key: "project-local".to_owned(),
        display_name: "Local project".to_owned(),
        status: "running".to_owned(),
        node_id: "node-local".to_owned(),
        runtime_backend: "host".to_owned(),
        current_ego_browser_device_id: None,
        current_ego_browser_device_name: None,
        binding_id: None,
        controllable: true,
    }
}

#[test]
fn candidate_selection_fails_closed_without_tty_and_for_ambiguous_prefixes() {
    let candidates = [
        binding_candidate("149aef7a-ba99-4bd5-a0e9-baf1a2635c09"),
        binding_candidate("149aef7a-ba99-4bd5-a0e9-baf1a2635c10"),
    ];

    let non_interactive = format!(
        "{:#}",
        select_candidate_with_interactivity(&candidates, None, false).unwrap_err()
    );
    assert!(non_interactive.contains("error_code=confirmation_required"));
    assert!(non_interactive.contains("next_action=select_session"));

    let ambiguous = format!(
        "{:#}",
        select_candidate_with_interactivity(&candidates, Some("149aef7aba99"), true).unwrap_err()
    );
    assert!(ambiguous.contains("error_code=confirmation_required"));
    assert!(ambiguous.contains("next_action=select_session"));
}

#[test]
fn candidate_selection_accepts_displayed_ids_and_rejects_uncontrollable_sessions() {
    let id = "149aef7a-ba99-4bd5-a0e9-baf1a2635c09";
    let mut hidden = binding_candidate("149aef7a-ba99-4bd5-a0e9-baf1a2635c10");
    hidden.controllable = false;
    let candidates = [binding_candidate(id), hidden];
    for reference in [
        id.to_owned(),
        short_id(id),
        short_id(id).to_uppercase(),
        "149aef7a-ba99".into(),
    ] {
        let selected =
            select_candidate_with_interactivity(&candidates, Some(&reference), false).unwrap();
        assert_eq!(selected.tool_session_id, id);
    }
    for (reference, code) in [
        (
            "149aef7a-ba99-4bd5-a0e9-baf1a2635c10",
            "no_session_candidate",
        ),
        ("not-a-uuid", "invalid_session_reference"),
        ("149", "invalid_session_reference"),
    ] {
        let error =
            select_candidate_with_interactivity(&candidates, Some(reference), false).unwrap_err();
        assert!(error.to_string().contains(&format!("error_code={code}")));
    }
}

#[test]
fn candidate_fingerprint_detects_requery_drift_before_claim() {
    let selected = binding_candidate("session-alpha");
    assert!(candidate_matches_selection(&selected, &selected.clone()));

    let mut drifted = selected.clone();
    drifted.node_id = "node-reassigned".to_owned();
    assert!(!candidate_matches_selection(&selected, &drifted));

    let mut no_longer_controllable = selected.clone();
    no_longer_controllable.controllable = false;
    assert!(!candidate_matches_selection(
        &selected,
        &no_longer_controllable
    ));
}

fn status_local_device() -> LocalDeviceMetadata {
    LocalDeviceMetadata {
        device_id: "device-local".to_owned(),
        device_generation: 7,
        server_url: "https://control.example".to_owned(),
        release_profile: "community-local-trust".to_owned(),
        credential_profile: "community_file".to_owned(),
        credential_revision: 1,
        credential_expires_at_unix: 4_000_000_000,
    }
}

fn status_server_device(id: &str, generation: u64, status: &str) -> EgoBrowserDeviceData {
    EgoBrowserDeviceData {
        id: id.to_owned(),
        generation,
        device_generation: Some(generation),
        status: status.to_owned(),
        release_profile: "community-local-trust".to_owned(),
        bridge_version: Some("0.1.11".to_owned()),
        local_ego_browser_runtime_version: Some("0.4.7.4".to_owned()),
        ego_lite_runtime_version: Some("0.4.7.4".to_owned()),
        skill_version: Some("1.2.3".to_owned()),
    }
}

fn status_server_binding(
    id: &str,
    device_id: &str,
    generation: u64,
    lease_health: &str,
) -> EgoBrowserBindingData {
    EgoBrowserBindingData {
        id: id.to_owned(),
        ego_browser_device_id: device_id.to_owned(),
        tool_session_id: "session-local".to_owned(),
        node_id: "node-local".to_owned(),
        status: "active".to_owned(),
        relay_binding_kind: "device_relay".to_owned(),
        authorization_mode: "ego_browser_script_full_trust".to_owned(),
        release_profile: "community-local-trust".to_owned(),
        local_runtime_version: Some("0.4.7.4".to_owned()),
        ego_lite_runtime_version: Some("0.4.7.4".to_owned()),
        skill_version: Some("1.2.3".to_owned()),
        bridge_protocol_version: "ego-browser-bridge-v1".to_owned(),
        allowlist_revision: 1,
        learning_bundle_digest: None,
        lease_until: Some("2099-01-02T03:04:05Z".to_owned()),
        lease_health: lease_health.to_owned(),
        generation,
        binding_generation: Some(generation),
        connected_at: Some("2099-01-01T03:04:05Z".to_owned()),
        stop_reason: None,
    }
}

#[test]
fn lifecycle_target_fails_closed_without_tty_when_multiple_are_eligible() {
    let first = status_server_binding("binding-first", "device-local", 7, "healthy");
    let second = status_server_binding("binding-second", "device-local", 8, "healthy");
    let eligible = vec![&first, &second];

    let error = format!(
        "{:#}",
        select_lifecycle_binding_with_interactivity(&eligible, false, false, "open").unwrap_err()
    );
    assert!(error.contains("error_code=confirmation_required"));
    assert!(error.contains("state=multiple_bindings"));
    assert!(error.contains("next_action=select_binding"));
}

#[test]
fn paused_handoff_recovers_newer_generation_without_changing_identity() {
    let handoff = LocalActiveBindingHandoff {
        version: 1,
        binding_id: "binding-local".into(),
        generation: 3,
        device_id: "device-local".into(),
        task_space_label: "agent-remote:session-local".into(),
        authorization_mode: "ego_browser_script_full_trust".into(),
        user_confirmation: true,
    };
    let mut current = status_server_binding("binding-local", "device-local", 4, "healthy");
    current.status = "paused".into();
    for resume in [true, false] {
        let refreshed =
            super::reconciled_lifecycle_handoff(&handoff, &current, resume, "ready").unwrap();
        assert_eq!(refreshed.generation, 4);
        assert_eq!(handoff.generation, 3);
    }
    current.ego_browser_device_id = "different-device".into();
    assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true, "ready").is_err());
    current.ego_browser_device_id = handoff.device_id.clone();
    current.tool_session_id = "different-session".into();
    assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true, "ready").is_err());
    current.tool_session_id = "session-local".into();
    current.binding_generation = Some(2);
    assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true, "ready").is_err());
}

#[test]
fn lifecycle_target_automatically_selects_the_only_eligible_binding() {
    let binding = status_server_binding("binding-only", "device-local", 7, "healthy");
    let eligible = vec![&binding];

    let selected =
        select_lifecycle_binding_with_interactivity(&eligible, false, false, "open").unwrap();
    assert_eq!(selected.id, "binding-only");
}

#[test]
fn lifecycle_target_interactive_index_selection_is_strict_and_bounded() {
    assert_eq!(parse_lifecycle_binding_selection(" 2\n", 3).unwrap(), 1);
    for invalid in ["", "0", "4", "two", "1 2"] {
        let error = format!(
            "{:#}",
            parse_lifecycle_binding_selection(invalid, 3).unwrap_err()
        );
        assert!(error.contains("invalid binding selection"));
    }
}

#[test]
fn status_registration_requires_the_exact_local_device_and_origin() {
    let metadata = status_local_device();
    let unrelated = status_server_device("device-other", 7, "active");
    assert!(!local_device_is_registered(
        &metadata,
        "https://control.example",
        &[unrelated]
    ));

    let wrong_generation = status_server_device("device-local", 8, "active");
    assert!(!local_device_is_registered(
        &metadata,
        "https://control.example",
        &[wrong_generation]
    ));

    let matching = status_server_device("device-local", 7, "active");
    assert!(local_device_is_registered(
        &metadata,
        "https://control.example",
        std::slice::from_ref(&matching)
    ));
    assert!(!local_device_is_registered(
        &metadata,
        "https://other.example",
        &[matching]
    ));
}

#[test]
fn status_connection_ignores_unrelated_or_stale_server_bindings() {
    let metadata = status_local_device();
    let admission = LocalAdmissionSnapshot {
        state: "open".to_owned(),
        record: Some(LocalAdmissionRecord {
            version: 1,
            state: "open".to_owned(),
            device_id: Some(metadata.device_id.clone()),
            device_generation: Some(metadata.device_generation),
            binding_id: Some("binding-local".to_owned()),
            binding_generation: Some(11),
            updated_at_unix: 1,
        }),
    };
    let unrelated = status_server_binding("binding-other", "device-local", 11, "healthy");
    assert!(!local_binding_is_connected(
        &admission,
        Some(&metadata),
        "https://control.example",
        &[unrelated]
    ));

    let wrong_device = status_server_binding("binding-local", "device-other", 11, "healthy");
    let wrong_generation = status_server_binding("binding-local", "device-local", 12, "healthy");
    let grace = status_server_binding("binding-local", "device-local", 11, "renewal_grace");
    assert!(!local_binding_is_connected(
        &admission,
        Some(&metadata),
        "https://control.example",
        &[wrong_device, wrong_generation, grace]
    ));

    let matching = status_server_binding("binding-local", "device-local", 11, "healthy");
    assert!(local_binding_is_connected(
        &admission,
        Some(&metadata),
        "https://control.example",
        &[matching]
    ));
}

#[test]
fn status_json_fails_closed_on_malformed_present_local_admission() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let store = device_store_dir(&paths);
    ensure_device_store_dir(&store).unwrap();
    std::fs::write(local_admission_path(&paths), b"{not-json").unwrap();
    crate::platform::set_owner_only_permissions(&local_admission_path(&paths)).unwrap();

    assert!(render_status_json(
        &paths,
        "https://control.example",
        &[],
        &[],
        None,
        None,
        false,
    )
    .is_err());
}

#[test]
fn optional_local_metadata_distinguishes_absence_from_corruption() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    assert!(load_local_device_metadata(&paths).unwrap().is_none());

    let store = device_store_dir(&paths);
    ensure_device_store_dir(&store).unwrap();
    let credential = store.join("ego-browser-credential.json");
    std::fs::write(&credential, b"{}").unwrap();
    crate::platform::set_owner_only_permissions(&credential).unwrap();
    assert!(load_local_device_metadata(&paths).is_err());
}

#[cfg(unix)]
fn create_private_store_file(path: &std::path::Path, contents: &[u8]) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::write(path, contents).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

#[cfg(unix)]
fn create_private_store_directory(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    std::fs::create_dir_all(path).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[cfg(unix)]
#[test]
fn legacy_store_migration_moves_valid_state_without_overwrite() {
    let directory = tempdir().unwrap();
    let home = directory.path();
    let legacy = home.join(".config/agent-remote/ego-browser-device");
    let canonical = home.join(".config/agent-remote-ego-browser");
    create_private_store_directory(&legacy);
    create_private_store_file(&legacy.join("ego-browser-credential.json"), b"credential");
    create_private_store_file(&legacy.join("ego-browser-device-key.bin"), b"key");

    migrate_legacy_device_store_paths(home, &legacy, &canonical).unwrap();

    assert_eq!(
        std::fs::read(canonical.join("ego-browser-credential.json")).unwrap(),
        b"credential"
    );
    assert_eq!(
        std::fs::read(canonical.join("ego-browser-device-key.bin")).unwrap(),
        b"key"
    );
    assert!(!legacy.exists());
}

#[cfg(unix)]
#[test]
fn legacy_store_migration_rejects_parent_symlinks_before_creating_canonical_state() {
    use std::os::unix::fs::symlink;

    let directory = tempdir().unwrap();
    let home = directory.path().join("home");
    let redirected = directory.path().join("redirected-config");
    std::fs::create_dir_all(&home).unwrap();
    std::fs::create_dir_all(redirected.join("agent-remote")).unwrap();
    symlink(&redirected, home.join(".config")).unwrap();
    let legacy = home.join(".config/agent-remote/ego-browser-device");
    let canonical = home.join(".config/agent-remote-ego-browser");
    create_private_store_directory(&legacy);
    create_private_store_file(&legacy.join("ego-browser-credential.json"), b"credential");

    let error = migrate_legacy_device_store_paths(&home, &legacy, &canonical).unwrap_err();

    assert!(format!("{error:#}").contains("parent path is unsafe"));
    assert!(!redirected.join("agent-remote-ego-browser").exists());
    assert!(legacy.join("ego-browser-credential.json").exists());
}

#[cfg(unix)]
#[test]
fn legacy_store_migration_rejects_nested_locations() {
    let directory = tempdir().unwrap();
    let home = directory.path();
    let legacy = home.join("store");
    let canonical = legacy.join("canonical");
    let error = migrate_legacy_device_store_paths(home, &legacy, &canonical).unwrap_err();
    assert!(format!("{error:#}").contains("must not overlap"));
}

#[cfg(unix)]
#[test]
fn legacy_store_transaction_rolls_back_a_mid_move_conflict() {
    let directory = tempdir().unwrap();
    let legacy = directory.path().join("legacy");
    let canonical = directory.path().join("canonical");
    create_private_store_directory(&legacy);
    create_private_store_directory(&canonical);
    let first_source = legacy.join("ego-browser-credential.json");
    let second_source = legacy.join("ego-browser-policy.json");
    let first_destination = canonical.join("ego-browser-credential.json");
    let second_destination = canonical.join("ego-browser-policy.json");
    create_private_store_file(&first_source, b"first");
    create_private_store_file(&second_source, b"second");
    create_private_store_file(&second_destination, b"conflict");

    let error = move_store_files_transactionally(&[
        (first_source.clone(), first_destination.clone()),
        (second_source.clone(), second_destination.clone()),
    ])
    .unwrap_err();

    assert!(format!("{error:#}").contains("rolled back"));
    assert_eq!(std::fs::read(&first_source).unwrap(), b"first");
    assert_eq!(std::fs::read(&second_source).unwrap(), b"second");
    assert!(!first_destination.exists());
    assert_eq!(std::fs::read(&second_destination).unwrap(), b"conflict");
}

#[cfg(unix)]
#[test]
fn legacy_store_conflicts_are_preflighted_before_any_move() {
    let directory = tempdir().unwrap();
    let home = directory.path();
    let legacy = home.join("legacy");
    let canonical = home.join("canonical");
    create_private_store_directory(&legacy);
    create_private_store_directory(&canonical);
    create_private_store_file(&legacy.join("ego-browser-credential.json"), b"credential");
    create_private_store_file(&legacy.join("ego-browser-policy.json"), b"policy");
    create_private_store_file(
        &canonical.join("ego-browser-policy.json"),
        b"canonical-policy",
    );

    let error = migrate_legacy_device_store_paths(home, &legacy, &canonical).unwrap_err();

    assert!(format!("{error:#}").contains("conflicting state"));
    assert!(legacy.join("ego-browser-credential.json").exists());
    assert!(legacy.join("ego-browser-policy.json").exists());
    assert!(!canonical.join("ego-browser-credential.json").exists());
}

fn switch_pending_for_test() -> PendingRevocation {
    PendingRevocation {
        version: 1,
        scope: "device".to_owned(),
        device_id: Some("old-device".to_owned()),
        binding_id: None,
        device_generation: Some(4),
        reason: "switch_server".to_owned(),
        operation_id: "op-switch-test".to_owned(),
        target_binding_generation: None,
        retry_count: 0,
        next_retry_at_unix: 1,
        server_url: Some("https://old.example".to_owned()),
        target_server_url: Some("https://new.example".to_owned()),
        old_origin_revoked: false,
        local_purged: false,
        config_switched: false,
        new_identity_ensured: false,
        created_at_unix: 1,
    }
}

#[test]
fn switch_server_progress_is_ordered_and_retryable() {
    let mut pending = switch_pending_for_test();
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::RevokeOldOrigin
    );
    pending.old_origin_revoked = true;
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::PurgeLocal
    );
    pending.local_purged = true;
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::SwitchConfig
    );
    pending.config_switched = true;
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::EnsureNewIdentity
    );
    pending.new_identity_ensured = true;
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::Finalize
    );
}

#[test]
fn switch_retry_preserves_target_identity_after_ensure_failure() {
    let pending = switch_pending_for_test();
    let incomplete = LocalDeviceMetadata {
        device_id: "new-device".to_owned(),
        device_generation: 1,
        server_url: "https://new.example".to_owned(),
        release_profile: "community-local-trust".to_owned(),
        credential_profile: "community_file".to_owned(),
        credential_revision: 0,
        credential_expires_at_unix: 0,
    };
    assert_eq!(
        classify_switch_local_identity(&pending, Some(&incomplete)).unwrap(),
        SwitchLocalIdentity::TargetIncomplete
    );
    let mut resumed = pending;
    resumed.old_origin_revoked = true;
    resumed.local_purged = true;
    resumed.config_switched = true;
    assert_eq!(
        next_switch_server_stage(&resumed),
        SwitchServerStage::EnsureNewIdentity
    );
    assert_ne!(
        classify_switch_local_identity(&resumed, Some(&incomplete)).unwrap(),
        SwitchLocalIdentity::Old
    );
}

#[test]
fn switch_reconcile_advances_markers_without_purging_target_identity() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    let store = device_store_dir(&paths);
    ensure_device_store_dir(&store).unwrap();
    std::fs::write(
        store.join("ego-browser-credential.json"),
        serde_json::json!({
            "version": 1,
            "device_id": "new-device",
            "server_url": "https://new.example",
            "token": "egbc_new-token",
            "credential_id": "credential-new",
            "release_profile": "community-local-trust",
            "credential_profile": "community_file",
            "expires_at_unix": 4_000_000_000_u64,
            "revision": 1,
            "device_generation": 1
        })
        .to_string(),
    )
    .unwrap();
    crate::platform::set_owner_only_permissions(&store.join("ego-browser-credential.json"))
        .unwrap();
    Config {
        server_url: Some("https://new.example".to_owned()),
        active_device_id: None,
    }
    .save(&paths)
    .unwrap();

    let mut pending = switch_pending_for_test();
    reconcile_switch_server_progress(&paths, &mut pending).unwrap();
    assert!(pending.old_origin_revoked);
    assert!(pending.local_purged);
    assert!(pending.config_switched);
    assert!(pending.new_identity_ensured);
    assert!(store.join("ego-browser-credential.json").exists());
    assert_eq!(
        next_switch_server_stage(&pending),
        SwitchServerStage::Finalize
    );
}

#[test]
fn pending_revocation_next_step_preserves_scope() {
    let mut pending = PendingRevocation {
        version: 1,
        scope: "binding".to_owned(),
        device_id: Some("device-1".to_owned()),
        binding_id: Some("binding-1".to_owned()),
        device_generation: Some(1),
        reason: "remove_binding".to_owned(),
        operation_id: "op-scope".to_owned(),
        target_binding_generation: Some(2),
        retry_count: 0,
        next_retry_at_unix: 1,
        server_url: Some("https://control.example".to_owned()),
        target_server_url: None,
        old_origin_revoked: false,
        local_purged: false,
        config_switched: false,
        new_identity_ensured: false,
        created_at_unix: 1,
    };
    assert_eq!(
        pending_revocation_next_command(&pending),
        "agent-remote ego-browser remove"
    );
    pending.scope = "device".to_owned();
    pending.binding_id = None;
    pending.target_binding_generation = None;
    pending.device_generation = Some(1);
    assert_eq!(
        pending_revocation_next_command(&pending),
        "agent-remote ego-browser forget-this-mac"
    );
    pending.reason = "switch_server".to_owned();
    pending.target_server_url = Some("https://new.example".to_owned());
    assert_eq!(
        pending_revocation_next_command(&pending),
        "agent-remote ego-browser switch-server --server-url SERVER"
    );
}

#[tokio::test]
async fn forget_retries_existing_pending_device_without_identity_or_login() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    write_pending_revocation(
        &paths,
        &PendingRevocation {
            version: 1,
            scope: "device".to_owned(),
            device_id: Some("device-1".to_owned()),
            binding_id: None,
            device_generation: Some(3),
            reason: "forget_device".to_owned(),
            operation_id: "op-device-retry".to_owned(),
            target_binding_generation: None,
            retry_count: 0,
            next_retry_at_unix: 1,
            server_url: Some("https://control.example".to_owned()),
            target_server_url: None,
            old_origin_revoked: false,
            local_purged: false,
            config_switched: false,
            new_identity_ensured: false,
            created_at_unix: 1,
        },
    )
    .unwrap();
    set_local_admission_state(&paths, "ready").unwrap();

    let error = forget_this_mac(
        paths.clone(),
        EgoBrowserForgetArgs {
            device_id: None,
            yes: true,
        },
    )
    .await
    .unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("error_code=pending_revocation"));
    assert!(rendered.contains("operation_id=op-device-retry"));
    assert_eq!(local_admission_state(&paths).unwrap(), "closed");
    let persisted = load_pending_revocation(&paths).unwrap().unwrap();
    assert_eq!(persisted.operation_id, "op-device-retry");
    assert_eq!(persisted.retry_count, 1);
}

#[test]
fn pending_binding_revocation_keeps_local_admission_closed() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    write_pending_revocation(
        &paths,
        &PendingRevocation {
            version: 1,
            scope: "binding".to_owned(),
            device_id: Some("device-1".to_owned()),
            binding_id: Some("binding-1".to_owned()),
            device_generation: Some(2),
            reason: "remove_binding".to_owned(),
            operation_id: "op-binding-test".to_owned(),
            target_binding_generation: Some(4),
            retry_count: 1,
            next_retry_at_unix: 1,
            server_url: Some("https://control.example".to_owned()),
            target_server_url: None,
            old_origin_revoked: false,
            local_purged: false,
            config_switched: false,
            new_identity_ensured: false,
            created_at_unix: 1,
        },
    )
    .unwrap();

    let error = reject_pending_revocation(&paths).unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("error_code=pending_revocation"));
    assert!(rendered.contains("admission=closed"));
    assert!(rendered.contains("next_command=agent-remote ego-browser remove"));
}

#[test]
fn pending_device_revocation_keeps_local_admission_closed() {
    let directory = tempdir().unwrap();
    let paths = AppPaths::from_home(directory.path().join("agent-remote"));
    write_pending_revocation(
        &paths,
        &PendingRevocation {
            version: 1,
            scope: "device".to_owned(),
            device_id: Some("device-1".to_owned()),
            binding_id: None,
            device_generation: Some(3),
            reason: "forget_device".to_owned(),
            operation_id: "op-device-test".to_owned(),
            target_binding_generation: None,
            retry_count: 0,
            next_retry_at_unix: 1,
            server_url: Some("https://control.example".to_owned()),
            target_server_url: None,
            old_origin_revoked: false,
            local_purged: false,
            config_switched: false,
            new_identity_ensured: false,
            created_at_unix: 1,
        },
    )
    .unwrap();

    let error = reject_pending_revocation(&paths).unwrap_err();
    let rendered = format!("{error:#}");
    assert!(rendered.contains("error_code=pending_revocation"));
    assert!(rendered.contains("admission=closed"));
    assert!(rendered.contains("next_command=agent-remote ego-browser forget-this-mac"));
}
