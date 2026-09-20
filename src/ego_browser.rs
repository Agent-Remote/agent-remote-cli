use std::collections::HashSet;
use std::ffi::OsString;
use std::fs;
use std::io::{IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::FileTypeExt;

use anyhow::{anyhow, bail, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command as ProcessCommand;
use uuid::Uuid;

use crate::api::{
    ApiClient, EgoBrowserBindingCandidateData, EgoBrowserBindingData, EgoBrowserDeviceData,
    EgoBrowserPolicyData, EgoBrowserRequestData,
};
use crate::auth::{load_device_token, load_user_token};
use crate::bridge_release::{
    self, MANAGED_BRIDGE_PROTOCOL_VERSION, MANAGED_BRIDGE_VERSION, MANAGED_CREDENTIAL_PROFILE,
    MANAGED_PROFILE_ID, MANAGED_SIGNER_CERTIFICATE_SHA256,
};
use crate::cli::{
    EgoBrowserActionArgs, EgoBrowserCancelRequestArgs, EgoBrowserClaimArgs, EgoBrowserCommand,
    EgoBrowserConnectArgs, EgoBrowserDeleteArgs, EgoBrowserForgetArgs, EgoBrowserLifecycleArgs,
    EgoBrowserRegisterArgs, EgoBrowserRemoveArgs, EgoBrowserRequestsArgs, EgoBrowserSetupArgs,
    EgoBrowserStatusArgs, EgoBrowserSwitchServerArgs, EgoBrowserUpgradeArgs, ListArgs,
};
use crate::config::{AppPaths, Config};
use crate::identifiers::{resolve_id, short_id};
use crate::local_state::{LocalEgoBrowserBinding, LocalState};
use crate::terminal::{self, Details, Table};

const FULL_TRUST_WARNING: &str = "Remote fclaude will execute complete ego-browser heredoc scripts as the current macOS user without an App Sandbox. Scripts can access that user's files, environment, network, browser login data, Node modules, subprocesses, and other tabs or Task Spaces, and can send data remotely. Stopping terminates supervised work only; it cannot roll back side effects or guarantee cleanup of deliberately detached processes.";
const SAFE_DEVICE_CLIENT_ERROR_CODES: &[&str] = &[
    "credential_missing",
    "credential_invalid_path",
    "credential_unsafe_permissions",
    "credential_malformed",
    "policy_invalid",
    "policy_conflict",
    "rotation_conflict",
    "learning_bundle_invalid",
    "credential_too_large",
    "control_plane_error",
    "io_error",
    "operation_failed",
    "login_required",
    "server_profile_required",
    "device_conflict",
    "device_generation_conflict",
    "device_not_found",
    "device_revoked",
    "compatibility_mismatch",
    "admission_disabled",
    "server_unreachable",
    "local_lock_busy",
    "bridge_installer_unavailable",
    "server_capability_unavailable",
    "identity_corrupt",
    "identity_origin_conflict",
    "pending_expired",
    "transport_unavailable",
    "node_join_code_error",
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PendingRevocation {
    #[serde(default = "pending_revocation_version")]
    version: u8,
    #[serde(default)]
    scope: String,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    binding_id: Option<String>,
    #[serde(default)]
    device_generation: Option<u64>,
    #[serde(default = "legacy_revocation_reason")]
    reason: String,
    #[serde(default)]
    operation_id: String,
    #[serde(default, alias = "generation")]
    target_binding_generation: Option<u64>,
    #[serde(default)]
    retry_count: u32,
    #[serde(default)]
    next_retry_at_unix: u64,
    #[serde(default)]
    server_url: Option<String>,
    #[serde(default)]
    target_server_url: Option<String>,
    #[serde(default)]
    old_origin_revoked: bool,
    #[serde(default)]
    local_purged: bool,
    #[serde(default)]
    config_switched: bool,
    #[serde(default)]
    new_identity_ensured: bool,
    #[serde(default = "legacy_created_at")]
    created_at_unix: u64,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalDeviceMetadata {
    device_id: String,
    device_generation: u64,
    server_url: String,
    release_profile: String,
    credential_profile: String,
    credential_revision: u64,
    credential_expires_at_unix: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalTrustConfirmation {
    version: u8,
    #[serde(alias = "release_profile")]
    profile_id: String,
    #[serde(default)]
    profile_version: String,
    #[serde(default)]
    bridge_version: String,
    signer_certificate_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct BridgeTrustEvidence {
    profile_id: String,
    profile_version: String,
    bridge_version: String,
    signer_certificate_sha256: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LocalActiveBindingHandoff {
    version: u32,
    binding_id: String,
    generation: u64,
    device_id: String,
    task_space_label: String,
    authorization_mode: String,
    user_confirmation: bool,
}

/// Content-free local execution admission shared outside the CLI database.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LocalAdmissionRecord {
    version: u8,
    state: String,
    #[serde(default)]
    device_id: Option<String>,
    #[serde(default)]
    device_generation: Option<u64>,
    #[serde(default)]
    binding_id: Option<String>,
    #[serde(default)]
    binding_generation: Option<u64>,
    updated_at_unix: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct LocalAdmissionSnapshot {
    state: String,
    record: Option<LocalAdmissionRecord>,
}

fn pending_revocation_version() -> u8 {
    1
}

fn legacy_revocation_reason() -> String {
    "legacy_revocation".to_owned()
}

fn legacy_created_at() -> u64 {
    unix_time_seconds()
}

fn managed_bridge_trust_evidence() -> BridgeTrustEvidence {
    BridgeTrustEvidence {
        profile_id: MANAGED_PROFILE_ID.to_owned(),
        profile_version: MANAGED_BRIDGE_VERSION.to_owned(),
        bridge_version: MANAGED_BRIDGE_VERSION.to_owned(),
        signer_certificate_sha256: MANAGED_SIGNER_CERTIFICATE_SHA256.to_owned(),
    }
}

fn trust_confirmation_matches(
    confirmation: &LocalTrustConfirmation,
    evidence: &BridgeTrustEvidence,
) -> bool {
    confirmation.version == 2
        && confirmation.profile_id == evidence.profile_id
        && confirmation.profile_version == evidence.profile_version
        && confirmation.bridge_version == evidence.bridge_version
        && confirmation.signer_certificate_sha256 == evidence.signer_certificate_sha256
}

fn confirm_bridge_trust(
    paths: &AppPaths,
    evidence: &BridgeTrustEvidence,
    yes: bool,
    command: &str,
) -> Result<bool> {
    if load_trust_confirmation(paths)?
        .as_ref()
        .is_some_and(|confirmation| trust_confirmation_matches(confirmation, evidence))
    {
        return Ok(true);
    }
    if yes {
        return Ok(true);
    }
    if !interactive_terminal() {
        return Err(lifecycle_error(
            "trust_confirmation_required",
            "profile_verified",
            "closed",
            "confirm_local_trust",
            command,
            false,
        ));
    }
    terminal::warning_line(format!(
        "Local Bridge profile: {}\nProfile version: {}\nBridge version: {}\nSigner certificate SHA-256: {}",
        evidence.profile_id,
        evidence.profile_version,
        evidence.bridge_version,
        evidence.signer_certificate_sha256,
    ));
    super::prompt_yes_no(
        "Trust this exact project-self-signed profile and grant local runtime access? [y/N] ",
    )
}

fn trust_confirmation(evidence: &BridgeTrustEvidence) -> LocalTrustConfirmation {
    LocalTrustConfirmation {
        version: 2,
        profile_id: evidence.profile_id.clone(),
        profile_version: evidence.profile_version.clone(),
        bridge_version: evidence.bridge_version.clone(),
        signer_certificate_sha256: evidence.signer_certificate_sha256.clone(),
    }
}

async fn setup(paths: AppPaths, args: EgoBrowserSetupArgs) -> Result<()> {
    if let Some(pending) = load_pending_revocation(&paths)? {
        close_local_admission(&paths)?;
        let next_command = pending_revocation_next_command(&pending);
        return Err(lifecycle_error(
            "pending_revocation",
            "pending_revocation",
            "closed",
            "retry_revocation",
            next_command,
            false,
        ));
    }
    let (server_url, token) = load_user_control_token(&paths).await?;
    let policy = ApiClient::new(server_url.clone())?
        .ego_browser_policy(&token)
        .await
        .map_err(|error| map_api_error(error, "setup"))?;
    if !policy.enrollment_is_admitted() {
        return Err(lifecycle_error(
            "admission_disabled",
            "absent",
            "server_enrollment_closed",
            "request_enrollment_admission",
            "agent-remote ego-browser setup",
            false,
        ));
    }
    // Close prior execution before trust checks so a changed profile cannot retain admission.
    close_local_admission(&paths)?;
    let target_evidence =
        discover_bridge_trust_evidence(&paths)?.unwrap_or_else(managed_bridge_trust_evidence);
    if !confirm_bridge_trust(
        &paths,
        &target_evidence,
        args.yes,
        "agent-remote ego-browser setup --yes",
    )? {
        terminal::note("Ego-browser setup cancelled.");
        return Ok(());
    }
    run_bridge_installer(&paths, "setup", args.yes)
        .await
        .map_err(|error| map_operational_error(error, "setup"))?;
    let installed_evidence = discover_bridge_trust_evidence(&paths)?
        .context("installed Bridge trust evidence is unavailable after setup")?;
    if installed_evidence != target_evidence {
        bail!("installed Bridge release does not match the confirmed profile")
    }
    write_trust_confirmation(&paths, &trust_confirmation(&installed_evidence))?;
    run_device_client_with_token_at(
        &paths,
        [
            OsString::from("ensure"),
            OsString::from("--server"),
            OsString::from(server_url),
            OsString::from("--token-stdin"),
        ],
        &token,
    )
    .await
    .map_err(|error| map_operational_error(error, "setup"))?;
    // Setup proves readiness only; an explicit binding claim opens execution.
    set_local_admission_state(&paths, "ready")?;
    terminal::success_line(
        "Ego-browser Bridge is ready; no remote session was claimed (run `agent-remote ego-browser connect`).",
    );
    Ok(())
}

async fn connect(paths: AppPaths, args: EgoBrowserConnectArgs) -> Result<()> {
    let pending = load_pending_revocation(&paths)?;
    if let Some(pending) = pending {
        close_local_admission(&paths)?;
        let next_command = pending_revocation_next_command(&pending);
        return Err(lifecycle_error(
            "admission_disabled",
            "pending_revocation",
            "closed",
            "retry_revocation",
            next_command,
            false,
        ));
    }
    if !local_admission_is_ready(&paths)? {
        return Err(lifecycle_error(
            "admission_disabled",
            "ready",
            "closed",
            "setup",
            "agent-remote ego-browser setup",
            false,
        ));
    }
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let policy = client
        .ego_browser_policy(&token)
        .await
        .map_err(|error| map_api_error(error, "connect"))?;
    // Existing devices require execution admission, not an open enrollment gate.
    if !policy.execution_is_admitted() {
        return Err(lifecycle_error(
            "admission_disabled",
            "ready",
            "server_execution_closed",
            "request_execution_admission",
            "agent-remote ego-browser connect",
            false,
        ));
    }
    if policy
        .protocol
        .as_deref()
        .is_some_and(|protocol| protocol != MANAGED_BRIDGE_PROTOCOL_VERSION)
    {
        return Err(lifecycle_error(
            "compatibility_mismatch",
            "ready",
            "closed",
            "repair",
            "agent-remote ego-browser repair",
            false,
        ));
    }
    let candidates = client
        .list_ego_browser_candidates(&token)
        .await
        .map_err(|error| map_api_error(error, "connect"))?;
    let selected = select_candidate(&candidates, args.tool_session.as_deref())?;

    // Re-query before the privileged claim so a stale index cannot select another session.
    let refreshed = client
        .list_ego_browser_candidates(&token)
        .await
        .map_err(|error| map_api_error(error, "connect"))?;
    let current = refreshed
        .iter()
        .find(|candidate| candidate_matches_selection(&selected, candidate))
        .ok_or_else(|| {
            lifecycle_error(
                "candidate_stale",
                "ready",
                "unknown",
                "refresh_candidates",
                "agent-remote ego-browser connect",
                true,
            )
        })?;
    if selected.binding_id.is_some()
        || selected.current_ego_browser_device_id.is_some()
        || current.binding_id.is_some()
        || current.current_ego_browser_device_id.is_some()
    {
        return Err(lifecycle_error(
            "binding_conflict",
            "candidate_bound",
            "closed",
            "stop_existing_binding",
            "agent-remote ego-browser status",
            false,
        ));
    }

    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "candidate_selected",
                "unknown",
                "confirm_full_trust",
                "agent-remote ego-browser connect --yes",
                false,
            ));
        }
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no(&format!(
            "Authorize session {} ({}) for full-trust control? [y/N] ",
            short_id(&selected.tool_session_id),
            selected.display_name
        ))? {
            terminal::note("Ego-browser connect cancelled.");
            return Ok(());
        }
    }

    // Close admission before delegating the atomic handoff, including to compatibility clients.
    close_local_admission(&paths)?;
    let _output = run_device_client_at(
        &paths,
        [
            OsString::from("claim"),
            OsString::from(selected.tool_session_id.clone()),
            OsString::from("--confirm"),
        ],
    )
    .await
    .map_err(|error| map_operational_error(error, "connect"))?;
    terminal::success_line(format!(
        "Ego-browser binding claimed for {} ({})",
        short_id(&selected.tool_session_id),
        selected.display_name
    ));
    Ok(())
}

async fn repair(paths: AppPaths, args: EgoBrowserActionArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let target_evidence = discover_bridge_trust_evidence(&paths)?.ok_or_else(|| {
        lifecycle_error(
            "bridge_installer_unavailable",
            "absent",
            "closed",
            "setup",
            "agent-remote ego-browser setup",
            false,
        )
    })?;
    if !confirm_bridge_trust(
        &paths,
        &target_evidence,
        args.yes,
        "agent-remote ego-browser repair --yes",
    )? {
        terminal::note("Ego-browser repair cancelled.");
        return Ok(());
    }
    // Repair keeps execution closed until local and control-plane checks both succeed.
    close_local_admission(&paths)?;
    let (server_url, token) = load_user_control_token(&paths).await?;
    drain_local_bindings(&paths, &server_url, &token).await?;
    run_bridge_installer(&paths, "repair", args.yes)
        .await
        .map_err(|error| map_operational_error(error, "repair"))?;
    let installed_evidence = discover_bridge_trust_evidence(&paths)?
        .context("installed Bridge trust evidence is unavailable after repair")?;
    if installed_evidence != target_evidence {
        bail!("repaired Bridge release does not match the confirmed profile")
    }
    write_trust_confirmation(&paths, &trust_confirmation(&installed_evidence))?;
    run_device_client_with_token_at(
        &paths,
        [
            OsString::from("ensure"),
            OsString::from("--server"),
            OsString::from(server_url),
            OsString::from("--token-stdin"),
            OsString::from("--force-refresh"),
        ],
        &token,
    )
    .await
    .map_err(|error| map_operational_error(error, "repair"))?;
    set_local_admission_state(&paths, "ready")?;
    terminal::success_line("Ego-browser Bridge repair completed; Device identity was preserved.");
    Ok(())
}

async fn upgrade(paths: AppPaths, args: EgoBrowserUpgradeArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let target_evidence = managed_bridge_trust_evidence();
    if !confirm_bridge_trust(
        &paths,
        &target_evidence,
        args.yes,
        "agent-remote ego-browser upgrade --yes",
    )? {
        terminal::note("Ego-browser upgrade cancelled.");
        return Ok(());
    }
    // Drain before switching `current`; identity and generation live in a separate store.
    close_local_admission(&paths)?;
    let (server_url, token) = load_user_control_token(&paths).await?;
    drain_local_bindings(&paths, &server_url, &token).await?;
    run_bridge_installer(&paths, "upgrade", args.yes)
        .await
        .map_err(|error| map_operational_error(error, "upgrade"))?;
    let installed_evidence = discover_bridge_trust_evidence(&paths)?
        .context("installed Bridge trust evidence is unavailable after upgrade")?;
    if installed_evidence != target_evidence {
        bail!("upgraded Bridge release does not match the confirmed profile")
    }
    write_trust_confirmation(&paths, &trust_confirmation(&installed_evidence))?;
    re_enroll_retained_device(&paths, server_url, &token)
        .await
        .map_err(|error| map_operational_error(error, "upgrade"))?;
    set_local_admission_state(&paths, "ready")?;
    terminal::success_line(
        "Ego-browser Bridge release verified; Device identity and device generation were preserved.",
    );
    Ok(())
}

/// Invalidates exact Device binding generations before changing the Bridge release.
async fn drain_local_bindings(paths: &AppPaths, server_url: &str, token: &str) -> Result<()> {
    let metadata = match discover_device_metadata(paths).await {
        Ok(value) => value,
        Err(_) if !local_identity_artifacts_exist(paths) => return Ok(()),
        Err(_) => {
            return Err(lifecycle_error(
                "identity_corrupt",
                "admission_closed",
                "closed",
                "repair",
                "agent-remote ego-browser repair",
                false,
            ))
        }
    };
    if metadata.server_url != server_url {
        return Err(lifecycle_error(
            "identity_origin_conflict",
            "admission_closed",
            "closed",
            "switch_server",
            "agent-remote ego-browser upgrade",
            false,
        ));
    }
    let client = ApiClient::new(server_url.to_owned())?;
    let bindings = client
        .list_ego_browser_bindings(token)
        .await
        .map_err(|error| map_api_error(error, "upgrade"))?;
    let handoff = load_local_active_binding_handoff(paths)?;
    for binding in bindings.into_iter().filter(|binding| {
        binding.ego_browser_device_id == metadata.device_id
            && matches!(
                binding.status.as_str(),
                "active" | "connecting" | "probing_local_browser"
            )
    }) {
        // The Device Client commits the paused generation to its lifecycle handoff.
        if handoff.as_ref().is_some_and(|value| {
            value.binding_id == binding.id && value.device_id == metadata.device_id
        }) {
            run_device_client_at(
                paths,
                [
                    OsString::from("pause"),
                    OsString::from(&binding.id),
                    OsString::from("--binding-generation"),
                    OsString::from(binding_generation(&binding).to_string()),
                ],
            )
            .await
            .map_err(|error| map_operational_error(error, "upgrade"))?;
            continue;
        }
        client
            .control_ego_browser_binding(
                token,
                &binding.id,
                binding_generation(&binding),
                "pause",
                "bridge_upgrade",
            )
            .await
            .map_err(|error| map_api_error(error, "upgrade"))?;
    }
    Ok(())
}

async fn remove(paths: AppPaths, args: EgoBrowserRemoveArgs) -> Result<()> {
    let pending = load_pending_revocation(&paths)?;
    if pending
        .as_ref()
        .is_some_and(|value| value.scope == "device")
    {
        close_local_admission(&paths)?;
        return Err(pending_revocation_error(
            pending.as_ref().expect("pending device revocation"),
            pending_revocation_next_command(pending.as_ref().expect("pending device revocation")),
        ));
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "installed",
                "unknown",
                "confirm_remove",
                "agent-remote ego-browser remove --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(
            "Stop active ego-browser execution and remove Bridge components (ego lite is kept)? [y/N] ",
        )? {
            terminal::note("Ego-browser removal cancelled.");
            return Ok(());
        }
    }
    close_local_admission(&paths)?;

    let local_metadata = discover_device_metadata(&paths).await;
    let local_identity_present = local_identity_artifacts_exist(&paths);
    // Revocation requires user authentication; a general Device token may have another scope.
    let control_result = load_user_control_token(&paths).await;
    let control = match control_result {
        Ok(value) => Some(value),
        Err(error)
            if pending.is_some()
                || local_identity_present
                || device_store_dir(&paths)
                    .join("ego-browser-active-binding.json")
                    .is_file() =>
        {
            let code = if format!("{error:#}").contains("login_required") {
                "login_required"
            } else if format!("{error:#}").contains("server_profile_required") {
                "server_profile_required"
            } else {
                "server_unreachable"
            };
            if let Some(pending) = pending.as_ref() {
                let updated = record_pending_failure(&paths, pending.clone(), code)?;
                return Err(pending_revocation_error(
                    &updated,
                    "agent-remote ego-browser remove",
                ));
            }
            return Err(lifecycle_error(
                code,
                "admission_closed",
                "closed",
                if code == "server_unreachable" {
                    "retry_revocation"
                } else {
                    "login"
                },
                "agent-remote ego-browser remove",
                false,
            ));
        }
        Err(_) => None,
    };
    if let Some(pending) = pending.as_ref() {
        let Some((server_url, token)) = control.as_ref() else {
            let pending = record_pending_failure(&paths, pending.clone(), "login_required")?;
            return Err(pending_revocation_error(
                &pending,
                "agent-remote ego-browser remove",
            ));
        };
        if pending.server_url.as_deref() != Some(server_url.as_str()) {
            return Err(lifecycle_error(
                "identity_origin_conflict",
                "pending_revocation",
                "closed",
                "switch_server",
                "agent-remote ego-browser forget-this-mac",
                false,
            ));
        }
        let client = ApiClient::new(server_url.clone())?;
        if let Err(error) = revoke_pending_binding(&client, token, pending).await {
            let updated = record_pending_failure(&paths, pending.clone(), &error)?;
            return Err(pending_revocation_error(
                &updated,
                "agent-remote ego-browser remove",
            ));
        }
        clear_pending_revocation(&paths)?;
    }

    if let Some((server_url, token)) = control.as_ref() {
        let client = ApiClient::new(server_url.clone())?;
        let metadata = match local_metadata {
            Ok(value) => Some(value),
            Err(_) if local_identity_present => {
                return Err(lifecycle_error(
                    "identity_corrupt",
                    "admission_closed",
                    "closed",
                    "repair",
                    "agent-remote ego-browser repair",
                    false,
                ));
            }
            Err(_) => None,
        };
        if let Some(metadata) = metadata.as_ref() {
            if metadata.server_url != *server_url {
                return Err(lifecycle_error(
                    "identity_origin_conflict",
                    "admission_closed",
                    "closed",
                    "switch_server",
                    "agent-remote ego-browser remove",
                    false,
                ));
            }
        }
        // Prefer the exact local handoff so removal works while broad listing is enrollment-gated.
        let mut handled_binding_id = None;
        if let Some(handoff) = load_local_active_binding_handoff(&paths)? {
            let metadata_matches = metadata.as_ref().is_none_or(|value| {
                value.device_id == handoff.device_id && value.server_url == *server_url
            });
            if metadata_matches {
                let pending = PendingRevocation {
                    version: 1,
                    scope: "binding".into(),
                    device_id: Some(handoff.device_id.clone()),
                    binding_id: Some(handoff.binding_id.clone()),
                    device_generation: metadata.as_ref().map(|value| value.device_generation),
                    reason: "remove_binding".into(),
                    operation_id: new_operation_id(),
                    target_binding_generation: Some(handoff.generation),
                    retry_count: 0,
                    next_retry_at_unix: unix_time_seconds(),
                    server_url: Some(server_url.clone()),
                    target_server_url: None,
                    old_origin_revoked: false,
                    local_purged: false,
                    config_switched: false,
                    new_identity_ensured: false,
                    created_at_unix: unix_time_seconds(),
                };
                write_pending_revocation(&paths, &pending)?;
                if let Err(error) = revoke_pending_binding(&client, token, &pending).await {
                    let updated = record_pending_failure(&paths, pending, &error)?;
                    return Err(pending_revocation_error(
                        &updated,
                        "agent-remote ego-browser remove",
                    ));
                }
                clear_pending_revocation(&paths)?;
                handled_binding_id = Some(handoff.binding_id);
            }
        }

        let bindings = match client.list_ego_browser_bindings(token).await {
            Ok(value) => value,
            Err(error)
                if handled_binding_id.is_some()
                    && error.code().is_some_and(|code| {
                        matches!(
                            code,
                            "EGO_BROWSER_ENROLLMENT_DISABLED"
                                | "EGO_BROWSER_ENROLLMENT_ADMISSION_DISABLED"
                        )
                    }) =>
            {
                // After exact revocation, an enrollment freeze must not block local cleanup.
                Vec::new()
            }
            Err(error) => return Err(map_api_error(error, "remove")),
        };
        let has_live_binding = bindings.iter().any(|item| {
            matches!(
                item.status.as_str(),
                "pending_device"
                    | "active"
                    | "connecting"
                    | "paused"
                    | "probing_local_browser"
                    | "stopping"
            ) && metadata
                .as_ref()
                .is_none_or(|value| item.ego_browser_device_id == value.device_id)
        });
        if metadata.is_none() && has_live_binding {
            return Err(lifecycle_error(
                "identity_corrupt",
                "admission_closed",
                "closed",
                "repair",
                "agent-remote ego-browser repair",
                false,
            ));
        }
        let device_id = metadata.as_ref().map(|value| value.device_id.as_str());
        for binding in bindings.iter().filter(|item| {
            Some(item.id.as_str()) != handled_binding_id.as_deref()
                && device_id.is_none_or(|id| id == item.ego_browser_device_id)
                && matches!(
                    item.status.as_str(),
                    "pending_device"
                        | "active"
                        | "connecting"
                        | "paused"
                        | "probing_local_browser"
                        | "stopping"
                )
        }) {
            let pending = PendingRevocation {
                version: 1,
                scope: "binding".into(),
                device_id: Some(binding.ego_browser_device_id.clone()),
                binding_id: Some(binding.id.clone()),
                device_generation: metadata.as_ref().map(|value| value.device_generation),
                reason: "remove_binding".into(),
                operation_id: new_operation_id(),
                target_binding_generation: Some(binding_generation(binding)),
                retry_count: 0,
                next_retry_at_unix: unix_time_seconds(),
                server_url: Some(server_url.clone()),
                target_server_url: None,
                old_origin_revoked: false,
                local_purged: false,
                config_switched: false,
                new_identity_ensured: false,
                created_at_unix: unix_time_seconds(),
            };
            write_pending_revocation(&paths, &pending)?;
            if let Err(error) = revoke_pending_binding(&client, token, &pending).await {
                let updated = record_pending_failure(&paths, pending, &error)?;
                return Err(pending_revocation_error(
                    &updated,
                    "agent-remote ego-browser remove",
                ));
            }
            clear_pending_revocation(&paths)?;
        }
    }

    if device_client_available(&paths) {
        run_device_client_at(
            &paths,
            [
                OsString::from("retire-local"),
                OsString::from("--confirmed-stopped"),
            ],
        )
        .await
        .map_err(|error| map_operational_error(error, "remove"))?;
    }
    run_bridge_uninstaller(&paths, args.remove_releases)
        .await
        .map_err(|error| map_operational_error(error, "remove"))?;
    terminal::success_line("Ego-browser Bridge removed; Device identity was retained for setup.");
    Ok(())
}

fn confirm_forget_this_mac(device_id: &str, yes: bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !interactive_terminal() {
        return Err(lifecycle_error(
            "confirmation_required",
            "identity_corrupt",
            "closed",
            "confirm_forget",
            "agent-remote ego-browser forget-this-mac --yes",
            false,
        ));
    }
    if !super::prompt_yes_no(&format!(
        "Revoke ego-browser Device {} and delete its local keys? This cannot be undone. [y/N] ",
        short_id(device_id)
    ))? {
        terminal::note("Ego-browser forget-this-mac cancelled.");
        return Ok(false);
    }
    Ok(true)
}

async fn forget_this_mac(paths: AppPaths, args: EgoBrowserForgetArgs) -> Result<()> {
    let existing_pending = load_pending_revocation(&paths)?;
    if existing_pending
        .as_ref()
        .is_some_and(|value| value.scope == "binding")
    {
        close_local_admission(&paths)?;
        return Err(pending_revocation_error(
            existing_pending
                .as_ref()
                .expect("pending binding revocation"),
            "agent-remote ego-browser remove",
        ));
    }
    // If local metadata is unreadable, require an exact authenticated control-plane selection.
    let discovered_metadata = if existing_pending.is_none() {
        discover_device_metadata(&paths).await.ok()
    } else {
        None
    };
    let (server_url, token) = match load_user_control_token(&paths).await {
        Ok(value) => value,
        Err(error) => {
            // The pending device revocation remains the durable target across credential outages.
            if let Some(pending) = existing_pending.clone() {
                close_local_admission(&paths)?;
                let updated = record_pending_failure(&paths, pending, "login_required")?;
                return Err(pending_revocation_error(
                    &updated,
                    "agent-remote ego-browser forget-this-mac",
                ));
            }
            let Some(metadata) = discovered_metadata.as_ref() else {
                close_local_admission(&paths)?;
                return Err(lifecycle_error(
                    if format!("{error:#}").contains("server_profile_required") {
                        "server_profile_required"
                    } else {
                        "login_required"
                    },
                    "identity_corrupt",
                    "closed",
                    "login",
                    "agent-remote login",
                    false,
                ));
            };
            if !confirm_forget_this_mac(&metadata.device_id, args.yes)? {
                return Ok(());
            }
            close_local_admission(&paths)?;
            let pending = PendingRevocation {
                version: 1,
                scope: "device".into(),
                device_id: Some(metadata.device_id.clone()),
                binding_id: None,
                device_generation: Some(metadata.device_generation),
                reason: "forget_device".into(),
                operation_id: new_operation_id(),
                target_binding_generation: None,
                retry_count: 0,
                next_retry_at_unix: unix_time_seconds(),
                server_url: Some(metadata.server_url.clone()),
                target_server_url: None,
                old_origin_revoked: false,
                local_purged: false,
                config_switched: false,
                new_identity_ensured: false,
                created_at_unix: unix_time_seconds(),
            };
            let pending = record_pending_failure(&paths, pending, "login_required")?;
            return Err(pending_revocation_error(&pending, &error.to_string()));
        }
    };
    let client = ApiClient::new(server_url.clone())?;
    let metadata = match existing_pending.clone() {
        Some(pending) => LocalDeviceMetadata {
            device_id: pending
                .device_id
                .clone()
                .context("pending device revocation has no device ID")?,
            device_generation: pending
                .device_generation
                .context("pending device revocation has no device generation")?,
            server_url: pending
                .server_url
                .clone()
                .context("pending device revocation has no server origin")?,
            release_profile: String::new(),
            credential_profile: String::new(),
            credential_revision: 0,
            credential_expires_at_unix: 0,
        },
        None => match discovered_metadata {
            Some(metadata) => {
                if let Some(reference) = args.device_id.as_deref() {
                    let resolved = resolve_id(
                        reference,
                        "ego-browser device",
                        [metadata.device_id.as_str()].into_iter(),
                    )
                    .map_err(|_| {
                        lifecycle_error(
                            "device_conflict",
                            "identity_corrupt",
                            "closed",
                            "select_device",
                            "agent-remote ego-browser forget-this-mac --device-id DEVICE_ID",
                            false,
                        )
                    })?;
                    if resolved != metadata.device_id {
                        return Err(lifecycle_error(
                            "device_conflict",
                            "identity_corrupt",
                            "closed",
                            "select_device",
                            "agent-remote ego-browser forget-this-mac --device-id DEVICE_ID",
                            false,
                        ));
                    }
                }
                metadata
            }
            None => {
                select_recovery_device(&client, &server_url, &token, args.device_id.as_deref())
                    .await?
            }
        },
    };
    if server_url != metadata.server_url {
        return Err(lifecycle_error(
            "identity_origin_conflict",
            "admission_closed",
            "closed",
            "switch_server",
            "agent-remote ego-browser forget-this-mac",
            false,
        ));
    }
    if existing_pending.is_none() && !confirm_forget_this_mac(&metadata.device_id, args.yes)? {
        return Ok(());
    }
    close_local_admission(&paths)?;
    let pending = existing_pending.unwrap_or(PendingRevocation {
        version: 1,
        scope: "device".into(),
        device_id: Some(metadata.device_id.clone()),
        binding_id: None,
        device_generation: Some(metadata.device_generation),
        reason: "forget_device".into(),
        operation_id: new_operation_id(),
        target_binding_generation: None,
        retry_count: 0,
        next_retry_at_unix: unix_time_seconds(),
        server_url: Some(server_url.clone()),
        target_server_url: None,
        old_origin_revoked: false,
        local_purged: false,
        config_switched: false,
        new_identity_ensured: false,
        created_at_unix: unix_time_seconds(),
    });
    write_pending_revocation(&paths, &pending)?;
    if let Err(error) = revoke_pending_device(&client, &token, &pending).await {
        let pending = record_pending_failure(&paths, pending, &error)?;
        return Err(pending_revocation_error(
            &pending,
            "agent-remote ego-browser forget-this-mac",
        ));
    }
    run_device_client_at(
        &paths,
        [
            OsString::from("purge-local"),
            OsString::from("--confirmed-revoked"),
        ],
    )
    .await
    .map_err(|error| {
        match record_pending_failure(&paths, pending.clone(), "local_cleanup_failed") {
            Ok(updated) => {
                pending_revocation_error(&updated, "agent-remote ego-browser forget-this-mac")
            }
            Err(_) => map_operational_error(error, "forget-this-mac"),
        }
    })?;
    clear_pending_revocation(&paths)?;
    terminal::success_line("This Mac's ego-browser Device identity was revoked and removed.");
    Ok(())
}

async fn re_enroll(paths: AppPaths, args: EgoBrowserActionArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let metadata = match discover_device_metadata(&paths).await {
        Ok(metadata) => metadata,
        Err(_) => {
            close_local_admission(&paths)?;
            return Err(lifecycle_error(
                "identity_corrupt",
                "identity_corrupt",
                "closed",
                "forget",
                "agent-remote ego-browser forget-this-mac",
                false,
            ));
        }
    };
    let (server_url, token) = load_user_control_token(&paths).await?;
    if metadata.server_url != server_url {
        return Err(lifecycle_error(
            "identity_origin_conflict",
            "identity_corrupt",
            "closed",
            "switch_server",
            "agent-remote ego-browser switch-server --server-url SERVER",
            false,
        ));
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "identity_corrupt",
                "closed",
                "confirm_re_enroll",
                "agent-remote ego-browser re-enroll --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(&format!(
            "Re-enroll retained ego-browser Device {} on {} without generating a new key? [y/N] ",
            short_id(&metadata.device_id),
            server_url
        ))? {
            terminal::note("Ego-browser re-enrollment cancelled.");
            return Ok(());
        }
    }
    close_local_admission(&paths)?;
    re_enroll_retained_device(&paths, server_url, &token)
        .await
        .map_err(|error| map_operational_error(error, "re-enroll"))?;
    set_local_admission_state(&paths, "ready")?;
    terminal::success_line(format!(
        "Ego-browser Device {} was re-enrolled without changing its identity.",
        short_id(&metadata.device_id)
    ));
    Ok(())
}

async fn re_enroll_retained_device(
    paths: &AppPaths,
    server_url: String,
    token: &str,
) -> Result<()> {
    run_device_client_with_token_at(
        paths,
        [
            OsString::from("ensure"),
            OsString::from("--server"),
            OsString::from(server_url),
            OsString::from("--token-stdin"),
            OsString::from("--force-refresh"),
            OsString::from("--re-enroll"),
        ],
        token,
    )
    .await
}

/// Rotates retained keys after bindings stop, persisting retry state before the request.
async fn device_rotate(paths: AppPaths, args: EgoBrowserActionArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let metadata = match discover_device_metadata(&paths).await {
        Ok(metadata) => metadata,
        Err(_) => {
            close_local_admission(&paths)?;
            return Err(lifecycle_error(
                "identity_corrupt",
                "identity_corrupt",
                "closed",
                "forget",
                "agent-remote ego-browser forget-this-mac",
                false,
            ));
        }
    };
    let (server_url, token) = load_user_control_token(&paths).await?;
    if metadata.server_url != server_url {
        return Err(lifecycle_error(
            "identity_origin_conflict",
            "identity_corrupt",
            "closed",
            "switch_server",
            "agent-remote ego-browser switch-server --server-url SERVER",
            false,
        ));
    }
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client
        .list_ego_browser_bindings(&token)
        .await
        .map_err(|error| map_api_error(error, "device-rotate"))?;
    if bindings.iter().any(|binding| {
        binding.ego_browser_device_id == metadata.device_id
            && matches!(
                binding.status.as_str(),
                "pending_device"
                    | "active"
                    | "connecting"
                    | "paused"
                    | "probing_local_browser"
                    | "stopping"
            )
    }) {
        return Err(lifecycle_error(
            "binding_conflict",
            "connected",
            "closed",
            "stop_existing_binding",
            "agent-remote ego-browser status",
            false,
        ));
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "registered",
                "closed",
                "confirm_device_rotate",
                "agent-remote ego-browser device-rotate --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(&format!(
            "Rotate the signing and encryption keys for Device {}? Existing credentials and bindings will be invalidated. [y/N] ",
            short_id(&metadata.device_id)
        ))? {
            terminal::note("Ego-browser Device rotation cancelled.");
            return Ok(());
        }
    }
    close_local_admission(&paths)?;
    run_device_client_with_token_at(
        &paths,
        [
            OsString::from("device-rotate"),
            OsString::from("--token-stdin"),
            OsString::from("--confirm"),
        ],
        &token,
    )
    .await
    .map_err(|error| map_operational_error(error, "device-rotate"))?;
    set_local_admission_state(&paths, "ready")?;
    terminal::success_line(format!(
        "Ego-browser Device {} rotated to a new identity generation.",
        short_id(&metadata.device_id)
    ));
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwitchServerStage {
    RevokeOldOrigin,
    PurgeLocal,
    SwitchConfig,
    EnsureNewIdentity,
    Finalize,
}

fn next_switch_server_stage(pending: &PendingRevocation) -> SwitchServerStage {
    if !pending.old_origin_revoked {
        SwitchServerStage::RevokeOldOrigin
    } else if !pending.local_purged {
        SwitchServerStage::PurgeLocal
    } else if !pending.config_switched {
        SwitchServerStage::SwitchConfig
    } else if !pending.new_identity_ensured {
        SwitchServerStage::EnsureNewIdentity
    } else {
        SwitchServerStage::Finalize
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SwitchLocalIdentity {
    Absent,
    Old,
    TargetIncomplete,
    TargetEnsured,
    Foreign,
}

fn classify_switch_local_identity(
    pending: &PendingRevocation,
    metadata: Option<&LocalDeviceMetadata>,
) -> Result<SwitchLocalIdentity> {
    let old_device_id = pending
        .device_id
        .as_deref()
        .context("switch-server pending device ID is missing")?;
    let old_generation = pending
        .device_generation
        .context("switch-server pending device generation is missing")?;
    let old_server = pending
        .server_url
        .as_deref()
        .context("switch-server pending origin is missing")?;
    let target_server = pending
        .target_server_url
        .as_deref()
        .context("switch-server pending target origin is missing")?;
    let Some(metadata) = metadata else {
        return Ok(SwitchLocalIdentity::Absent);
    };
    if metadata.server_url == old_server
        && metadata.device_id == old_device_id
        && metadata.device_generation == old_generation
    {
        return Ok(SwitchLocalIdentity::Old);
    }
    if metadata.server_url == target_server && metadata.device_id != old_device_id {
        return Ok(if metadata.credential_revision > 0 {
            SwitchLocalIdentity::TargetEnsured
        } else {
            SwitchLocalIdentity::TargetIncomplete
        });
    }
    Ok(SwitchLocalIdentity::Foreign)
}

fn inspect_switch_local_identity(
    paths: &AppPaths,
    pending: &PendingRevocation,
) -> Result<SwitchLocalIdentity> {
    match read_local_device_metadata_file(paths) {
        Ok(metadata) => classify_switch_local_identity(pending, Some(&metadata)),
        Err(error) if !local_identity_artifacts_exist(paths) => {
            // Missing state after purge is expected; unreadable present state must not be guessed.
            let _ = error;
            classify_switch_local_identity(pending, None)
        }
        Err(error) => {
            Err(error).context("local identity state is unavailable during switch-server")
        }
    }
}

fn switch_pending_failure(
    paths: &AppPaths,
    pending: PendingRevocation,
    error_code: &str,
) -> Result<()> {
    let updated = record_pending_failure(paths, pending, error_code)?;
    Err(pending_revocation_error(
        &updated,
        pending_revocation_next_command(&updated),
    ))
}

async fn server_secret(paths: &AppPaths, server_url: &str) -> Result<Option<String>> {
    load_user_token(paths, server_url).await
}

fn config_points_at(paths: &AppPaths, server_url: &str) -> Result<bool> {
    Ok(Config::load(paths)?
        .server_url
        .as_deref()
        .map(crate::normalize_server_url)
        .is_some_and(|value| value == server_url))
}

/// Infers crash progress monotonically without resetting stages or deleting identities.
fn reconcile_switch_server_progress(
    paths: &AppPaths,
    pending: &mut PendingRevocation,
) -> Result<()> {
    let local = inspect_switch_local_identity(paths, pending)?;
    let config_target = config_points_at(
        paths,
        pending
            .target_server_url
            .as_deref()
            .context("switch-server pending target origin is missing")?,
    )?;
    let mut changed = false;

    match local {
        SwitchLocalIdentity::TargetIncomplete | SwitchLocalIdentity::TargetEnsured => {
            // A target-origin identity proves old-state purge; advance markers without repurging.
            if !pending.old_origin_revoked {
                pending.old_origin_revoked = true;
                changed = true;
            }
            if !pending.local_purged {
                pending.local_purged = true;
                changed = true;
            }
            if config_target && !pending.config_switched {
                pending.config_switched = true;
                changed = true;
            }
            if matches!(local, SwitchLocalIdentity::TargetEnsured)
                && pending.config_switched
                && !pending.new_identity_ensured
            {
                pending.new_identity_ensured = true;
                changed = true;
            }
        }
        SwitchLocalIdentity::Absent if config_target => {
            // Missing identity after config save identifies the post-purge marker crash window.
            if !pending.old_origin_revoked {
                pending.old_origin_revoked = true;
                changed = true;
            }
            if !pending.local_purged {
                pending.local_purged = true;
                changed = true;
            }
            if !pending.config_switched {
                pending.config_switched = true;
                changed = true;
            }
        }
        SwitchLocalIdentity::Old | SwitchLocalIdentity::Absent | SwitchLocalIdentity::Foreign => {}
    }
    if changed {
        write_pending_revocation(paths, pending)?;
    }
    Ok(())
}

/// Switches origin only after revocation, without sending old identity material to the target.
async fn switch_server(paths: AppPaths, args: EgoBrowserSwitchServerArgs) -> Result<()> {
    let new_server = crate::normalize_server_url(&args.server_url);
    if !valid_lifecycle_server_url(&new_server) {
        return Err(lifecycle_error(
            "configuration_invalid",
            "identity_corrupt",
            "closed",
            "login",
            "agent-remote login",
            false,
        ));
    }
    let existing_pending = load_pending_revocation(&paths)?;
    if let Some(pending) = existing_pending.as_ref() {
        if pending.scope == "binding" {
            close_local_admission(&paths)?;
            return Err(pending_revocation_error(
                pending,
                pending_revocation_next_command(pending),
            ));
        }
        if pending.scope != "device" || pending.reason != "switch_server" {
            close_local_admission(&paths)?;
            return Err(pending_revocation_error(
                pending,
                pending_revocation_next_command(pending),
            ));
        }
        if pending.target_server_url.as_deref() != Some(new_server.as_str()) {
            close_local_admission(&paths)?;
            return Err(lifecycle_error(
                "identity_origin_conflict",
                "pending_revocation",
                "closed",
                "switch_server",
                "agent-remote ego-browser switch-server --server-url SERVER",
                false,
            ));
        }
    }

    let mut pending = if let Some(pending) = existing_pending {
        // After destruction begins, the pending record is the sole source of truth.
        pending
    } else {
        let metadata = match discover_device_metadata(&paths).await {
            Ok(metadata) => metadata,
            Err(_) => {
                close_local_admission(&paths)?;
                return Err(lifecycle_error(
                    "identity_corrupt",
                    "identity_corrupt",
                    "closed",
                    "forget",
                    "agent-remote ego-browser forget-this-mac",
                    false,
                ));
            }
        };
        if metadata.server_url == new_server {
            return Err(lifecycle_error(
                "identity_origin_conflict",
                "registered",
                "closed",
                "status",
                "agent-remote ego-browser status",
                false,
            ));
        }
        // Validate both profiles before creating a destructive operation or revoking the old Device.
        let new_token = server_secret(&paths, &new_server).await?;
        if new_token.as_deref().is_none_or(str::is_empty) {
            return Err(lifecycle_error(
                "server_profile_required",
                "identity_corrupt",
                "closed",
                "login",
                "agent-remote login",
                false,
            ));
        }
        let old_token = server_secret(&paths, &metadata.server_url).await?;
        if old_token.as_deref().is_none_or(str::is_empty) {
            return Err(lifecycle_error(
                "login_required",
                "identity_corrupt",
                "closed",
                "login",
                "agent-remote login",
                false,
            ));
        }
        if !args.yes {
            if !interactive_terminal() {
                return Err(lifecycle_error(
                    "confirmation_required",
                    "registered",
                    "closed",
                    "confirm_switch_server",
                    "agent-remote ego-browser switch-server --server-url SERVER --yes",
                    false,
                ));
            }
            if !super::prompt_yes_no(&format!(
                "Revoke Device {} on {} and create a separate identity on {}? Old keys and bindings will not migrate. [y/N] ",
                short_id(&metadata.device_id),
                metadata.server_url,
                new_server
            ))? {
                terminal::note("Ego-browser Server switch cancelled.");
                return Ok(());
            }
        }
        PendingRevocation {
            version: 1,
            scope: "device".into(),
            device_id: Some(metadata.device_id),
            binding_id: None,
            device_generation: Some(metadata.device_generation),
            reason: "switch_server".into(),
            operation_id: new_operation_id(),
            target_binding_generation: None,
            retry_count: 0,
            next_retry_at_unix: unix_time_seconds(),
            server_url: Some(metadata.server_url),
            target_server_url: Some(new_server.clone()),
            old_origin_revoked: false,
            local_purged: false,
            config_switched: false,
            new_identity_ensured: false,
            created_at_unix: unix_time_seconds(),
        }
    };

    close_local_admission(&paths)?;
    // Persist the operation before later reads or mutations so every failure is recoverable.
    write_pending_revocation(&paths, &pending)?;
    if reconcile_switch_server_progress(&paths, &mut pending).is_err() {
        return switch_pending_failure(&paths, pending, "local_state_unavailable");
    }

    loop {
        match next_switch_server_stage(&pending) {
            SwitchServerStage::RevokeOldOrigin => {
                let old_server = pending
                    .server_url
                    .as_deref()
                    .context("switch-server pending origin is missing")?;
                let old_token = match server_secret(&paths, old_server).await {
                    Ok(Some(token)) if !token.is_empty() => token,
                    _ => return switch_pending_failure(&paths, pending, "login_required"),
                };
                let old_client = match ApiClient::new(old_server.to_owned()) {
                    Ok(client) => client,
                    Err(_) => {
                        return switch_pending_failure(&paths, pending, "old_origin_unavailable")
                    }
                };
                let already_revoked = old_client
                    .list_ego_browser_devices(&old_token, false)
                    .await
                    .ok()
                    .and_then(|devices| {
                        devices.into_iter().find(|device| {
                            device.id == pending.device_id.as_deref().unwrap_or_default()
                                && device_generation(device) == pending.device_generation
                        })
                    })
                    .is_some_and(|device| device.status == "revoked");
                if !already_revoked {
                    if let Err(error) =
                        revoke_pending_device(&old_client, &old_token, &pending).await
                    {
                        return switch_pending_failure(&paths, pending, &error);
                    }
                }
                pending.old_origin_revoked = true;
                write_pending_revocation(&paths, &pending)?;
            }
            SwitchServerStage::PurgeLocal => {
                let local = match inspect_switch_local_identity(&paths, &pending) {
                    Ok(local) => local,
                    Err(_) => {
                        return switch_pending_failure(&paths, pending, "local_state_unavailable")
                    }
                };
                match local {
                    SwitchLocalIdentity::Old => {
                        if run_device_client_at(
                            &paths,
                            [
                                OsString::from("purge-local"),
                                OsString::from("--confirmed-revoked"),
                            ],
                        )
                        .await
                        .is_err()
                        {
                            return switch_pending_failure(&paths, pending, "local_cleanup_failed");
                        }
                    }
                    SwitchLocalIdentity::Absent
                    | SwitchLocalIdentity::TargetIncomplete
                    | SwitchLocalIdentity::TargetEnsured => {
                        // A retry may predate its purge marker; never purge a target-origin identity.
                    }
                    SwitchLocalIdentity::Foreign => {
                        return switch_pending_failure(&paths, pending, "local_identity_conflict")
                    }
                }
                pending.local_purged = true;
                write_pending_revocation(&paths, &pending)?;
            }
            SwitchServerStage::SwitchConfig => {
                let target = pending
                    .target_server_url
                    .as_deref()
                    .context("switch-server pending target origin is missing")?
                    .to_owned();
                let config_result = (|| {
                    let mut config = Config::load(&paths)?;
                    if config
                        .server_url
                        .as_deref()
                        .map(crate::normalize_server_url)
                        .as_deref()
                        != Some(target.as_str())
                    {
                        config.server_url = Some(target);
                        config.save(&paths)?;
                    }
                    Ok::<(), anyhow::Error>(())
                })();
                if config_result.is_err() {
                    return switch_pending_failure(&paths, pending, "config_switch_failed");
                }
                pending.config_switched = true;
                write_pending_revocation(&paths, &pending)?;
            }
            SwitchServerStage::EnsureNewIdentity => {
                let target = pending
                    .target_server_url
                    .as_deref()
                    .context("switch-server pending target origin is missing")?
                    .to_owned();
                let local = match inspect_switch_local_identity(&paths, &pending) {
                    Ok(local) => local,
                    Err(_) => {
                        return switch_pending_failure(&paths, pending, "local_state_unavailable")
                    }
                };
                match local {
                    SwitchLocalIdentity::TargetEnsured => {
                        pending.new_identity_ensured = true;
                        write_pending_revocation(&paths, &pending)?;
                        continue;
                    }
                    SwitchLocalIdentity::Old | SwitchLocalIdentity::Foreign => {
                        return switch_pending_failure(&paths, pending, "new_identity_conflict")
                    }
                    SwitchLocalIdentity::Absent | SwitchLocalIdentity::TargetIncomplete => {}
                }
                let new_token = match server_secret(&paths, &target).await {
                    Ok(Some(token)) if !token.is_empty() => token,
                    _ => return switch_pending_failure(&paths, pending, "server_profile_required"),
                };
                if run_device_client_with_token_at(
                    &paths,
                    [
                        OsString::from("ensure"),
                        OsString::from("--server"),
                        OsString::from(target),
                        OsString::from("--token-stdin"),
                    ],
                    &new_token,
                )
                .await
                .is_err()
                {
                    return switch_pending_failure(&paths, pending, "new_origin_ensure_failed");
                }
                let local = match inspect_switch_local_identity(&paths, &pending) {
                    Ok(local) => local,
                    Err(_) => {
                        return switch_pending_failure(&paths, pending, "local_state_unavailable")
                    }
                };
                if !matches!(local, SwitchLocalIdentity::TargetEnsured) {
                    return switch_pending_failure(
                        &paths,
                        pending,
                        "new_origin_ensure_unconfirmed",
                    );
                }
                pending.new_identity_ensured = true;
                write_pending_revocation(&paths, &pending)?;
            }
            SwitchServerStage::Finalize => {
                let local = match inspect_switch_local_identity(&paths, &pending) {
                    Ok(local) => local,
                    Err(_) => {
                        return switch_pending_failure(&paths, pending, "local_state_unavailable")
                    }
                };
                if !matches!(local, SwitchLocalIdentity::TargetEnsured) {
                    return switch_pending_failure(
                        &paths,
                        pending,
                        "new_origin_ensure_unconfirmed",
                    );
                }
                let target = pending
                    .target_server_url
                    .as_deref()
                    .context("switch-server pending target origin is missing")?
                    .to_owned();
                let config_result = (|| {
                    let mut config = Config::load(&paths)?;
                    if config
                        .server_url
                        .as_deref()
                        .map(crate::normalize_server_url)
                        .as_deref()
                        != Some(target.as_str())
                    {
                        config.server_url = Some(target);
                        config.save(&paths)?;
                    }
                    Ok::<(), anyhow::Error>(())
                })();
                if config_result.is_err() {
                    return switch_pending_failure(&paths, pending, "config_switch_failed");
                }
                set_local_admission_state(&paths, "ready")?;
                clear_pending_revocation(&paths)?;
                terminal::success_line(
                    "Ego-browser switched Server origins with a new Device identity.",
                );
                return Ok(());
            }
        }
    }
}

async fn select_recovery_device(
    client: &ApiClient,
    server_url: &str,
    token: &str,
    requested: Option<&str>,
) -> Result<LocalDeviceMetadata> {
    let devices = match client.list_ego_browser_devices(token, true).await {
        Ok(devices) => devices,
        Err(error) if error.code() == Some("COMMON_FORBIDDEN") => client
            .list_ego_browser_devices(token, false)
            .await
            .map_err(|error| map_api_error(error, "forget-this-mac"))?,
        Err(error) => return Err(map_api_error(error, "forget-this-mac")),
    };
    if devices.is_empty() {
        return Err(lifecycle_error(
            "device_not_found",
            "identity_corrupt",
            "closed",
            "re_enroll",
            "agent-remote ego-browser setup",
            false,
        ));
    }
    let selected_id = if let Some(reference) = requested {
        resolve_id(
            reference,
            "ego-browser device",
            devices.iter().map(|device| device.id.as_str()),
        )?
    } else {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "identity_corrupt",
                "closed",
                "select_device",
                "agent-remote ego-browser forget-this-mac --device-id DEVICE_ID --yes",
                false,
            ));
        }
        terminal::section("Ego-browser devices eligible for recovery");
        let mut table = Table::new(["#", "ID", "STATUS", "PROFILE", "GEN"]);
        for (index, device) in devices.iter().enumerate() {
            table.row([
                (index + 1).to_string(),
                short_id(&device.id),
                device.status.clone(),
                device.release_profile.clone(),
                device_generation(device).unwrap_or_default().to_string(),
            ]);
        }
        table.render();
        let input = super::prompt_line("Select the Device number to revoke: ")?;
        let index = input
            .trim()
            .parse::<usize>()
            .ok()
            .filter(|value| *value >= 1 && *value <= devices.len())
            .context("invalid ego-browser device selection")?;
        devices[index - 1].id.clone()
    };
    let selected = devices
        .iter()
        .find(|device| device.id == selected_id)
        .context("selected ego-browser device disappeared")?;
    let generation = device_generation(selected)
        .filter(|value| *value > 0)
        .context("selected ego-browser device has no generation")?;
    Ok(LocalDeviceMetadata {
        device_id: selected.id.clone(),
        device_generation: generation,
        server_url: server_url.to_owned(),
        release_profile: selected.release_profile.clone(),
        credential_profile: String::new(),
        credential_revision: 0,
        credential_expires_at_unix: 0,
    })
}

fn interactive_terminal() -> bool {
    !terminal::output_suppressed()
        && std::io::stdin().is_terminal()
        && std::io::stdout().is_terminal()
}

fn unix_time_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

fn new_operation_id() -> String {
    let mut bytes = [0_u8; 16];
    OsRng.fill_bytes(&mut bytes);
    format!("op_{}", Uuid::from_bytes(bytes))
}

fn pending_revocation_path(paths: &AppPaths) -> std::path::PathBuf {
    paths.home().join("ego-browser-pending-revocation.json")
}

fn local_identity_artifacts_exist(paths: &AppPaths) -> bool {
    let directory = device_store_dir(paths);
    [
        "ego-browser-credential.json",
        "ego-browser-device-key.bin",
        "ego-browser-device-metadata.json",
        "ego-browser-active-binding.json",
        "ego-browser-pending-registration.json",
    ]
    .into_iter()
    .any(|name| fs::symlink_metadata(directory.join(name)).is_ok())
}

fn load_pending_revocation(paths: &AppPaths) -> Result<Option<PendingRevocation>> {
    let path = pending_revocation_path(paths);
    let bytes = match read_owner_only_file(&path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(anyhow!("pending revocation file is unavailable: {error}")),
    };
    let original: PendingRevocation =
        serde_json::from_slice(&bytes).context("pending revocation file is malformed")?;
    let mut pending = original.clone();
    if pending.operation_id.is_empty() {
        // Assign and persist one operation ID for legacy pending records.
        pending.operation_id = new_operation_id();
    }
    if pending.next_retry_at_unix == 0 {
        pending.next_retry_at_unix = unix_time_seconds();
    }
    if pending.server_url.is_none() {
        pending.server_url = Config::load(paths)?
            .server_url
            .as_deref()
            .map(crate::normalize_server_url);
    }
    // Interpret legacy `generation` by persisted scope before strict validation.
    if pending.scope == "device" && pending.device_generation.is_none() {
        pending.device_generation = pending.target_binding_generation.take();
    } else if pending.scope == "binding" && pending.target_binding_generation.is_none() {
        pending.target_binding_generation = pending.device_generation.take();
    }
    if pending.created_at_unix == 0 {
        pending.created_at_unix = unix_time_seconds();
    }
    validate_pending_revocation(&pending)?;
    if pending != original {
        write_pending_revocation(paths, &pending)?;
    }
    Ok(Some(pending))
}

fn validate_pending_revocation(pending: &PendingRevocation) -> Result<()> {
    if pending.version != 1
        || !matches!(pending.scope.as_str(), "binding" | "device")
        || pending.operation_id.len() < 3
        || pending.operation_id.len() > 128
        || !pending
            .operation_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || pending.reason.is_empty()
        || pending.reason.len() > 64
        || !pending
            .reason
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || pending.retry_count > 10_000
        || pending.created_at_unix == 0
    {
        bail!("pending revocation file failed validation")
    }
    for value in [pending.device_id.as_deref(), pending.binding_id.as_deref()]
        .into_iter()
        .flatten()
    {
        if !safe_lifecycle_id(value) {
            bail!("pending revocation file contains an invalid identifier")
        }
    }
    let Some(device_id) = pending.device_id.as_deref() else {
        bail!("pending revocation file has no device ID")
    };
    if !safe_lifecycle_id(device_id) {
        bail!("pending revocation file has an invalid device ID")
    }
    if pending.scope == "binding"
        && (pending.binding_id.is_none()
            || pending
                .target_binding_generation
                .is_none_or(|value| value == 0))
    {
        bail!("pending binding revocation has no target generation")
    }
    if pending.scope == "device" && pending.device_generation.is_none_or(|value| value == 0) {
        bail!("pending device revocation has no device generation")
    }
    let has_switch_progress = pending.old_origin_revoked
        || pending.local_purged
        || pending.config_switched
        || pending.new_identity_ensured;
    if has_switch_progress && (pending.scope != "device" || pending.reason != "switch_server") {
        bail!("switch-server progress is only valid for a device switch operation")
    }
    if pending.reason == "switch_server" {
        if pending.scope != "device"
            || pending.binding_id.is_some()
            || pending.target_binding_generation.is_some()
            || pending.target_server_url.is_none()
        {
            bail!("switch-server pending revocation has an invalid target shape")
        }
        if pending
            .target_server_url
            .as_deref()
            .is_some_and(|target| pending.server_url.as_deref() == Some(target))
        {
            bail!("switch-server pending revocation must change the server origin")
        }
        if pending.local_purged && !pending.old_origin_revoked {
            bail!("switch-server local purge cannot precede old-origin revoke")
        }
        if pending.config_switched && !pending.local_purged {
            bail!("switch-server config change cannot precede local purge")
        }
        if pending.new_identity_ensured && !pending.config_switched {
            bail!("switch-server identity ensure cannot precede config change")
        }
    } else if pending.target_server_url.is_some() {
        bail!("non-switch pending revocation cannot carry a target origin")
    }
    if let Some(server_url) = pending.server_url.as_deref() {
        if !valid_lifecycle_server_url(server_url) {
            bail!("pending revocation file has an invalid server origin")
        }
    } else {
        bail!("pending revocation file has no server origin")
    }
    if let Some(server_url) = pending.target_server_url.as_deref() {
        if !valid_lifecycle_server_url(server_url) {
            bail!("pending revocation file has an invalid target server origin")
        }
    }
    Ok(())
}

fn safe_lifecycle_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

fn valid_lifecycle_server_url(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && (url.path().is_empty() || url.path() == "/")
        && crate::normalize_server_url(value) == value
}

/// Resolves the shared Device store while keeping custom homes isolated.
fn device_store_dir(paths: &AppPaths) -> PathBuf {
    if let Some(path) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME") {
        return PathBuf::from(path);
    }
    let is_default_home = crate::platform::default_app_home()
        .ok()
        .is_some_and(|default| default == paths.home());
    if is_default_home {
        if let Some(home) = crate::platform::user_home_dir() {
            return home.join(".config/agent-remote-ego-browser");
        }
    }
    paths.home().join("ego-browser-device")
}

const LEGACY_DEVICE_STORE_FILES: &[&str] = &[
    "ego-browser-credential.json",
    "ego-browser-device-key.bin",
    "ego-browser-device-metadata.json",
    "ego-browser-device-key.pending.bin",
    "ego-browser-pending-rotation.json",
    "ego-browser-pending-registration.json",
    "ego-browser-policy.json",
    ".ego-browser-policy.lock",
    "ego-browser-active-binding.json",
    "ego-browser-local-admission.json",
    ".ego-browser-registration.lock",
];

/// Moves the legacy default store once without migrating custom homes implicitly.
fn migrate_legacy_device_store(paths: &AppPaths) -> Result<()> {
    if std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE_HOME").is_some() {
        return Ok(());
    }
    let Some(home) = crate::platform::user_home_dir() else {
        return Ok(());
    };
    let is_default_home = crate::platform::default_app_home()
        .ok()
        .is_some_and(|default| default == paths.home());
    if !is_default_home {
        return Ok(());
    }
    let canonical = home.join(".config/agent-remote-ego-browser");
    let legacy = home.join(".config/agent-remote/ego-browser-device");
    migrate_legacy_device_store_paths(&home, &legacy, &canonical)
}

fn migrate_legacy_device_store_paths(home: &Path, legacy: &Path, canonical: &Path) -> Result<()> {
    if legacy == canonical || legacy.starts_with(canonical) || canonical.starts_with(legacy) {
        bail!("legacy and canonical ego-browser stores must not overlap")
    }
    validate_directory_chain_without_symlinks(
        home,
        legacy.parent().context("legacy store has no parent")?,
    )?;
    validate_directory_chain_without_symlinks(
        home,
        canonical
            .parent()
            .context("canonical store has no parent")?,
    )?;

    let legacy_metadata = match fs::symlink_metadata(legacy) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    };
    validate_cli_store_directory(&legacy_metadata)?;
    validate_cli_store_entries(legacy)?;

    let mut movable = Vec::new();
    for entry in fs::read_dir(legacy)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("legacy ego-browser store contains a non-UTF-8 filename"))?;
        let source = entry.path();
        let metadata = fs::symlink_metadata(&source)?;
        if name == "device-service.sock" {
            if metadata.file_type().is_symlink() || !is_cli_socket_file_type(&metadata) {
                bail!("legacy ego-browser Device service path is unsafe")
            }
            continue;
        }
        if !LEGACY_DEVICE_STORE_FILES.contains(&name.as_str()) {
            // Unknown files may belong to newer releases and remain untouched.
            continue;
        }
        validate_cli_store_file(&metadata)?;
        let destination = canonical.join(&name);
        movable.push((source, destination));
    }

    let mut canonical_created = false;
    match fs::symlink_metadata(canonical) {
        Ok(metadata) => {
            validate_cli_store_directory(&metadata)?;
            validate_cli_store_entries(canonical)?;
            preflight_store_destinations(&movable)?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Finish all source validation before creating any canonical state.
            if let Some(parent) = canonical.parent() {
                fs::create_dir_all(parent)?;
                validate_directory_chain_without_symlinks(home, parent)?;
            }
            #[cfg(unix)]
            let mut builder = fs::DirBuilder::new();
            #[cfg(not(unix))]
            let builder = fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            match builder.create(canonical) {
                Ok(()) => canonical_created = true,
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
            let validation = (|| {
                let metadata = fs::symlink_metadata(canonical)?;
                validate_cli_store_directory(&metadata)?;
                validate_cli_store_entries(canonical)?;
                preflight_store_destinations(&movable)
            })();
            if let Err(error) = validation {
                if canonical_created {
                    let _ = fs::remove_dir(canonical);
                }
                return Err(error);
            }
        }
        Err(error) => return Err(error.into()),
    }

    if let Err(error) = move_store_files_transactionally(&movable) {
        if canonical_created {
            let _ = fs::remove_dir(canonical);
        }
        return Err(error);
    }
    let _ = fs::remove_dir(legacy);
    Ok(())
}

fn validate_directory_chain_without_symlinks(base: &Path, target: &Path) -> Result<()> {
    let relative = target
        .strip_prefix(base)
        .context("ego-browser store path escapes the user home")?;
    let base_metadata = fs::symlink_metadata(base)?;
    if base_metadata.file_type().is_symlink() || !base_metadata.is_dir() {
        bail!("ego-browser store home is not a real directory")
    }
    let mut current = base.to_path_buf();
    for component in relative.components() {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_dir() {
                    bail!("ego-browser store parent path is unsafe")
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn preflight_store_destinations(movable: &[(PathBuf, PathBuf)]) -> Result<()> {
    if movable
        .iter()
        .any(|(_, destination)| fs::symlink_metadata(destination).is_ok())
    {
        bail!("legacy and canonical ego-browser stores contain conflicting state")
    }
    Ok(())
}

fn move_store_files_transactionally(movable: &[(PathBuf, PathBuf)]) -> Result<()> {
    let mut moved: Vec<(PathBuf, PathBuf)> = Vec::new();
    for (source, destination) in movable {
        let result = (|| {
            if fs::symlink_metadata(destination).is_ok() {
                bail!("legacy and canonical ego-browser stores contain conflicting state")
            }
            // create-new hard links cannot overwrite state that appears after preflight.
            fs::hard_link(source, destination)?;
            if let Err(error) = fs::remove_file(source) {
                let _ = fs::remove_file(destination);
                return Err(error.into());
            }
            Ok(())
        })();
        if let Err(error) = result {
            let mut rollback_error = None;
            for (moved_source, moved_destination) in moved.iter().rev() {
                if let Err(error) = fs::hard_link(moved_destination, moved_source)
                    .and_then(|()| fs::remove_file(moved_destination))
                {
                    rollback_error = Some(error);
                    break;
                }
            }
            return match rollback_error {
                Some(rollback) => Err(anyhow!(
                    "legacy ego-browser store migration failed ({error}); rollback failed ({rollback})"
                )),
                None => Err(error).context("legacy ego-browser store migration failed and rolled back"),
            };
        }
        moved.push((source.clone(), destination.clone()));
    }
    Ok(())
}

fn validate_cli_store_entries(directory: &Path) -> Result<()> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("legacy ego-browser store contains a non-UTF-8 filename"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        if name == "device-service.sock" {
            if metadata.file_type().is_symlink() || !is_cli_socket_file_type(&metadata) {
                bail!("legacy ego-browser Device service path is unsafe")
            }
        } else if LEGACY_DEVICE_STORE_FILES.contains(&name.as_str()) {
            validate_cli_store_file(&metadata)?;
        } else if metadata.file_type().is_symlink() {
            bail!("legacy ego-browser Device store contains an unsafe entry")
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_cli_socket_file_type(metadata: &fs::Metadata) -> bool {
    metadata.file_type().is_socket()
}

#[cfg(not(unix))]
fn is_cli_socket_file_type(_metadata: &fs::Metadata) -> bool {
    false
}

fn validate_cli_store_directory(metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("ego-browser Device store is not a directory")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o077 != 0
        {
            bail!("ego-browser Device store has unsafe ownership or permissions")
        }
    }
    Ok(())
}

fn validate_cli_store_file(metadata: &fs::Metadata) -> Result<()> {
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("legacy ego-browser Device state path is unsafe")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o600
        {
            bail!("legacy ego-browser Device state has unsafe ownership or permissions")
        }
    }
    Ok(())
}

fn validate_existing_device_store(paths: &AppPaths) -> Result<Option<PathBuf>> {
    let directory = device_store_dir(paths);
    let metadata = match fs::symlink_metadata(&directory) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_cli_store_directory(&metadata)?;
    validate_cli_store_entries(&directory)?;
    Ok(Some(directory))
}

fn local_admission_path(paths: &AppPaths) -> PathBuf {
    device_store_dir(paths).join("ego-browser-local-admission.json")
}

fn load_local_admission_record(paths: &AppPaths) -> Result<Option<LocalAdmissionRecord>> {
    if validate_existing_device_store(paths)?.is_none() {
        return Ok(None);
    }
    let admission_path = local_admission_path(paths);
    let bytes = match read_owner_only_file(&admission_path, 16 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            // Malformed shared state must not be hidden by the legacy SQLite fallback.
            return Err(anyhow!(
                "local ego-browser admission record is unavailable: {error}"
            ));
        }
    };
    let record: LocalAdmissionRecord = serde_json::from_slice(&bytes)
        .context("local ego-browser admission record is malformed")?;
    validate_local_admission_record(&record)?;
    Ok(Some(record))
}

fn local_admission_snapshot(paths: &AppPaths) -> Result<LocalAdmissionSnapshot> {
    if let Some(record) = load_local_admission_record(paths)? {
        return Ok(LocalAdmissionSnapshot {
            state: record.state.clone(),
            record: Some(record),
        });
    }
    // Read legacy SQLite during migration, but always write shared state first.
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let state = state
        .get_kv("ego-browser-local-admission")?
        .unwrap_or_else(|| "closed".to_owned());
    if !matches!(state.as_str(), "closed" | "ready" | "open") {
        bail!("legacy local ego-browser admission projection has an invalid state")
    }
    Ok(LocalAdmissionSnapshot {
        state,
        record: None,
    })
}

fn local_admission_state(paths: &AppPaths) -> Result<String> {
    Ok(local_admission_snapshot(paths)?.state)
}

fn local_admission_is_ready(paths: &AppPaths) -> Result<bool> {
    Ok(matches!(
        local_admission_state(paths)?.as_str(),
        "ready" | "open"
    ))
}

fn set_local_admission_state(paths: &AppPaths, admission: &str) -> Result<()> {
    if !matches!(admission, "closed" | "ready" | "open") {
        bail!("invalid local admission state")
    }
    let directory = device_store_dir(paths);
    ensure_device_store_dir(&directory)?;
    // Damaged state may still close execution; opening requires every reference to validate.
    let (device_id, device_generation, binding_id, binding_generation) = if admission == "open" {
        let handoff = load_local_active_binding_handoff(paths)?
            .context("open local admission requires an active binding handoff")?;
        let metadata = read_local_device_metadata_file(paths)
            .context("open local admission requires local Device metadata")?;
        if handoff.device_id != metadata.device_id {
            bail!("local admission handoff and Device metadata refer to different devices")
        }
        if metadata.device_generation == 0 || handoff.generation == 0 {
            bail!("open local admission requires non-zero identity generations")
        }
        (
            Some(metadata.device_id),
            Some(metadata.device_generation),
            Some(handoff.binding_id),
            Some(handoff.generation),
        )
    } else {
        (None, None, None, None)
    };
    let record = LocalAdmissionRecord {
        version: 1,
        state: admission.to_owned(),
        device_id,
        device_generation,
        binding_id,
        binding_generation,
        updated_at_unix: unix_time_seconds().max(1),
    };
    write_local_admission_record(&directory, &local_admission_path(paths), &record)?;
    // Retain the old projection for status consumers from older CLI builds.
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.set_kv("ego-browser-local-admission", admission)
}

fn validate_local_admission_record(record: &LocalAdmissionRecord) -> Result<()> {
    if record.version != 1
        || !matches!(record.state.as_str(), "closed" | "ready" | "open")
        || record.updated_at_unix == 0
        || record
            .device_id
            .as_deref()
            .is_some_and(|value| !safe_lifecycle_id(value))
        || record
            .binding_id
            .as_deref()
            .is_some_and(|value| !safe_lifecycle_id(value))
        || record.device_generation == Some(0)
        || record.binding_generation == Some(0)
        || record.device_id.is_some() != record.device_generation.is_some()
    {
        bail!("local ego-browser admission record failed validation")
    }
    match record.state.as_str() {
        "open" => {
            if record.device_id.is_none()
                || record.device_generation.is_none()
                || record.binding_id.is_none()
                || record.binding_generation.is_none()
            {
                bail!("open local admission must carry complete identity and binding references")
            }
        }
        "closed" | "ready" => {
            if record.binding_id.is_some() || record.binding_generation.is_some() {
                bail!("closed local admission cannot carry a binding reference")
            }
        }
        _ => unreachable!("state was checked above"),
    }
    Ok(())
}

fn ensure_device_store_dir(directory: &Path) -> Result<()> {
    fs::create_dir_all(directory)?;
    let metadata = fs::symlink_metadata(directory)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("ego-browser Device store is not a directory")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!("ego-browser Device store has unsafe ownership")
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn write_local_admission_record(
    directory: &Path,
    destination: &Path,
    record: &LocalAdmissionRecord,
) -> Result<()> {
    let bytes = serde_json::to_vec(record)?;
    let temporary = directory.join(format!(
        ".ego-browser-local-admission-{}-{}",
        std::process::id(),
        new_operation_id().trim_start_matches("op_")
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, destination)?;
        crate::platform::set_owner_only_permissions(destination)?;
        #[cfg(unix)]
        fs::File::open(directory)?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

async fn discover_device_metadata(paths: &AppPaths) -> Result<LocalDeviceMetadata> {
    if let Ok(output) = run_device_client_at(paths, [OsString::from("metadata")]).await {
        if let Ok(metadata) = parse_local_device_metadata(&output) {
            return Ok(metadata);
        }
    }
    if let Ok(metadata) = read_local_device_metadata_file(paths) {
        return Ok(metadata);
    }
    // Destructive commands require exact local identity metadata, never a server-list guess.
    bail!("exact local ego-browser device metadata is unavailable")
}

fn write_pending_revocation(paths: &AppPaths, pending: &PendingRevocation) -> Result<()> {
    validate_pending_revocation(pending)?;
    paths.ensure_base_dirs()?;
    let path = pending_revocation_path(paths);
    let bytes = serde_json::to_vec_pretty(pending)?;
    let temporary = paths.home().join(format!(
        ".ego-browser-pending-revocation-{}-{}",
        std::process::id(),
        new_operation_id().trim_start_matches("op_")
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("failed to create {}", temporary.display()))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)
            .with_context(|| format!("failed to replace {}", path.display()))?;
        crate::platform::set_owner_only_permissions(&path)?;
        #[cfg(unix)]
        fs::File::open(paths.home())?.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn read_owner_only_file(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let path_metadata = fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "owner-only state path is not a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if path_metadata.uid() != unsafe { libc::geteuid() }
            || path_metadata.nlink() != 1
            || path_metadata.permissions().mode() & 0o777 != 0o600
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "owner-only state path has unsafe ownership or permissions",
            ));
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if path_metadata.dev() != opened.dev() || path_metadata.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "owner-only state path changed while opening",
            ));
        }
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::FileTooLarge,
            "owner-only state path is oversized",
        ));
    }
    Ok(bytes)
}

fn trust_confirmation_path(paths: &AppPaths) -> PathBuf {
    paths.home().join("ego-browser-trust.json")
}

fn load_trust_confirmation(paths: &AppPaths) -> Result<Option<LocalTrustConfirmation>> {
    let bytes = match read_owner_only_file(&trust_confirmation_path(paths), 8 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let confirmation: LocalTrustConfirmation = serde_json::from_slice(&bytes)
        .context("local ego-browser trust confirmation is malformed")?;
    if !matches!(confirmation.version, 1 | 2)
        || confirmation.profile_id.is_empty()
        || confirmation.profile_id.len() > 128
        || !confirmation
            .profile_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || confirmation.signer_certificate_sha256.len() != 64
        || !confirmation
            .signer_certificate_sha256
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        || (confirmation.version == 1
            && (!confirmation.profile_version.is_empty()
                || !confirmation.bridge_version.is_empty()))
        || (confirmation.version == 2
            && (!valid_release_version(&confirmation.profile_version)
                || !valid_release_version(&confirmation.bridge_version)))
    {
        bail!("local ego-browser trust confirmation failed validation")
    }
    Ok(Some(confirmation))
}

fn write_trust_confirmation(paths: &AppPaths, confirmation: &LocalTrustConfirmation) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(confirmation)?;
    paths.ensure_base_dirs()?;
    let path = trust_confirmation_path(paths);
    let temporary = paths.home().join(format!(
        ".ego-browser-trust-{}-{}",
        std::process::id(),
        new_operation_id().trim_start_matches("op_")
    ));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, &path)?;
        crate::platform::set_owner_only_permissions(&path)?;
        #[cfg(unix)]
        fs::File::open(paths.home())?.sync_all()?;
        Ok::<(), anyhow::Error>(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[derive(Debug, Deserialize)]
struct InstalledSigningEvidence {
    schema_version: u8,
    version: String,
    profile: String,
    signer_certificate_sha256: String,
}

fn discover_bridge_trust_evidence(paths: &AppPaths) -> Result<Option<BridgeTrustEvidence>> {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(installer) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_INSTALLER") {
        if let Some(root) = infer_bridge_install_root(Path::new(&installer)) {
            roots.push(root);
        }
    }
    if let Some(executable) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE") {
        if let Some(root) = infer_bridge_install_root(Path::new(&executable)) {
            roots.push(root);
        }
    }
    if let Some(home) = crate::platform::user_home_dir() {
        roots.push(
            home.join("Library")
                .join("Application Support")
                .join("Agent Remote Ego Browser"),
        );
    }
    roots.push(paths.home().join("ego-browser"));
    let mut seen_roots = HashSet::new();
    let mut discovered = None;
    for root in roots {
        if !seen_roots.insert(root.clone()) {
            continue;
        }
        let current = root.join("current");
        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        if !metadata.file_type().is_symlink() {
            bail!("managed Bridge current path is not a symlink")
        }
        let releases = fs::canonicalize(root.join("releases"))
            .context("managed Bridge releases directory is unavailable")?;
        let release =
            fs::canonicalize(&current).context("managed Bridge current release is unavailable")?;
        if release.parent() != Some(releases.as_path()) {
            bail!("managed Bridge current release escaped its releases directory")
        }
        let version =
            String::from_utf8(read_installed_release_file(&release.join("VERSION"), 128)?)?
                .trim()
                .to_owned();
        if !valid_release_version(&version) {
            bail!("managed Bridge release version is invalid")
        }
        let evidence_bytes =
            read_installed_release_file(&release.join("SIGNING-EVIDENCE.json"), 32 * 1024)?;
        let evidence: InstalledSigningEvidence = serde_json::from_slice(&evidence_bytes)
            .context("managed Bridge signing evidence is malformed")?;
        let pin = read_trusted_certificate_pin(&root.join("TRUSTED_CERTIFICATE_SHA256"))?
            .context("managed Bridge trusted certificate pin is missing")?;
        if evidence.schema_version != 1
            || evidence.version != version
            || evidence.profile != MANAGED_PROFILE_ID
            || evidence.signer_certificate_sha256 != pin
            || pin != MANAGED_SIGNER_CERTIFICATE_SHA256
        {
            bail!("managed Bridge signing evidence does not match the supported profile")
        }
        let value = BridgeTrustEvidence {
            profile_id: evidence.profile,
            profile_version: version.clone(),
            bridge_version: version,
            signer_certificate_sha256: pin,
        };
        if let Some(previous) = &discovered {
            if previous != &value {
                bail!("multiple managed Bridge installations have conflicting trust evidence")
            }
        } else {
            discovered = Some(value);
        }
    }
    Ok(discovered)
}

fn valid_release_version(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.is_ascii()
        && semver::Version::parse(value).is_ok_and(|version| version.to_string() == value)
}

fn read_installed_release_file(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if before.file_type().is_symlink() || !before.is_file() || before.len() > limit {
        bail!("managed Bridge release metadata is not a bounded regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.uid() != unsafe { libc::geteuid() }
            || before.nlink() != 1
            || before.permissions().mode() & 0o777 != 0o400
        {
            bail!("managed Bridge release metadata has unsafe ownership or permissions")
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = file.metadata()?;
        if before.dev() != after.dev() || before.ino() != after.ino() || after.nlink() != 1 {
            bail!("managed Bridge release metadata changed while opening")
        }
    }
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("managed Bridge release metadata exceeds its size limit")
    }
    Ok(bytes)
}

fn read_trusted_certificate_pin(path: &Path) -> Result<Option<String>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        bail!("trusted certificate pin is not a regular file")
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
            || metadata.permissions().mode() & 0o777 != 0o400
        {
            bail!("trusted certificate pin has unsafe ownership or permissions")
        }
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let opened = file.metadata()?;
        if metadata.dev() != opened.dev() || metadata.ino() != opened.ino() {
            bail!("trusted certificate pin changed while opening")
        }
    }
    let mut bytes = Vec::new();
    file.take(66).read_to_end(&mut bytes)?;
    if bytes.len() > 65 {
        bail!("trusted certificate pin is oversized")
    }
    let value = String::from_utf8(bytes)?.trim().to_owned();
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("trusted certificate pin is invalid")
    }
    Ok(Some(value.to_ascii_lowercase()))
}

fn parse_local_device_metadata(output: &str) -> Result<LocalDeviceMetadata> {
    if output.len() > 16 * 1024 {
        bail!("local device metadata is oversized")
    }
    let metadata: LocalDeviceMetadata =
        serde_json::from_str(output.trim()).context("local Device Client metadata is malformed")?;
    validate_local_device_metadata(&metadata)?;
    Ok(metadata)
}

fn validate_local_device_metadata(metadata: &LocalDeviceMetadata) -> Result<()> {
    if !safe_lifecycle_id(&metadata.device_id)
        || metadata.device_generation == 0
        || !valid_lifecycle_server_url(&metadata.server_url)
        || metadata.release_profile.is_empty()
        || metadata.release_profile.len() > 128
        || !metadata
            .release_profile
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
        || metadata.credential_profile.len() > 128
        || (metadata.credential_revision == 0) != (metadata.credential_expires_at_unix == 0)
    {
        bail!("local Device Client metadata failed validation")
    }
    Ok(())
}

fn load_local_device_metadata(paths: &AppPaths) -> Result<Option<LocalDeviceMetadata>> {
    let Some(directory) = validate_existing_device_store(paths)? else {
        return Ok(None);
    };
    let credential_path = directory.join("ego-browser-credential.json");
    let bytes = match read_owner_only_file(&credential_path, 64 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let metadata_path = directory.join("ego-browser-device-metadata.json");
            let bytes = match read_owner_only_file(&metadata_path, 16 * 1024) {
                Ok(bytes) => bytes,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
                Err(error) => {
                    return Err(anyhow!(
                        "failed to read {}: {error}",
                        metadata_path.display()
                    ));
                }
            };
            let value: serde_json::Value =
                serde_json::from_slice(&bytes).context("local identity metadata is malformed")?;
            let object = value
                .as_object()
                .context("local identity metadata is not an object")?;
            let string_field = |name: &str| {
                object
                    .get(name)
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
            };
            let device_id = string_field("device_id").context("local identity has no device ID")?;
            let server_url =
                string_field("server_url").context("local identity has no server origin")?;
            let release_profile =
                string_field("release_profile").unwrap_or_else(|| MANAGED_PROFILE_ID.to_owned());
            let credential_profile = string_field("credential_profile")
                .unwrap_or_else(|| MANAGED_CREDENTIAL_PROFILE.to_owned());
            let device_generation = read_local_key_generation(paths)?;
            let metadata = LocalDeviceMetadata {
                device_id,
                device_generation,
                server_url: crate::normalize_server_url(&server_url),
                release_profile,
                credential_profile,
                credential_revision: 0,
                credential_expires_at_unix: 0,
            };
            validate_local_device_metadata(&metadata)?;
            return Ok(Some(metadata));
        }
        Err(error) => {
            return Err(anyhow!(
                "failed to read {}: {error}",
                credential_path.display()
            ));
        }
    };
    let value: serde_json::Value = serde_json::from_slice(&bytes)
        .context("local Device Client credential metadata is malformed")?;
    let object = value
        .as_object()
        .context("local Device Client credential metadata is not an object")?;
    let string_field = |name: &str| {
        object
            .get(name)
            .and_then(serde_json::Value::as_str)
            .map(str::to_owned)
    };
    let device_id = string_field("device_id").context("local credential has no device ID")?;
    let server_url = string_field("server_url").context("local credential has no server origin")?;
    let release_profile =
        string_field("release_profile").unwrap_or_else(|| MANAGED_PROFILE_ID.to_owned());
    let credential_profile =
        string_field("credential_profile").unwrap_or_else(|| MANAGED_CREDENTIAL_PROFILE.to_owned());
    let credential_revision = object
        .get("revision")
        .and_then(serde_json::Value::as_u64)
        .context("local credential has no revision")?;
    let credential_expires_at_unix = object
        .get("expires_at_unix")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let device_generation = object
        .get("device_generation")
        .or_else(|| object.get("generation"))
        .and_then(serde_json::Value::as_u64)
        .or_else(|| read_local_key_generation(paths).ok())
        .context("local identity has no device generation")?;
    let metadata = LocalDeviceMetadata {
        device_id,
        device_generation,
        server_url: crate::normalize_server_url(&server_url),
        release_profile,
        credential_profile,
        credential_revision,
        credential_expires_at_unix,
    };
    validate_local_device_metadata(&metadata)?;
    Ok(Some(metadata))
}

fn read_local_device_metadata_file(paths: &AppPaths) -> Result<LocalDeviceMetadata> {
    load_local_device_metadata(paths)?.context("local Device Client metadata does not exist")
}

fn load_local_active_binding_handoff(
    paths: &AppPaths,
) -> Result<Option<LocalActiveBindingHandoff>> {
    let path = device_store_dir(paths).join("ego-browser-active-binding.json");
    let bytes = match read_owner_only_file(&path, 16 * 1024) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(anyhow!(
                "failed to read local ego-browser binding handoff: {error}"
            ))
        }
    };
    let handoff: LocalActiveBindingHandoff =
        serde_json::from_slice(&bytes).context("local ego-browser binding handoff is malformed")?;
    validate_local_active_binding_handoff(&handoff)?;
    Ok(Some(handoff))
}

fn validate_local_active_binding_handoff(handoff: &LocalActiveBindingHandoff) -> Result<()> {
    if handoff.version != 1
        || !safe_lifecycle_id(&handoff.binding_id)
        || handoff.generation == 0
        || !safe_lifecycle_id(&handoff.device_id)
        || handoff.task_space_label.is_empty()
        || handoff.task_space_label.len() > 256
        || !handoff
            .task_space_label
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
        || handoff.authorization_mode != "ego_browser_script_full_trust"
        || !handoff.user_confirmation
    {
        bail!("local ego-browser binding handoff failed validation")
    }
    Ok(())
}

fn read_local_key_generation(paths: &AppPaths) -> Result<u64> {
    let path = device_store_dir(paths).join("ego-browser-device-key.bin");
    let bytes = read_owner_only_file(&path, 128)
        .with_context(|| format!("failed to read {}", path.display()))?;
    if bytes.len() < 16 || &bytes[..8] != b"EGBKEY1\0" && &bytes[..8] != b"EGBKEY2\0" {
        bail!("local identity key is malformed")
    }
    let generation = u64::from_be_bytes(bytes[8..16].try_into()?);
    if generation == 0 {
        bail!("local identity generation is invalid")
    }
    Ok(generation)
}

fn record_pending_failure(
    paths: &AppPaths,
    mut pending: PendingRevocation,
    _error_code: &str,
) -> Result<PendingRevocation> {
    pending.retry_count = pending.retry_count.saturating_add(1);
    let exponent = pending.retry_count.min(9);
    let delay = 5_u64.saturating_mul(1_u64 << exponent).min(3600);
    pending.next_retry_at_unix = unix_time_seconds().saturating_add(delay);
    write_pending_revocation(paths, &pending)?;
    Ok(pending)
}

fn pending_revocation_error(pending: &PendingRevocation, next_command: &str) -> anyhow::Error {
    anyhow!(
        "error_code=pending_revocation state=pending_revocation admission=closed scope={} retry_count={} next_retry_at_unix={} operation_id={} next_action=retry_revocation next_command={} stale=false",
        pending.scope,
        pending.retry_count,
        pending.next_retry_at_unix,
        pending.operation_id,
        next_command
    )
}

fn pending_revocation_next_command(pending: &PendingRevocation) -> &'static str {
    if pending.reason == "switch_server" {
        "agent-remote ego-browser switch-server --server-url SERVER"
    } else if pending.scope == "binding" {
        "agent-remote ego-browser remove"
    } else {
        "agent-remote ego-browser forget-this-mac"
    }
}

async fn revoke_pending_binding(
    client: &ApiClient,
    token: &str,
    pending: &PendingRevocation,
) -> Result<(), String> {
    let binding_id = pending
        .binding_id
        .as_deref()
        .ok_or_else(|| "binding_id_missing".to_owned())?;
    let generation = pending
        .target_binding_generation
        .ok_or_else(|| "binding_generation_missing".to_owned())?;
    let result = client
        .control_ego_browser_binding(token, binding_id, generation, "revoke", "remove_binding")
        .await
        .map_err(|error| error.code().unwrap_or("server_unreachable").to_owned())?;
    if result.id != binding_id
        || !matches!(
            result.status.as_str(),
            "revoked" | "stopped" | "expired" | "failed"
        )
    {
        return Err("binding_revoke_unconfirmed".to_owned());
    }
    Ok(())
}

async fn revoke_pending_device(
    client: &ApiClient,
    token: &str,
    pending: &PendingRevocation,
) -> Result<(), String> {
    let device_id = pending
        .device_id
        .as_deref()
        .ok_or_else(|| "device_id_missing".to_owned())?;
    let generation = pending
        .device_generation
        .ok_or_else(|| "device_generation_missing".to_owned())?;
    let result = client
        .revoke_ego_browser_device(token, device_id, generation, &pending.reason)
        .await
        .map_err(|error| error.code().unwrap_or("server_unreachable").to_owned())?;
    if result.id != device_id || result.status != "revoked" {
        return Err("device_revoke_unconfirmed".to_owned());
    }
    Ok(())
}

async fn run_bridge_installer(paths: &AppPaths, operation: &str, yes: bool) -> Result<()> {
    let mut candidates = Vec::new();
    if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
        candidates.push(
            PathBuf::from(root)
                .join("current")
                .join("installer/install-macos.sh"),
        );
    }
    if let Some(home) = crate::platform::user_home_dir() {
        candidates.push(
            home.join("Library")
                .join("Application Support")
                .join("Agent Remote Ego Browser")
                .join("current")
                .join("installer/install-macos.sh"),
        );
    }
    candidates.push(
        paths
            .home()
            .join("ego-browser/current/installer/install-macos.sh"),
    );
    let source = select_bridge_installer(operation, candidates)?;
    let BridgeInstallerSource::Installed(script) = source else {
        return run_managed_bridge_bootstrap(paths).await;
    };
    let inferred_install_root = infer_bridge_install_root(&script);
    let mut command = if script
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
    {
        let mut command = ProcessCommand::new("bash");
        command.arg(&script);
        command
    } else {
        ProcessCommand::new(&script)
    };
    command.arg(format!("--{operation}"));
    if yes {
        command.arg("--yes");
    }
    if let Some(root) = inferred_install_root {
        command.env("EGO_BROWSER_INSTALL_ROOT", root);
    }
    // Installer and CLI subprocesses must share the same owner-only Device store.
    command.env("EGO_BROWSER_DEVICE_HOME", device_store_dir(paths));
    let output = command
        .output()
        .await
        .with_context(|| format!("failed to launch Bridge installer ({})", script.display()))?;
    if !output.status.success() {
        let diagnostic = String::from_utf8_lossy(&output.stderr);
        if diagnostic.contains("bridge_installer_unavailable") {
            bail!("bridge_installer_unavailable")
        }
        bail!("Bridge installer exited with {}", output.status)
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
enum BridgeInstallerSource {
    ManagedBootstrap,
    Installed(PathBuf),
}

fn select_bridge_installer(
    operation: &str,
    candidates: impl IntoIterator<Item = PathBuf>,
) -> Result<BridgeInstallerSource> {
    if !matches!(operation, "setup" | "repair" | "upgrade") {
        bail!("unsupported Bridge installer operation")
    }
    if operation == "upgrade" {
        return Ok(BridgeInstallerSource::ManagedBootstrap);
    }
    let installed = candidates.into_iter().find(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| {
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && secure_installed_executable_metadata(&metadata)
            })
            .unwrap_or(false)
    });
    if let Some(script) = installed {
        return Ok(BridgeInstallerSource::Installed(script));
    }
    if operation == "setup" {
        return Ok(BridgeInstallerSource::ManagedBootstrap);
    }
    bail!("bridge_installer_unavailable: signed Bridge installer is unavailable")
}

fn secure_installed_executable_metadata(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o777 == 0o500
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

async fn run_managed_bridge_bootstrap(paths: &AppPaths) -> Result<()> {
    if !cfg!(target_os = "macos") {
        bail!("the managed ego-browser Bridge bootstrap supports macOS only")
    }
    let bootstrap = bridge_release::obtain_bootstrap()
        .await
        .context("release_verification_failed: pinned Bridge bootstrap is unavailable")?;
    let mut command = ProcessCommand::new("bash");
    command
        .arg(bootstrap.path())
        .args(bridge_release::managed_bootstrap_arguments())
        .env("EGO_BROWSER_DEVICE_HOME", device_store_dir(paths))
        .env_remove("EGO_BROWSER_SERVER_URL")
        .env_remove("EGO_BROWSER_REGISTRATION_TOKEN")
        .env_remove("EGO_BROWSER_SESSION_ID")
        .env_remove("EGO_BROWSER_CONFIRM_FULL_TRUST")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let status = command
        .status()
        .await
        .context("failed to launch the authenticated Bridge bootstrap")?;
    if !status.success() {
        bail!("authenticated Bridge bootstrap exited with {status}")
    }
    Ok(())
}

async fn run_bridge_uninstaller(paths: &AppPaths, remove_releases: bool) -> Result<()> {
    let executable = device_client_executable();
    let mut candidates = Vec::new();
    if let Some(override_path) = std::env::var_os("AGENT_REMOTE_EGO_BROWSER_UNINSTALLER") {
        candidates.push(PathBuf::from(override_path));
    }
    candidates.push(paths.home().join("bin/ego-browser-uninstall"));
    let executable_path = PathBuf::from(&executable);
    if executable_path.is_absolute() {
        if let Some(bin_dir) = executable_path.parent() {
            if let Some(install_root) = bin_dir.parent() {
                candidates.push(install_root.join("installer/uninstall-macos.sh"));
            }
        }
    }
    let Some(script) = candidates.into_iter().find(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| {
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && secure_installed_executable_metadata(&metadata)
            })
            .unwrap_or(false)
    }) else {
        if !managed_bridge_installation_exists(paths) {
            return Ok(());
        }
        bail!("signed Bridge uninstaller is unavailable")
    };
    let inferred_install_root = infer_bridge_install_root(&script);
    let mut command = if script
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("sh"))
    {
        let mut command = ProcessCommand::new("bash");
        command.arg(&script);
        command
    } else {
        ProcessCommand::new(&script)
    };
    if let Some(root) = inferred_install_root {
        // Pass the signed layout root so a custom install cannot remove the default location.
        command.env("EGO_BROWSER_INSTALL_ROOT", root);
    }
    if remove_releases {
        command.arg("--remove-releases");
    }
    command.stdout(Stdio::null()).stderr(Stdio::null());
    let output = command
        .output()
        .await
        .with_context(|| format!("failed to launch Bridge uninstaller ({})", script.display()))?;
    if !output.status.success() {
        bail!("Bridge uninstaller exited with {}", output.status)
    }
    Ok(())
}

fn infer_bridge_install_root(script: &std::path::Path) -> Option<PathBuf> {
    let installer_dir = script.parent()?;
    let release_dir = installer_dir.parent()?;
    if release_dir
        .file_name()
        .is_some_and(|name| name == "current")
    {
        return release_dir.parent().map(PathBuf::from);
    }
    if release_dir
        .parent()
        .and_then(std::path::Path::file_name)
        .is_some_and(|name| name == "releases")
    {
        return release_dir
            .parent()
            .and_then(std::path::Path::parent)
            .map(PathBuf::from);
    }
    None
}

fn device_client_available(paths: &AppPaths) -> bool {
    let executable = PathBuf::from(device_client_executable());
    if executable.components().count() > 1 {
        return executable.is_file();
    }
    if paths.home().join("bin").join(&executable).is_file() {
        return true;
    }
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|value| std::env::split_paths(&value).collect::<Vec<_>>())
        .map(|directory| directory.join(&executable))
        .any(|candidate| candidate.is_file())
}

fn managed_bridge_installation_exists(paths: &AppPaths) -> bool {
    let mut roots = Vec::new();
    if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
        roots.push(PathBuf::from(root));
    }
    if let Some(home) = crate::platform::user_home_dir() {
        roots.push(
            home.join("Library")
                .join("Application Support")
                .join("Agent Remote Ego Browser"),
        );
    }
    roots.push(paths.home().join("ego-browser"));
    roots
        .into_iter()
        .any(|root| fs::symlink_metadata(root.join("current")).is_ok())
}

fn clear_pending_revocation(paths: &AppPaths) -> Result<()> {
    match fs::remove_file(pending_revocation_path(paths)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn close_local_admission(paths: &AppPaths) -> Result<()> {
    set_local_admission_state(paths, "closed")
}

fn reject_pending_revocation(paths: &AppPaths) -> Result<()> {
    let Some(pending) = load_pending_revocation(paths)? else {
        return Ok(());
    };
    close_local_admission(paths)?;
    let next_command = pending_revocation_next_command(&pending);
    Err(pending_revocation_error(&pending, next_command))
}

fn candidate_fingerprint(candidate: &EgoBrowserBindingCandidateData) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        candidate.tool_session_id,
        candidate.tool_type,
        candidate.tool_account_id,
        candidate.workspace_id,
        candidate.node_id,
        candidate.status,
        candidate.runtime_backend,
        candidate.project_key,
        candidate.display_name,
        candidate
            .current_ego_browser_device_id
            .as_deref()
            .unwrap_or(""),
        candidate
            .current_ego_browser_device_name
            .as_deref()
            .unwrap_or(""),
        candidate.binding_id.as_deref().unwrap_or(""),
        candidate.controllable
    )
}

fn candidate_matches_selection(
    selected: &EgoBrowserBindingCandidateData,
    refreshed: &EgoBrowserBindingCandidateData,
) -> bool {
    refreshed.tool_session_id == selected.tool_session_id
        && refreshed.controllable
        && candidate_fingerprint(refreshed) == candidate_fingerprint(selected)
}

fn select_candidate(
    candidates: &[EgoBrowserBindingCandidateData],
    requested: Option<&str>,
) -> Result<EgoBrowserBindingCandidateData> {
    select_candidate_with_interactivity(candidates, requested, interactive_terminal())
}

fn select_candidate_with_interactivity(
    candidates: &[EgoBrowserBindingCandidateData],
    requested: Option<&str>,
    interactive: bool,
) -> Result<EgoBrowserBindingCandidateData> {
    let selectable: Vec<&EgoBrowserBindingCandidateData> = candidates
        .iter()
        .filter(|candidate| candidate.controllable)
        .collect();
    if let Some(requested) = requested {
        let matches: Vec<&EgoBrowserBindingCandidateData> = selectable
            .iter()
            .copied()
            .filter(|candidate| {
                candidate.tool_session_id == requested
                    || candidate.tool_session_id.starts_with(requested)
            })
            .collect();
        return match matches.as_slice() {
            [candidate] => Ok((*candidate).clone()),
            [] => Err(lifecycle_error(
                "no_session_candidate",
                "candidates",
                "unknown",
                "start_session",
                "agent-remote ego-browser connect",
                false,
            )),
            _ => Err(lifecycle_error(
                "confirmation_required",
                "candidates",
                "unknown",
                "select_session",
                "agent-remote ego-browser connect TOOL_SESSION",
                false,
            )),
        };
    }
    match selectable.as_slice() {
        [] => Err(lifecycle_error(
            "no_session_candidate",
            "candidates",
            "unknown",
            "start_session",
            "agent-remote ego-browser connect",
            false,
        )),
        [candidate] => Ok((*candidate).clone()),
        _ if !interactive => Err(lifecycle_error(
            "confirmation_required",
            "candidates",
            "unknown",
            "select_session",
            "agent-remote ego-browser connect TOOL_SESSION",
            false,
        )),
        many => {
            terminal::section("Ego-browser session candidates");
            let mut table = Table::new([
                "#",
                "SESSION",
                "PROJECT",
                "WORKSPACE",
                "BACKEND",
                "NODE",
                "STATUS",
            ]);
            for (index, candidate) in many.iter().enumerate() {
                table.row([
                    (index + 1).to_string(),
                    short_id(&candidate.tool_session_id),
                    candidate.display_name.clone(),
                    short_id(&candidate.workspace_id),
                    candidate.runtime_backend.clone(),
                    short_id(&candidate.node_id),
                    candidate.status.clone(),
                ]);
            }
            table.render();
            let mut input = String::new();
            print!("Select a session number: ");
            use std::io::Write;
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            let index = input
                .trim()
                .parse::<usize>()
                .ok()
                .filter(|value| *value >= 1 && *value <= many.len())
                .context("invalid session selection")?;
            Ok(many[index - 1].clone())
        }
    }
}

fn lifecycle_error(
    code: &str,
    state: &str,
    admission: &str,
    next_action: &str,
    next_command: &str,
    stale: bool,
) -> anyhow::Error {
    anyhow!(
        "error_code={code} state={state} admission={admission} next_action={next_action} next_command={next_command} stale={stale}"
    )
}

fn map_api_error(error: crate::api::ApiError, operation: &str) -> anyhow::Error {
    map_api_error_fields(
        error.status_code(),
        error.code().unwrap_or("control_plane_error"),
        operation,
    )
}

fn map_api_error_fields(
    status_code: Option<u16>,
    raw_code: &str,
    operation: &str,
) -> anyhow::Error {
    let normalized = raw_code.to_ascii_uppercase();
    if status_code == Some(401) {
        return crate::auth::user_login_error();
    }
    let (code, admission, default_next_action) = if status_code.is_none() {
        ("server_unreachable", "unknown", "retry")
    } else {
        match normalized.as_str() {
            "EGO_BROWSER_GENERATION_MISMATCH" | "EGO_BROWSER_POP_CONTEXT_INVALID"
                if matches!(
                    operation,
                    "pause" | "resume" | "stop" | "revoke" | "lifecycle" | "upgrade"
                ) =>
            {
                ("binding_generation_stale", "unknown", "refresh_status")
            }
            "EGO_BROWSER_BINDING_NOT_FOUND" => ("no_active_binding", "unknown", "connect"),
            // Accept the historical *_ADMISSION_DISABLED spelling under one stable CLI code.
            "EGO_BROWSER_EXECUTION_ADMISSION_DISABLED" => (
                "admission_disabled",
                "server_execution_closed",
                "request_execution_admission",
            ),
            "EGO_BROWSER_ENROLLMENT_DISABLED" | "EGO_BROWSER_ENROLLMENT_ADMISSION_DISABLED" => (
                "admission_disabled",
                "server_enrollment_closed",
                "request_enrollment_admission",
            ),
            "SERVER_CAPABILITY_UNAVAILABLE" => {
                ("server_capability_unavailable", "unknown", "repair")
            }
            "ADMISSION_DISABLED" => (
                "admission_disabled",
                "unknown",
                admission_next_action(operation),
            ),
            "EGO_BROWSER_DEVICE_NOT_FOUND" => ("device_not_found", "unknown", "retry"),
            "EGO_BROWSER_DEVICE_CONFLICT" => ("device_conflict", "unknown", "retry"),
            "EGO_BROWSER_DEVICE_REVOKED" => ("device_revoked", "unknown", "forget"),
            "EGO_BROWSER_IDEMPOTENCY_CONFLICT" => ("operation_conflict", "unknown", "retry"),
            "EGO_BROWSER_IDEMPOTENCY_INVALID" | "EGO_BROWSER_IDEMPOTENCY_RESULT_INVALID" => {
                ("operation_failed", "unknown", "repair")
            }
            "EGO_BROWSER_SESSION_UNAVAILABLE" => {
                ("session_unavailable", "unknown", "start_session")
            }
            value if value.starts_with("NODE_JOIN_CODE_") => {
                ("node_join_code_error", "unknown", "repair")
            }
            "EGO_BROWSER_PROFILE_MISMATCH"
            | "EGO_BROWSER_SIGNER_MISMATCH"
            | "EGO_BROWSER_VERSION_MISMATCH"
            | "EGO_BROWSER_RUNTIME_UNSUPPORTED"
            | "EGO_BROWSER_RUNTIME_UNAVAILABLE"
            | "EGO_BROWSER_CAPABILITY_MISMATCH"
            | "EGO_BROWSER_CAPABILITY_DIGEST_MISMATCH"
            | "EGO_BROWSER_POLICY_DIGEST_MISMATCH"
            | "EGO_BROWSER_ENCRYPTION_KEY_MISMATCH"
            | "EGO_BROWSER_ENCRYPTION_KEY_REQUIRED"
            | "EGO_BROWSER_CREDENTIAL_PROFILE_UNSUPPORTED" => {
                ("compatibility_mismatch", "unknown", "repair")
            }
            "EGO_BROWSER_GENERATION_MISMATCH" => ("device_generation_conflict", "unknown", "retry"),
            _ => ("control_plane_error", "unknown", "retry"),
        }
    };
    let status = if status_code.is_some_and(|value| value == 404) {
        "unknown"
    } else {
        "installed"
    };
    let next_action = match code {
        "EGO_BROWSER_SESSION_UNAVAILABLE" => "start_session",
        _ => default_next_action,
    };
    lifecycle_error(
        code,
        status,
        admission,
        next_action,
        &format!("agent-remote ego-browser {operation}"),
        false,
    )
}

fn admission_next_action(operation: &str) -> &'static str {
    if matches!(
        operation,
        "setup" | "register" | "re-enroll" | "device-rotate" | "repair"
    ) {
        "request_enrollment_admission"
    } else {
        "request_execution_admission"
    }
}

fn map_operational_error(error: anyhow::Error, operation: &str) -> anyhow::Error {
    let rendered = format!("{error:#}");
    let code = SAFE_DEVICE_CLIENT_ERROR_CODES
        .iter()
        .copied()
        .find(|value| rendered.contains(value))
        .unwrap_or("control_plane_error");
    let (admission, next_action) = if code == "admission_disabled" {
        if admission_next_action(operation) == "request_enrollment_admission" {
            ("server_enrollment_closed", "request_enrollment_admission")
        } else {
            ("server_execution_closed", "request_execution_admission")
        }
    } else {
        (
            "unknown",
            match code {
                "login_required" => "login",
                "device_not_found" => "re_enroll",
                "device_revoked" | "identity_origin_conflict" => "forget",
                "bridge_installer_unavailable" => "install_bridge",
                _ => "repair",
            },
        )
    };
    lifecycle_error(
        code,
        "installed",
        admission,
        next_action,
        &format!("agent-remote ego-browser {operation}"),
        false,
    )
}

async fn run_device_client_at<const N: usize>(
    paths: &AppPaths,
    args: [OsString; N],
) -> Result<String> {
    let executable = device_client_executable();
    let mut command = ProcessCommand::new(&executable);
    command
        .args(args)
        .env("EGO_BROWSER_DEVICE_HOME", device_store_dir(paths));
    let output = command
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .await
        .with_context(|| device_client_launch_context(&executable))?;
    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    finish_device_client(output)?;
    Ok(stdout)
}

async fn run_device_client_with_token_at<const N: usize>(
    paths: &AppPaths,
    args: [OsString; N],
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        bail!("agent-remote credential store returned an empty token")
    }
    let executable = device_client_executable();
    let mut command = ProcessCommand::new(&executable);
    command
        .args(args)
        .env("EGO_BROWSER_DEVICE_HOME", device_store_dir(paths))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .with_context(|| device_client_launch_context(&executable))?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Device Client token pipe")?;
    stdin
        .write_all(token.as_bytes())
        .await
        .context("failed to pass the credential to the Device Client")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for the Device Client")?;
    finish_device_client(output)
}

#[derive(Clone, Copy)]
struct JsonCommandSuccess {
    command: &'static str,
    result: &'static str,
    next_action: &'static str,
    next_command: Option<&'static str>,
}

fn render_command_success_json(success: JsonCommandSuccess) {
    println!(
        "{}",
        serde_json::json!({
            "error_code": serde_json::Value::Null,
            "command": success.command,
            "result": success.result,
            "state": {
                "phase": success.result,
                "installed": serde_json::Value::Null,
                "enabled": serde_json::Value::Null,
                "registered": serde_json::Value::Null,
                "available": serde_json::Value::Null,
                "connected": serde_json::Value::Null,
            },
            "stale": false,
            "next_action": success.next_action,
            "next_command": success.next_command,
        })
    );
}

pub async fn run(paths: AppPaths, command: EgoBrowserCommand, json: bool) -> Result<()> {
    let _output_guard = terminal::suppress_output(json);
    migrate_legacy_device_store(&paths)?;
    let success = match command {
        EgoBrowserCommand::Setup(args) => {
            setup(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "setup",
                result: "ready",
                next_action: "connect",
                next_command: Some("agent-remote ego-browser connect"),
            })
        }
        EgoBrowserCommand::Connect(args) => {
            connect(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "connect",
                result: "claim_submitted",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Repair(args) => {
            repair(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "repair",
                result: "ready",
                next_action: "connect",
                next_command: Some("agent-remote ego-browser connect"),
            })
        }
        EgoBrowserCommand::Upgrade(args) => {
            upgrade(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "upgrade",
                result: "ready",
                next_action: "connect",
                next_command: Some("agent-remote ego-browser connect"),
            })
        }
        EgoBrowserCommand::Remove(args) => {
            remove(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "remove",
                result: "removed",
                next_action: "setup",
                next_command: Some("agent-remote ego-browser setup"),
            })
        }
        EgoBrowserCommand::ForgetThisMac(args) => {
            forget_this_mac(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "forget-this-mac",
                result: "identity_removed",
                next_action: "setup",
                next_command: Some("agent-remote ego-browser setup"),
            })
        }
        EgoBrowserCommand::ReEnroll(args) => {
            re_enroll(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "re-enroll",
                result: "registered",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::DeviceRotate(args) => {
            device_rotate(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "device-rotate",
                result: "registered",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::SwitchServer(args) => {
            switch_server(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "switch-server",
                result: "registered",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Register(args) => {
            register(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "register",
                result: "registered",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Status(args) => {
            status(paths, args, json).await?;
            None
        }
        EgoBrowserCommand::List(args) => {
            list(paths, args, json).await?;
            None
        }
        EgoBrowserCommand::Requests(args) => {
            requests(paths, args, json).await?;
            None
        }
        EgoBrowserCommand::CancelRequest(args) => {
            cancel_request(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "cancel-request",
                result: "completed",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Claim(args) => {
            claim(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "claim",
                result: "claim_submitted",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Pause(args) => {
            lifecycle(paths, "pause", args).await?;
            Some(JsonCommandSuccess {
                command: "pause",
                result: "paused",
                next_action: "resume",
                next_command: Some("agent-remote ego-browser resume"),
            })
        }
        EgoBrowserCommand::Resume(args) => {
            resume(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "resume",
                result: "reauthorization_submitted",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::Stop(args) => {
            lifecycle(paths, "stop", args).await?;
            Some(JsonCommandSuccess {
                command: "stop",
                result: "stopped",
                next_action: "connect",
                next_command: Some("agent-remote ego-browser connect"),
            })
        }
        EgoBrowserCommand::Revoke(args) => {
            lifecycle(paths, "revoke", args).await?;
            Some(JsonCommandSuccess {
                command: "revoke",
                result: "revoked",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::DeleteDevice(args) => {
            delete_device(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "delete-device",
                result: "deleted",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
        EgoBrowserCommand::DeleteBinding(args) => {
            delete_binding(paths, args).await?;
            Some(JsonCommandSuccess {
                command: "delete-binding",
                result: "deleted",
                next_action: "status",
                next_command: Some("agent-remote ego-browser status"),
            })
        }
    };
    if json {
        if let Some(success) = success {
            render_command_success_json(success);
        }
    }
    Ok(())
}

async fn register(paths: AppPaths, args: EgoBrowserRegisterArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let (server_url, token) =
        load_control_token_for_server(&paths, args.server_url.as_deref()).await?;
    let certificate = args
        .signer_certificate_sha256
        .or_else(|| std::env::var("EGO_BROWSER_SIGNER_CERTIFICATE_SHA256").ok())
        .context(
            "Bridge signing-certificate SHA-256 is required; pass --signer-certificate-sha256",
        )?;
    let certificate = certificate.trim().to_ascii_lowercase();
    if certificate.len() != 64 || !certificate.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("Bridge signing-certificate SHA-256 is invalid")
    }

    terminal::note(
        "Registering the ego-browser Device Client with the agent-remote credential store.",
    );
    run_device_client_with_token(
        [
            OsString::from("register"),
            OsString::from("--server"),
            OsString::from(server_url),
            OsString::from("--token-stdin"),
            OsString::from("--signer-certificate-sha256"),
            OsString::from(certificate),
        ],
        &token,
    )
    .await?;
    terminal::success_line("Ego-browser Device Client registered");
    Ok(())
}

async fn status(paths: AppPaths, args: EgoBrowserStatusArgs, json: bool) -> Result<()> {
    let pending = load_pending_revocation(&paths)?;
    if !json {
        if let Some(pending) = pending.as_ref() {
            render_pending_revocation_notice(pending);
        }
    }
    let (server_url, token) = match load_control_token(&paths).await {
        Ok(value) => value,
        Err(_) => return status_from_cache(&paths, &args, None, json),
    };
    let client = ApiClient::new(server_url.clone())?;
    let devices = match client.list_ego_browser_devices(&token, false).await {
        Ok(value) => value,
        Err(_) => return status_from_cache(&paths, &args, Some(&server_url), json),
    };
    let bindings = match client.list_ego_browser_bindings(&token).await {
        Ok(value) => value,
        Err(_) => return status_from_cache(&paths, &args, Some(&server_url), json),
    };
    persist_bindings(&paths, &server_url, &bindings)?;

    if json {
        let selected = if let Some(reference) = args.binding.as_deref() {
            let binding_id = resolve_binding_reference(&bindings, reference)?;
            bindings
                .iter()
                .filter(|binding| binding.id == binding_id)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            bindings.clone()
        };
        let policy = client
            .ego_browser_policy(&token)
            .await
            .map_err(|error| map_api_error(error, "status"))?;
        render_status_json(
            &paths,
            &server_url,
            &devices,
            &selected,
            Some(&policy),
            pending.as_ref(),
            false,
        )?;
        return Ok(());
    }

    if let Some(reference) = args.binding {
        let binding_id = resolve_binding_reference(&bindings, &reference)?;
        let binding = client.get_ego_browser_binding(&token, &binding_id).await?;
        persist_binding(&paths, &server_url, &binding)?;
        print_binding(&binding, args.no_trunc);
        let requests = client
            .list_ego_browser_requests(&token, &binding_id)
            .await?;
        ensure_requests_for_binding(&requests, &binding_id)?;
        terminal::section("Active Ego Browser Requests");
        render_requests(&requests, args.no_trunc);
        return Ok(());
    }

    terminal::section("Ego Browser Devices");
    if devices.is_empty() {
        terminal::note("No independent ego-browser Device Client is registered.");
    } else {
        let mut table = Table::new(["ID", "STATUS", "PROFILE", "BRIDGE", "EGO RUNTIME", "SKILL"]);
        for device in devices {
            table.row([
                display_id(&device.id, args.no_trunc),
                device.status,
                device.release_profile,
                device.bridge_version.unwrap_or_else(|| "-".to_string()),
                device
                    .local_ego_browser_runtime_version
                    .or(device.ego_lite_runtime_version)
                    .unwrap_or_else(|| "-".to_string()),
                device.skill_version.unwrap_or_else(|| "-".to_string()),
            ]);
        }
        table.render();
    }

    terminal::section("Ego Browser Bindings");
    render_bindings(&bindings, args.no_trunc);
    Ok(())
}

fn render_status_json(
    paths: &AppPaths,
    server_url: &str,
    devices: &[EgoBrowserDeviceData],
    bindings: &[EgoBrowserBindingData],
    policy: Option<&EgoBrowserPolicyData>,
    pending: Option<&PendingRevocation>,
    stale: bool,
) -> Result<()> {
    // Server identity state cannot make locally removed Bridge files appear installed.
    let installed = local_bridge_installation_exists(paths);
    let metadata = load_local_device_metadata(paths)?;
    let local = local_admission_snapshot(paths)?;
    let registered = metadata
        .as_ref()
        .is_some_and(|metadata| local_device_is_registered(metadata, server_url, devices));
    let enrollment = policy.is_some_and(EgoBrowserPolicyData::enrollment_is_admitted);
    let execution = policy.is_some_and(EgoBrowserPolicyData::execution_is_admitted);
    let local_ready = local_admission_ready_for_identity(&local, metadata.as_ref());
    let live_binding = local_binding_is_connected(&local, metadata.as_ref(), server_url, bindings);
    let projection = project_status_state(
        installed,
        registered,
        execution,
        local_ready,
        pending.is_some(),
        live_binding,
    );
    let enabled = projection.enabled;
    let available = projection.available;
    let connected = projection.connected;
    let binding_admission = if connected {
        "established"
    } else {
        "not_established"
    };
    let local_admission = if pending.is_some() {
        "closed"
    } else {
        local.state.as_str()
    };
    let device_items = devices
        .iter()
        .map(|device| {
            serde_json::json!({
                "id": short_id(&device.id),
                "status": device.status,
                "release_profile": device.release_profile,
                "bridge_version": device.bridge_version,
                "runtime_version": device.local_ego_browser_runtime_version
                    .as_deref()
                    .or(device.ego_lite_runtime_version.as_deref()),
                "skill_version": device.skill_version,
            })
        })
        .collect::<Vec<_>>();
    let binding_items = bindings
        .iter()
        .map(|binding| {
            serde_json::json!({
                "id": short_id(&binding.id),
                "device_id": short_id(&binding.ego_browser_device_id),
                "tool_session_id": short_id(&binding.tool_session_id),
                "node_id": short_id(&binding.node_id),
                "status": binding.status,
                "binding_generation": binding_generation(binding),
                "lease_health": binding.lease_health,
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::json!({
            "error_code": serde_json::Value::Null,
            "state": {
                "installed": installed,
                "enabled": enabled,
                "registered": registered,
                "available": available,
                "connected": connected,
            },
            "capability": {
                "configured_enabled": serde_json::Value::Null,
                "effective_enabled": serde_json::Value::Null,
                "node_execution_allowed": serde_json::Value::Null,
            },
            "admission": {
                "enrollment": if enrollment { "allowed" } else { "unknown_or_denied" },
                "server_execution": if execution { "allowed" } else { "unknown_or_denied" },
                "binding": binding_admission,
                "local": local_admission,
                "reason": if pending.is_some() { "local" } else { "server" },
            },
            "stale": stale,
            "next_action": if pending.is_some() { "retry_revocation" } else { "none" },
            "next_command": pending.map(pending_revocation_next_command),
            "devices": device_items,
            "bindings": binding_items,
        })
    );
    Ok(())
}

fn local_bridge_installation_exists(paths: &AppPaths) -> bool {
    let local_candidates = [
        paths.home().join("bin/ego-browser-device"),
        paths.home().join("bin/ego-browser-install"),
    ];
    if local_candidates.iter().any(|path| {
        fs::symlink_metadata(path)
            .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
    }) {
        return true;
    }
    let is_default_home = crate::platform::default_app_home()
        .ok()
        .is_some_and(|default| default == paths.home());
    if !is_default_home {
        return false;
    }
    let executable = PathBuf::from(device_client_executable());
    executable.is_absolute()
        && fs::symlink_metadata(executable)
            .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
            .unwrap_or(false)
}

// Human status stays separate so machine output cannot serialize credential material.

fn status_from_cache(
    paths: &AppPaths,
    args: &EgoBrowserStatusArgs,
    server_url: Option<&str>,
    json: bool,
) -> Result<()> {
    let pending = load_pending_revocation(paths)?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let configured_server = server_url.map(str::to_owned).or_else(|| {
        Config::load(paths)
            .ok()
            .and_then(|config| config.server_url)
    });
    let bindings = configured_server
        .as_deref()
        .map(|server| state.list_ego_browser_bindings(server))
        .transpose()?
        .unwrap_or_default();
    if json {
        render_cached_status_json(paths, &bindings, pending.as_ref())?;
        return Ok(());
    }
    if let Some(pending) = pending.as_ref() {
        render_pending_revocation_notice(pending);
    }
    terminal::warning_line(
        "Ego-browser status is stale: the control plane is unavailable; cached state cannot authorize actions.",
    );
    if let Some(reference) = args.binding.as_deref() {
        let id = resolve_id(
            reference,
            "cached ego-browser binding",
            bindings.iter().map(|item| item.id.as_str()),
        )?;
        let binding = bindings
            .iter()
            .find(|item| item.id == id)
            .context("cached ego-browser binding disappeared")?;
        terminal::section("Cached Ego Browser Binding (STALE)");
        Details::new()
            .field("ID", display_id(&binding.id, args.no_trunc))
            .status("Status", &binding.status)
            .field("Binding generation", binding.generation)
            .field(
                "Tool session",
                display_id(&binding.tool_session_id, args.no_trunc),
            )
            .field(
                "Device",
                display_id(&binding.ego_browser_device_id, args.no_trunc),
            )
            .field("Node", display_id(&binding.node_id, args.no_trunc))
            .field(
                "Lease until",
                binding.lease_until.as_deref().unwrap_or("unknown"),
            )
            .render();
    } else if bindings.is_empty() {
        terminal::note("No cached ego-browser binding state is available (unknown).");
    } else {
        terminal::section("Cached Ego Browser Bindings (STALE)");
        let mut table = Table::new(["ID", "SESSION", "DEVICE", "STATUS", "GEN", "LEASE"]);
        for binding in bindings {
            table.row([
                display_id(&binding.id, args.no_trunc),
                display_id(&binding.tool_session_id, args.no_trunc),
                display_id(&binding.ego_browser_device_id, args.no_trunc),
                binding.status,
                binding.generation.to_string(),
                binding.lease_until.unwrap_or_else(|| "unknown".to_owned()),
            ]);
        }
        table.render();
    }
    Ok(())
}

fn render_cached_status_json(
    paths: &AppPaths,
    bindings: &[LocalEgoBrowserBinding],
    pending: Option<&PendingRevocation>,
) -> Result<()> {
    let metadata = load_local_device_metadata(paths)?;
    let local = local_admission_snapshot(paths)?;
    let installed = local_bridge_installation_exists(paths);
    let projection = project_status_state(
        installed,
        false,
        false,
        local_admission_ready_for_identity(&local, metadata.as_ref()),
        pending.is_some(),
        false,
    );
    let binding_items = bindings
        .iter()
        .map(|binding| {
            serde_json::json!({
                "id": short_id(&binding.id),
                "device_id": short_id(&binding.ego_browser_device_id),
                "tool_session_id": short_id(&binding.tool_session_id),
                "node_id": short_id(&binding.node_id),
                "status": binding.status,
                "binding_generation": binding.generation,
                "lease_health": "unknown",
            })
        })
        .collect::<Vec<_>>();
    println!(
        "{}",
        serde_json::json!({
            "error_code": serde_json::Value::Null,
            "state": {
                "installed": projection.installed,
                "enabled": projection.enabled,
                "registered": serde_json::Value::Null,
                "available": projection.available,
                "connected": projection.connected,
            },
            "capability": {
                "configured_enabled": serde_json::Value::Null,
                "effective_enabled": serde_json::Value::Null,
                "node_execution_allowed": false,
            },
            "admission": {
                "enrollment": "unknown_or_denied",
                "server_execution": "unknown_or_denied",
                "binding": "not_established",
                "local": if pending.is_some() { "closed" } else { local.state.as_str() },
                "reason": "server",
            },
            "stale": true,
            "next_action": if pending.is_some() { "retry_revocation" } else { "refresh_status" },
            "next_command": pending.map(pending_revocation_next_command),
            "devices": [],
            "bindings": binding_items,
        })
    );
    Ok(())
}

fn local_device_is_registered(
    metadata: &LocalDeviceMetadata,
    server_url: &str,
    devices: &[EgoBrowserDeviceData],
) -> bool {
    metadata.server_url == server_url
        && devices.iter().any(|device| {
            device.id == metadata.device_id
                && device.status == "active"
                && device_generation(device) == Some(metadata.device_generation)
                && (device.generation == 0 || device.generation == metadata.device_generation)
                && device
                    .device_generation
                    .is_none_or(|generation| generation == metadata.device_generation)
        })
}

fn local_admission_ready_for_identity(
    admission: &LocalAdmissionSnapshot,
    metadata: Option<&LocalDeviceMetadata>,
) -> bool {
    if !matches!(admission.state.as_str(), "ready" | "open") {
        return false;
    }
    let Some(record) = admission.record.as_ref() else {
        // Legacy SQLite is only a readiness hint because it lacks binding references.
        return true;
    };
    match (record.device_id.as_deref(), record.device_generation) {
        (None, None) => record.state == "ready",
        (Some(device_id), Some(device_generation)) => metadata.is_some_and(|metadata| {
            metadata.device_id == device_id && metadata.device_generation == device_generation
        }),
        _ => false,
    }
}

fn local_binding_is_connected(
    admission: &LocalAdmissionSnapshot,
    metadata: Option<&LocalDeviceMetadata>,
    server_url: &str,
    bindings: &[EgoBrowserBindingData],
) -> bool {
    let (Some(record), Some(metadata)) = (admission.record.as_ref(), metadata) else {
        return false;
    };
    if record.state != "open"
        || metadata.server_url != server_url
        || record.device_id.as_deref() != Some(metadata.device_id.as_str())
        || record.device_generation != Some(metadata.device_generation)
    {
        return false;
    }
    let (Some(binding_id), Some(expected_generation)) =
        (record.binding_id.as_deref(), record.binding_generation)
    else {
        return false;
    };
    bindings.iter().any(|binding| {
        binding.id == binding_id
            && binding.ego_browser_device_id == metadata.device_id
            && binding.status == "active"
            && binding.lease_health == "healthy"
            && binding.authorization_mode == "ego_browser_script_full_trust"
            && binding_generation(binding) == expected_generation
            && binding.generation == expected_generation
            && binding
                .binding_generation
                .is_none_or(|generation| generation == expected_generation)
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct StatusProjection {
    installed: bool,
    enabled: bool,
    registered: bool,
    available: bool,
    connected: bool,
}

fn project_status_state(
    installed: bool,
    registered: bool,
    execution: bool,
    local_admission_ready: bool,
    pending_revocation: bool,
    live_binding: bool,
) -> StatusProjection {
    // Availability combines local release state with execution, not enrollment, admission.
    let enabled = installed;
    let available =
        enabled && registered && execution && local_admission_ready && !pending_revocation;
    let connected = available && live_binding;
    StatusProjection {
        installed,
        enabled,
        registered,
        available,
        connected,
    }
}

fn render_pending_revocation_notice(pending: &PendingRevocation) {
    let next_command = pending_revocation_next_command(pending);
    terminal::warning_line(format!(
        "{}",
        pending_revocation_error(pending, next_command)
    ));
}

async fn list(paths: AppPaths, args: ListArgs, json: bool) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let bindings = ApiClient::new(server_url.clone())?
        .list_ego_browser_bindings(&token)
        .await?;
    persist_bindings(&paths, &server_url, &bindings)?;
    if json {
        let items = bindings.iter().map(binding_json_value).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::json!({
                "error_code": serde_json::Value::Null,
                "command": "list",
                "result": "completed",
                "stale": false,
                "bindings": items,
            })
        );
    } else {
        render_bindings(&bindings, args.no_trunc);
    }
    Ok(())
}

async fn requests(paths: AppPaths, args: EgoBrowserRequestsArgs, json: bool) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    persist_bindings(&paths, &server_url, &bindings)?;
    let requests = client
        .list_ego_browser_requests(&token, &binding_id)
        .await?;
    ensure_requests_for_binding(&requests, &binding_id)?;
    if json {
        let items = requests.iter().map(request_json_value).collect::<Vec<_>>();
        println!(
            "{}",
            serde_json::json!({
                "error_code": serde_json::Value::Null,
                "command": "requests",
                "result": "completed",
                "stale": false,
                "binding_id": binding_id,
                "requests": items,
            })
        );
    } else {
        render_requests(&requests, args.no_trunc);
    }
    Ok(())
}

fn binding_json_value(binding: &EgoBrowserBindingData) -> serde_json::Value {
    serde_json::json!({
        "id": binding.id,
        "device_id": binding.ego_browser_device_id,
        "tool_session_id": binding.tool_session_id,
        "node_id": binding.node_id,
        "status": binding.status,
        "binding_generation": binding_generation(binding),
        "lease_health": binding.lease_health,
        "lease_until": binding.lease_until,
    })
}

fn request_json_value(request: &EgoBrowserRequestData) -> serde_json::Value {
    serde_json::json!({
        "id": request.id,
        "request_id": request.request_id,
        "binding_id": request.binding_id,
        "message_type": request.message_type,
        "binding_generation": request_binding_generation(request),
        "sequence": request.sequence,
        "payload_bytes": request.payload_bytes,
        "status": request.status,
        "created_at": request.created_at,
    })
}

async fn cancel_request(paths: AppPaths, args: EgoBrowserCancelRequestArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url)?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.binding)?;
    let requests = client
        .list_ego_browser_requests(&token, &binding_id)
        .await?;
    ensure_requests_for_binding(&requests, &binding_id)?;
    let ledger_id = resolve_id(
        &args.request,
        "ego-browser request",
        requests.iter().map(|request| request.id.as_str()),
    )?;
    let request = requests
        .iter()
        .find(|request| request.id == ledger_id)
        .context("resolved ego-browser request disappeared")?;
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "request_active",
                "unknown",
                "confirm_request_cancellation",
                "agent-remote ego-browser cancel-request BINDING REQUEST --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(&format!(
            "Cancel browser request {}? [y/N] ",
            short_id(&request.id)
        ))? {
            terminal::note("Ego-browser request cancellation cancelled.");
            return Ok(());
        }
    }
    let result = client
        .cancel_ego_browser_request(
            &token,
            &binding_id,
            &request.request_id,
            request_binding_generation(request),
            request.sequence,
        )
        .await?;
    if result.status == "completed" {
        terminal::note(format!(
            "Ego-browser request {} completed before cancellation.",
            short_id(&result.id)
        ));
    } else {
        terminal::success_line(format!(
            "Ego-browser request {} is {}.",
            short_id(&result.id),
            result.status
        ));
    }
    Ok(())
}

async fn claim(paths: AppPaths, args: EgoBrowserClaimArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let tool_session_id = if let Some(canonical_id) = canonical_full_uuid(&args.tool_session) {
        canonical_id
    } else {
        let (server_url, token) = load_control_token(&paths).await?;
        let sessions = ApiClient::new(server_url)?
            .list_sessions(&token, Some("claude"), &[])
            .await?;
        resolve_id(
            &args.tool_session,
            "Claude tool session",
            sessions.iter().map(|session| session.id.as_str()),
        )?
    };
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "candidate_selected",
                "closed",
                "confirm_full_trust",
                "agent-remote ego-browser claim TOOL_SESSION --yes",
                false,
            ));
        }
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no(&format!(
            "Authorize Claude session {} for full-trust control? [y/N] ",
            short_id(&tool_session_id)
        ))? {
            terminal::note("Ego-browser claim cancelled.");
            return Ok(());
        }
    }
    // Keep the old gate closed until claim persists the exact handoff and admission.
    close_local_admission(&paths)?;
    run_device_client_at(
        &paths,
        [
            OsString::from("claim"),
            OsString::from(tool_session_id.clone()),
            OsString::from("--confirm"),
        ],
    )
    .await
    .map_err(|error| map_operational_error(error, "claim"))?;
    terminal::success_line(format!(
        "Ego-browser claim submitted for Claude session {}",
        short_id(&tool_session_id)
    ));
    Ok(())
}

fn canonical_full_uuid(value: &str) -> Option<String> {
    Uuid::parse_str(value).ok().map(|id| id.to_string())
}

async fn resume(paths: AppPaths, args: EgoBrowserLifecycleArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let binding_id;
    let generation;
    {
        let (resolved_id, resolved_generation) =
            resolve_lifecycle_target(&paths, &args, true).await?;
        binding_id = resolved_id;
        generation = resolved_generation;
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "paused",
                "closed",
                "confirm_full_trust",
                "agent-remote ego-browser resume --yes",
                false,
            ));
        }
        terminal::warning_line(FULL_TRUST_WARNING);
        if !super::prompt_yes_no("Reauthorize full-trust control for this binding? [y/N] ")? {
            terminal::note("Ego-browser resume cancelled.");
            return Ok(());
        }
    }
    revalidate_lifecycle_target(&paths, &binding_id, generation, true).await?;
    // Reauthorization marks readiness temporarily and opens only after Server confirmation.
    set_local_admission_state(&paths, "ready")?;
    run_device_client_at(
        &paths,
        [
            OsString::from("resume"),
            OsString::from(binding_id.clone()),
            OsString::from("--binding-generation"),
            OsString::from(generation.to_string()),
            OsString::from("--confirm"),
        ],
    )
    .await
    .map_err(|error| map_operational_error(error, "resume"))?;
    terminal::success_line(format!(
        "Ego-browser binding {} reauthorization submitted",
        short_id(&binding_id)
    ));
    Ok(())
}

async fn lifecycle(paths: AppPaths, action: &str, args: EgoBrowserLifecycleArgs) -> Result<()> {
    reject_pending_revocation(&paths)?;
    let (binding_id, generation) =
        resolve_lifecycle_target(&paths, &args, action == "resume").await?;
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "connected",
                "closed",
                "confirm_lifecycle",
                &format!("agent-remote ego-browser {action} --yes"),
                false,
            ));
        }
        let prompt = match action {
            "pause" => "Pause this binding and invalidate its current generation? [y/N] ",
            "stop" => "Stop this binding and all supervised browser execution? [y/N] ",
            "revoke" => "Permanently revoke this browser binding? [y/N] ",
            _ => bail!("unsupported ego-browser lifecycle action"),
        };
        if !super::prompt_yes_no(prompt)? {
            terminal::note(format!("Ego-browser {action} cancelled."));
            return Ok(());
        }
    }
    if matches!(action, "pause" | "stop" | "revoke") {
        // Close locally before invalidating the generation to block concurrent execution.
        close_local_admission(&paths)?;
    }
    revalidate_lifecycle_target(&paths, &binding_id, generation, false).await?;
    let _output = run_device_client_at(
        &paths,
        [
            OsString::from(action),
            OsString::from(binding_id.clone()),
            OsString::from("--binding-generation"),
            OsString::from(generation.to_string()),
        ],
    )
    .await
    .map_err(|error| map_operational_error(error, action))?;
    if matches!(action, "stop" | "revoke") {
        // Terminal actions close execution but leave the supervisor reusable after invalidation.
        set_local_admission_state(&paths, "ready")?;
    }
    terminal::success_line(format!(
        "Ego-browser binding {} {} (generation {})",
        short_id(&binding_id),
        action,
        generation
    ));
    Ok(())
}

async fn resolve_lifecycle_target(
    paths: &AppPaths,
    args: &EgoBrowserLifecycleArgs,
    resume: bool,
) -> Result<(String, u64)> {
    let operation = if resume { "resume" } else { "lifecycle" };
    let local_handoff = load_local_active_binding_handoff(paths)?;
    let explicit_reference = args
        .binding
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());

    // Prefer the exact handoff because containment remains valid when broad listing is gated.
    if explicit_reference.is_none() {
        if let Some(handoff) = local_handoff.as_ref() {
            let current = refresh_lifecycle_handoff(paths, handoff, resume).await?;
            return resolve_local_handoff_target(&current, args, resume);
        }
    }

    let (server_url, token) = load_control_token(paths).await?;
    let client = ApiClient::new(server_url)?;
    let bindings = client
        .list_ego_browser_bindings(&token)
        .await
        .map_err(|error| map_api_error(error, operation))?;
    let selected_id = if let Some(reference) = explicit_reference {
        resolve_binding_reference(&bindings, reference)?
    } else if let Some(handoff) = local_handoff.as_ref() {
        let binding = bindings.iter().find(|item| item.id == handoff.binding_id);
        let Some(binding) = binding else {
            return Err(lifecycle_error(
                "no_active_binding",
                "handoff_stale",
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            ));
        };
        if binding.ego_browser_device_id != handoff.device_id
            || binding_generation(binding) != handoff.generation
        {
            return Err(lifecycle_error(
                "binding_generation_stale",
                &binding.status,
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            ));
        }
        binding.id.clone()
    } else {
        let eligible: Vec<&EgoBrowserBindingData> = bindings
            .iter()
            .filter(|item| lifecycle_binding_is_eligible(item, resume))
            .collect();
        select_lifecycle_binding(&eligible, resume)?.id.clone()
    };

    let binding = bindings
        .iter()
        .find(|item| item.id == selected_id)
        .context("resolved ego-browser binding disappeared")?;
    if !lifecycle_binding_is_eligible(binding, resume) {
        return Err(lifecycle_error(
            "binding_conflict",
            &binding.status,
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            false,
        ));
    }
    let selected_generation = binding_generation(binding);
    let requested_generation = match (args.binding_generation, args.generation) {
        (Some(explicit), legacy) if legacy != 0 && explicit != legacy => {
            return Err(lifecycle_error(
                "binding_generation_stale",
                &binding.status,
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            ));
        }
        (Some(explicit), _) => explicit,
        (None, legacy) => legacy,
    };
    if requested_generation != 0 && requested_generation != selected_generation {
        return Err(lifecycle_error(
            "binding_generation_stale",
            &binding.status,
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            true,
        ));
    }
    Ok((selected_id, selected_generation))
}

async fn revalidate_lifecycle_target(
    paths: &AppPaths,
    binding_id: &str,
    expected_generation: u64,
    resume: bool,
) -> Result<()> {
    let operation = if resume { "resume" } else { "lifecycle" };
    if let Some(handoff) = load_local_active_binding_handoff(paths)? {
        if handoff.binding_id == binding_id {
            // The exact lifecycle mutation already rejects stale state; do not add a gated read.
            if handoff.generation == expected_generation {
                return Ok(());
            }
        }
    }
    let (server_url, token) = load_control_token(paths).await?;
    let current = ApiClient::new(server_url)?
        .list_ego_browser_bindings(&token)
        .await
        .map_err(|error| map_api_error(error, operation))?
        .into_iter()
        .find(|item| item.id == binding_id)
        .ok_or_else(|| {
            lifecycle_error(
                "no_active_binding",
                "unknown",
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            )
        })?;
    if binding_generation(&current) != expected_generation {
        return Err(lifecycle_error(
            "binding_generation_stale",
            &current.status,
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            true,
        ));
    }
    if let Some(handoff) = load_local_active_binding_handoff(paths)? {
        if handoff.binding_id == binding_id
            && (expected_generation < handoff.generation
                || current.ego_browser_device_id != handoff.device_id
                || handoff.task_space_label != format!("agent-remote:{}", current.tool_session_id))
        {
            return Err(lifecycle_error(
                "binding_generation_stale",
                &current.status,
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            ));
        }
    }
    if !lifecycle_binding_is_eligible(&current, resume) {
        return Err(lifecycle_error(
            "binding_conflict",
            &current.status,
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            false,
        ));
    }
    Ok(())
}

async fn refresh_lifecycle_handoff(
    paths: &AppPaths,
    handoff: &LocalActiveBindingHandoff,
    resume: bool,
) -> Result<LocalActiveBindingHandoff> {
    let output = match run_device_client_at(
        paths,
        [
            OsString::from("status"),
            OsString::from(&handoff.binding_id),
        ],
    )
    .await
    {
        Ok(output) => output,
        // Containment may still use the exact cached generation during a read outage.
        Err(_) => return Ok(handoff.clone()),
    };
    let response: serde_json::Value =
        serde_json::from_str(&output).context("Device Client returned invalid binding status")?;
    let data = response.get("data").context("binding status is missing")?;
    let current: EgoBrowserBindingData = serde_json::from_value(data.clone())
        .context("Device Client returned invalid binding data")?;
    reconciled_lifecycle_handoff(handoff, &current, resume)
}

fn reconciled_lifecycle_handoff(
    handoff: &LocalActiveBindingHandoff,
    current: &EgoBrowserBindingData,
    resume: bool,
) -> Result<LocalActiveBindingHandoff> {
    if current.id != handoff.binding_id
        || current.ego_browser_device_id != handoff.device_id
        || format!("agent-remote:{}", current.tool_session_id) != handoff.task_space_label
        || current.authorization_mode != handoff.authorization_mode
        || binding_generation(current) < handoff.generation
        || !lifecycle_binding_is_eligible(current, resume)
    {
        return Err(lifecycle_error(
            "binding_conflict",
            &current.status,
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            true,
        ));
    }
    let mut current_handoff = handoff.clone();
    current_handoff.generation = binding_generation(current);
    Ok(current_handoff)
}

fn resolve_local_handoff_target(
    handoff: &LocalActiveBindingHandoff,
    args: &EgoBrowserLifecycleArgs,
    _resume: bool,
) -> Result<(String, u64)> {
    let requested_generation = match (args.binding_generation, args.generation) {
        (Some(explicit), legacy) if legacy != 0 && explicit != legacy => {
            return Err(lifecycle_error(
                "binding_generation_stale",
                "handoff_stale",
                "closed",
                "refresh_status",
                "agent-remote ego-browser status",
                true,
            ));
        }
        (Some(explicit), _) => explicit,
        (None, legacy) => legacy,
    };
    if requested_generation != 0 && requested_generation != handoff.generation {
        return Err(lifecycle_error(
            "binding_generation_stale",
            "handoff_stale",
            "closed",
            "refresh_status",
            "agent-remote ego-browser status",
            true,
        ));
    }
    Ok((handoff.binding_id.clone(), handoff.generation))
}

fn lifecycle_binding_is_eligible(binding: &EgoBrowserBindingData, resume: bool) -> bool {
    if resume {
        binding.status == "paused"
    } else {
        matches!(
            binding.status.as_str(),
            "active" | "connecting" | "probing_local_browser" | "paused"
        )
    }
}

fn select_lifecycle_binding<'a>(
    eligible: &[&'a EgoBrowserBindingData],
    resume: bool,
) -> Result<&'a EgoBrowserBindingData> {
    select_lifecycle_binding_with_interactivity(eligible, resume, interactive_terminal())
}

fn select_lifecycle_binding_with_interactivity<'a>(
    eligible: &[&'a EgoBrowserBindingData],
    resume: bool,
    interactive: bool,
) -> Result<&'a EgoBrowserBindingData> {
    match eligible {
        [] => Err(lifecycle_error(
            "no_active_binding",
            "ready",
            "closed",
            "connect",
            "agent-remote ego-browser connect",
            false,
        )),
        [single] => Ok(single),
        _many if !interactive => Err(lifecycle_error(
            "confirmation_required",
            "multiple_bindings",
            "closed",
            "select_binding",
            if resume {
                "agent-remote ego-browser resume BINDING --yes"
            } else {
                "agent-remote ego-browser ACTION BINDING --yes"
            },
            false,
        )),
        many => {
            terminal::section("Ego-browser binding candidates");
            let mut table = Table::new(["#", "ID", "SESSION", "DEVICE", "STATUS", "GEN"]);
            for (index, binding) in many.iter().enumerate() {
                table.row([
                    (index + 1).to_string(),
                    short_id(&binding.id),
                    short_id(&binding.tool_session_id),
                    short_id(&binding.ego_browser_device_id),
                    binding.status.clone(),
                    binding_generation(binding).to_string(),
                ]);
            }
            table.render();
            let mut input = String::new();
            print!("Select a binding number: ");
            std::io::stdout().flush()?;
            std::io::stdin().read_line(&mut input)?;
            let index = parse_lifecycle_binding_selection(&input, many.len())?;
            Ok(many[index])
        }
    }
}

fn parse_lifecycle_binding_selection(input: &str, candidate_count: usize) -> Result<usize> {
    input
        .trim()
        .parse::<usize>()
        .ok()
        .filter(|value| *value >= 1 && *value <= candidate_count)
        .map(|value| value - 1)
        .context("invalid binding selection")
}

async fn delete_device(paths: AppPaths, args: EgoBrowserDeleteArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let devices = client.list_ego_browser_devices(&token, false).await?;
    let device_id = resolve_id(
        &args.id,
        "ego-browser device",
        devices.iter().map(|device| device.id.as_str()),
    )?;
    let device = devices
        .iter()
        .find(|device| device.id == device_id)
        .context("resolved ego-browser device disappeared")?;
    if device.status != "revoked" {
        bail!(
            "ego-browser device {} must be revoked before deletion",
            short_id(&device.id)
        );
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                "revoked",
                "closed",
                "confirm_device_deletion",
                "agent-remote ego-browser delete-device DEVICE --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(&format!(
            "Permanently delete revoked ego-browser device {}? [y/N] ",
            short_id(&device.id)
        ))? {
            terminal::note("Ego-browser device deletion cancelled.");
            return Ok(());
        }
    }
    client
        .delete_ego_browser_device(&token, &device_id)
        .await
        .context("failed to delete ego-browser device")?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_ego_browser_bindings_for_device(&server_url, &device_id)?;
    terminal::success_line(format!(
        "Deleted ego-browser device {}",
        short_id(&device_id)
    ));
    Ok(())
}

async fn delete_binding(paths: AppPaths, args: EgoBrowserDeleteArgs) -> Result<()> {
    let (server_url, token) = load_control_token(&paths).await?;
    let client = ApiClient::new(server_url.clone())?;
    let bindings = client.list_ego_browser_bindings(&token).await?;
    let binding_id = resolve_binding_reference(&bindings, &args.id)?;
    let binding = bindings
        .iter()
        .find(|binding| binding.id == binding_id)
        .context("resolved ego-browser binding disappeared")?;
    if !terminal_statuses().contains(&binding.status.as_str()) {
        bail!(
            "ego-browser binding {} must be stopped or revoked before deletion",
            short_id(&binding.id)
        );
    }
    if !args.yes {
        if !interactive_terminal() {
            return Err(lifecycle_error(
                "confirmation_required",
                &binding.status,
                "closed",
                "confirm_binding_deletion",
                "agent-remote ego-browser delete-binding BINDING --yes",
                false,
            ));
        }
        if !super::prompt_yes_no(&format!(
            "Permanently delete ego-browser binding {}? [y/N] ",
            short_id(&binding.id)
        ))? {
            terminal::note("Ego-browser binding deletion cancelled.");
            return Ok(());
        }
    }
    client
        .delete_ego_browser_binding(&token, &binding_id)
        .await
        .context("failed to delete ego-browser binding")?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    state.delete_ego_browser_binding(&server_url, &binding_id)?;
    terminal::success_line(format!(
        "Deleted ego-browser binding {}",
        short_id(&binding_id)
    ));
    Ok(())
}

fn terminal_statuses() -> &'static [&'static str] {
    &["stopped", "expired", "failed", "revoked"]
}

async fn run_device_client_with_token<const N: usize>(
    args: [OsString; N],
    token: &str,
) -> Result<()> {
    if token.is_empty() {
        bail!("agent-remote credential store returned an empty token")
    }
    let executable = device_client_executable();
    let mut child = ProcessCommand::new(&executable)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| device_client_launch_context(&executable))?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Device Client token pipe")?;
    stdin
        .write_all(token.as_bytes())
        .await
        .context("failed to pass the credential to the Device Client")?;
    drop(stdin);
    let output = child
        .wait_with_output()
        .await
        .context("failed waiting for the Device Client")?;
    finish_device_client(output)
}

fn device_client_launch_context(executable: &OsString) -> String {
    format!(
        "failed to launch independent ego-browser Device Client ({}); install the independent agent-remote-ego-browser Device Client",
        executable.to_string_lossy()
    )
}

fn finish_device_client(output: std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    if let Some(code) = extract_device_client_error_code(&output.stderr, &output.stdout) {
        bail!("independent ego-browser Device Client failed ({code})")
    }
    bail!(
        "independent ego-browser Device Client exited with {}",
        output.status
    )
}

fn extract_device_client_error_code(stderr: &[u8], stdout: &[u8]) -> Option<String> {
    for bytes in [stderr, stdout] {
        let text = String::from_utf8_lossy(bytes);
        for marker in ["error=", "error:", "code="] {
            let mut search_from = 0;
            while search_from < text.len() {
                let Some(relative_start) = text[search_from..].find(marker) else {
                    break;
                };
                let start = search_from + relative_start;
                let value = text[start + marker.len()..]
                    .trim_start()
                    .trim_matches(|character: char| character == '"' || character == '\'');
                let code: String = value
                    .chars()
                    .take_while(|character| {
                        character.is_ascii_alphanumeric() || *character == '_' || *character == '-'
                    })
                    .collect();
                if SAFE_DEVICE_CLIENT_ERROR_CODES.contains(&code.as_str()) {
                    return Some(code);
                }
                search_from = start + marker.len();
            }
        }
    }
    None
}

fn device_client_executable() -> OsString {
    if let Some(executable) =
        std::env::var_os("AGENT_REMOTE_EGO_BROWSER_DEVICE").filter(|value| !value.is_empty())
    {
        return executable;
    }
    if let Some(root) = std::env::var_os("EGO_BROWSER_INSTALL_ROOT") {
        if let Some(candidate) = managed_device_client_at_root(Path::new(&root)) {
            return candidate.into_os_string();
        }
    }
    #[cfg(target_os = "macos")]
    if let Some(home) = crate::platform::user_home_dir() {
        let root = home.join("Library/Application Support/Agent Remote Ego Browser");
        if let Some(candidate) = managed_device_client_at_root(&root) {
            return candidate.into_os_string();
        }
    }
    OsString::from("ego-browser-device")
}

fn managed_device_client_at_root(root: &Path) -> Option<PathBuf> {
    let current = root.join("current/bin/ego-browser-device");
    if fs::symlink_metadata(&current).is_ok_and(|metadata| {
        metadata.is_file()
            && !metadata.file_type().is_symlink()
            && secure_device_client_metadata(&metadata)
    }) {
        return Some(current);
    }

    // Removal retains verified releases and identity for a later managed revoke-and-purge.
    let releases = root.join("releases");
    let release = releases.join(MANAGED_BRIDGE_VERSION);
    let bin = release.join("bin");
    for directory in [root, releases.as_path(), release.as_path(), bin.as_path()] {
        let metadata = fs::symlink_metadata(directory).ok()?;
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || !secure_managed_directory_metadata(&metadata)
        {
            return None;
        }
    }
    let retained = bin.join("ego-browser-device");
    let metadata = fs::symlink_metadata(&retained).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || !secure_installed_executable_metadata(&metadata)
    {
        return None;
    }
    Some(retained)
}

fn secure_device_client_metadata(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() }
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o077 == 0
            && metadata.permissions().mode() & 0o100 != 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_file()
    }
}

fn secure_managed_directory_metadata(metadata: &fs::Metadata) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        metadata.uid() == unsafe { libc::geteuid() } && metadata.permissions().mode() & 0o077 == 0
    }
    #[cfg(not(unix))]
    {
        metadata.is_dir()
    }
}

async fn load_control_token(paths: &AppPaths) -> Result<(String, String)> {
    load_control_token_for_server(paths, None).await
}

async fn load_user_control_token(paths: &AppPaths) -> Result<(String, String)> {
    let config = Config::load(paths)?;
    let server_url = config
        .server_url
        .as_deref()
        .map(crate::normalize_server_url)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            lifecycle_error(
                "server_profile_required",
                "absent",
                "unknown",
                "login",
                "agent-remote login",
                false,
            )
        })?;
    let token = load_user_token(paths, &server_url).await?.ok_or_else(|| {
        lifecycle_error(
            "login_required",
            "absent",
            "unknown",
            "login",
            "agent-remote login",
            false,
        )
    })?;
    Ok((server_url, token))
}

async fn load_control_token_for_server(
    paths: &AppPaths,
    requested_server: Option<&str>,
) -> Result<(String, String)> {
    let config = Config::load(paths)?;
    let configured_server = config
        .server_url
        .clone()
        .context("not logged in: server URL is missing")?;
    let configured_server = crate::normalize_server_url(&configured_server);
    if configured_server.is_empty() {
        bail!("configured agent-remote server URL is empty")
    }
    let server_url = requested_server
        .map(crate::normalize_server_url)
        .unwrap_or_else(|| configured_server.clone());
    if server_url != configured_server {
        bail!(
            "requested server URL does not match the configured agent-remote server ({configured_server})"
        )
    }
    if let Some(token) = load_user_token(paths, &server_url).await? {
        return Ok((server_url, token));
    }
    let (device_server, _device_id, token) = load_device_token(paths).await?;
    if crate::normalize_server_url(&device_server) != server_url {
        bail!("stored agent-remote credential is bound to a different server")
    }
    Ok((server_url, token))
}

fn resolve_binding_reference(
    bindings: &[EgoBrowserBindingData],
    reference: &str,
) -> Result<String> {
    resolve_id(
        reference,
        "ego-browser binding",
        bindings.iter().map(|binding| binding.id.as_str()),
    )
}

fn display_id(value: &str, no_trunc: bool) -> String {
    if no_trunc {
        value.to_string()
    } else {
        short_id(value)
    }
}

fn device_generation(device: &EgoBrowserDeviceData) -> Option<u64> {
    device
        .device_generation
        .or((device.generation > 0).then_some(device.generation))
}

fn binding_generation(binding: &EgoBrowserBindingData) -> u64 {
    binding.binding_generation.unwrap_or(binding.generation)
}

fn request_binding_generation(request: &EgoBrowserRequestData) -> u64 {
    request.binding_generation.unwrap_or(request.generation)
}

fn render_bindings(bindings: &[EgoBrowserBindingData], no_trunc: bool) {
    if bindings.is_empty() {
        terminal::note("No ego-browser bindings found.");
        return;
    }
    let mut table = Table::new(["ID", "SESSION", "DEVICE", "STATUS", "GEN", "LEASE"]);
    for binding in bindings {
        table.row([
            display_id(&binding.id, no_trunc),
            display_id(&binding.tool_session_id, no_trunc),
            display_id(&binding.ego_browser_device_id, no_trunc),
            binding.status.clone(),
            binding_generation(binding).to_string(),
            binding
                .lease_until
                .clone()
                .unwrap_or_else(|| "-".to_string()),
        ]);
    }
    table.render();
}

fn render_requests(requests: &[EgoBrowserRequestData], no_trunc: bool) {
    if requests.is_empty() {
        terminal::note("No active ego-browser requests found.");
        return;
    }
    let mut table = Table::new([
        "ID", "REQUEST", "TYPE", "GEN", "SEQ", "BYTES", "STATUS", "STARTED",
    ]);
    for request in requests {
        table.row([
            display_id(&request.id, no_trunc),
            if no_trunc {
                request.request_id.clone()
            } else {
                short_id(&request.request_id)
            },
            request.message_type.clone(),
            request_binding_generation(request).to_string(),
            request.sequence.to_string(),
            request.payload_bytes.to_string(),
            request.status.clone(),
            request.created_at.clone(),
        ]);
    }
    table.render();
}

fn ensure_requests_for_binding(requests: &[EgoBrowserRequestData], binding_id: &str) -> Result<()> {
    if requests
        .iter()
        .any(|request| request.binding_id != binding_id)
    {
        bail!("control plane returned an ego-browser request for a different binding")
    }
    Ok(())
}

fn print_binding(binding: &EgoBrowserBindingData, no_trunc: bool) {
    terminal::section("Ego Browser Binding");
    Details::new()
        .field("ID", display_id(&binding.id, no_trunc))
        .status("Status", &binding.status)
        .field("Binding generation", binding_generation(binding))
        .field(
            "Tool session",
            display_id(&binding.tool_session_id, no_trunc),
        )
        .field(
            "Device",
            display_id(&binding.ego_browser_device_id, no_trunc),
        )
        .field("Node", display_id(&binding.node_id, no_trunc))
        .field("Relay", &binding.relay_binding_kind)
        .field("Authorization", &binding.authorization_mode)
        .field("Release profile", &binding.release_profile)
        .field("Protocol", &binding.bridge_protocol_version)
        .field(
            "Local runtime",
            binding
                .local_runtime_version
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field(
            "ego lite runtime",
            binding
                .ego_lite_runtime_version
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field(
            "Skill",
            binding.skill_version.as_deref().unwrap_or("unavailable"),
        )
        .field("Allowlist revision", binding.allowlist_revision)
        .field("Lease health", &binding.lease_health)
        .field("Lease until", binding.lease_until.as_deref().unwrap_or("-"))
        .field(
            "Learning bundle",
            binding
                .learning_bundle_digest
                .as_deref()
                .unwrap_or("unavailable"),
        )
        .field("Connected", binding.connected_at.as_deref().unwrap_or("no"))
        .field("Stop reason", binding.stop_reason.as_deref().unwrap_or("-"))
        .render();
    terminal::warning_line(FULL_TRUST_WARNING);
}

fn persist_bindings(
    paths: &AppPaths,
    server_url: &str,
    bindings: &[EgoBrowserBindingData],
) -> Result<()> {
    for binding in bindings {
        persist_binding(paths, server_url, binding)?;
    }
    Ok(())
}

fn persist_binding(
    paths: &AppPaths,
    server_url: &str,
    binding: &EgoBrowserBindingData,
) -> Result<()> {
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    state.upsert_ego_browser_binding(&LocalEgoBrowserBinding {
        id: binding.id.clone(),
        server_url: server_url.to_string(),
        ego_browser_device_id: binding.ego_browser_device_id.clone(),
        tool_session_id: binding.tool_session_id.clone(),
        node_id: binding.node_id.clone(),
        status: binding.status.clone(),
        generation: binding_generation(binding),
        relay_binding_kind: binding.relay_binding_kind.clone(),
        lease_until: binding.lease_until.clone(),
    })
}

#[cfg(test)]
mod tests {
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
        write_pending_revocation, write_trust_confirmation, BridgeInstallerSource,
        BridgeTrustEvidence, LocalActiveBindingHandoff, LocalAdmissionRecord,
        LocalAdmissionSnapshot, LocalDeviceMetadata, LocalTrustConfirmation, PendingRevocation,
        SwitchLocalIdentity, SwitchServerStage,
    };
    #[cfg(unix)]
    use super::{
        managed_device_client_at_root, migrate_legacy_device_store_paths,
        move_store_files_transactionally,
    };
    use crate::api::{EgoBrowserBindingCandidateData, EgoBrowserBindingData, EgoBrowserDeviceData};
    use crate::cli::EgoBrowserForgetArgs;
    use crate::config::{AppPaths, Config};
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
            resolve_local_handoff_target(&handoff, &args, false).unwrap(),
            ("binding-local".to_owned(), 9)
        );
        let stale = crate::cli::EgoBrowserLifecycleArgs {
            binding_generation: Some(8),
            ..args
        };
        assert!(resolve_local_handoff_target(&handoff, &stale, false).is_err());
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
            binding_candidate("session-alpha"),
            binding_candidate("session-alpine"),
        ];

        let non_interactive = format!(
            "{:#}",
            select_candidate_with_interactivity(&candidates, None, false).unwrap_err()
        );
        assert!(non_interactive.contains("error_code=confirmation_required"));
        assert!(non_interactive.contains("next_action=select_session"));

        let ambiguous = format!(
            "{:#}",
            select_candidate_with_interactivity(&candidates, Some("session-al"), true).unwrap_err()
        );
        assert!(ambiguous.contains("error_code=confirmation_required"));
        assert!(ambiguous.contains("next_action=select_session"));
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
            select_lifecycle_binding_with_interactivity(&eligible, false, false).unwrap_err()
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
                super::reconciled_lifecycle_handoff(&handoff, &current, resume).unwrap();
            assert_eq!(refreshed.generation, 4);
            assert_eq!(handoff.generation, 3);
        }
        current.ego_browser_device_id = "different-device".into();
        assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true).is_err());
        current.ego_browser_device_id = handoff.device_id.clone();
        current.tool_session_id = "different-session".into();
        assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true).is_err());
        current.tool_session_id = "session-local".into();
        current.binding_generation = Some(2);
        assert!(super::reconciled_lifecycle_handoff(&handoff, &current, true).is_err());
    }

    #[test]
    fn lifecycle_target_automatically_selects_the_only_eligible_binding() {
        let binding = status_server_binding("binding-only", "device-local", 7, "healthy");
        let eligible = vec![&binding];

        let selected =
            select_lifecycle_binding_with_interactivity(&eligible, false, false).unwrap();
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
        let wrong_generation =
            status_server_binding("binding-local", "device-local", 12, "healthy");
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
}
