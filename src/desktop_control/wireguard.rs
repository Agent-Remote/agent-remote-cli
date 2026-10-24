use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::Ordering;
use std::sync::{atomic::AtomicBool, Arc};

use serde::Deserialize;
use serde_json::Value;

use crate::config::AppPaths;
use crate::wireguard::configuration::{self, ConfigPlan};

use super::{Failure, Request};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PlanRequest {
    expected_home: PathBuf,
    output: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyRequest {
    confirmed: bool,
    expected_plan: ConfigPlan,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckRequest {
    expected_home: PathBuf,
    config: Option<PathBuf>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelPlanRequest {
    expected_home: PathBuf,
    action: crate::wireguard::tunnel::Action,
    #[serde(deserialize_with = "required_config")]
    config: Option<PathBuf>,
}

/// A tunnel apply is deliberately a two-phase protocol even while the native
/// privilege bridge is unavailable.  The selection is repeated outside the
/// opaque plan so the handler can reject malformed input before observing the
/// machine.  The plan is compared byte-for-byte (as canonical JSON) with a
/// fresh read-only observation; a stale plan is never silently replaced.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelApplyRequest {
    confirmed: bool,
    expected_home: PathBuf,
    action: crate::wireguard::tunnel::Action,
    #[serde(deserialize_with = "required_config")]
    config: Option<PathBuf>,
    expected_plan: Value,
}

#[derive(serde::Serialize)]
struct TunnelApplyReceipt {
    operation_id: String,
    home: PathBuf,
    action: crate::wireguard::tunnel::Action,
    config: PathBuf,
    state: &'static str,
    target_state: crate::wireguard::target::TargetState,
}

fn required_config<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<PathBuf>, D::Error> {
    Option::<PathBuf>::deserialize(deserializer)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusRequest {
    expected_home: PathBuf,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BridgeStatusRequest {
    expected_home: PathBuf,
}

#[derive(serde::Serialize)]
struct BridgeStatus {
    version: u32,
    home: PathBuf,
    platform: &'static str,
    state: &'static str,
    installation: &'static str,
    approval: &'static str,
    protocol: &'static str,
    authentication: &'static str,
    execution: &'static str,
}

pub(super) async fn execute(request: &Request) -> Result<Value, Failure> {
    let canceled = Arc::new(AtomicBool::new(false));
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .map_err(|_| Failure::new("configuration_unavailable"))?;
        let work = execute_inner(request, canceled.clone());
        tokio::pin!(work);
        tokio::select! {
            biased;
            _ = terminate.recv() => {
                canceled.store(true, Ordering::Release);
                let _ = tokio::time::timeout(std::time::Duration::from_secs(1), &mut work).await;
                Err(Failure::new(if request.method == "wireguard.config.apply" { "wireguard_outcome_unknown" } else { "canceled" }))
            },
            result = &mut work => result,
        }
    }
    #[cfg(not(unix))]
    execute_inner(request, canceled).await
}

async fn execute_inner(request: &Request, canceled: Arc<AtomicBool>) -> Result<Value, Failure> {
    if request.method == "wireguard.tunnel.apply" {
        let input: TunnelApplyRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.confirmed {
            return Err(Failure::new("confirmation_required"));
        }
        validate_tunnel_config(input.config.as_ref())?;
        if !valid_tunnel_plan_shape(&input.expected_plan) {
            return Err(Failure::new("invalid_params"));
        }
        let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
        verify_home(&paths, &input.expected_home)?;
        let fresh_plan = crate::wireguard::tunnel::plan(
            &paths,
            input.action,
            input.config.as_deref(),
            canceled.clone(),
        )
        .await
        .map_err(|error| Failure::new(error.0))?;
        let fresh = serde_json::to_value(&fresh_plan)
            .map_err(|_| Failure::new("configuration_unavailable"))?;
        let expected_config = input.config.clone().unwrap_or_else(|| {
            input
                .expected_home
                .join("wireguard")
                .join("agent-remote.conf")
        });
        let selected = serde_json::json!({
            "home": input.expected_home,
            "action": input.action,
            "config": expected_config,
        });
        if fresh["home"] != selected["home"]
            || fresh["action"] != selected["action"]
            || fresh["config"]["path"] != selected["config"]
            || fresh != input.expected_plan
        {
            return Err(Failure::new("wireguard_plan_stale"));
        }
        let issues = fresh
            .get("issues")
            .and_then(Value::as_array)
            .ok_or_else(|| Failure::new("configuration_unavailable"))?;
        if !issues.is_empty() {
            return Err(Failure::new("wireguard_precondition_failed"));
        }
        let config = input.config.clone().unwrap_or_else(|| {
            input
                .expected_home
                .join("wireguard")
                .join("agent-remote.conf")
        });
        let action = input.action;
        let original_request_id = request.request_id.clone();
        let expected_home = input.expected_home.clone();
        let receipt_config = config.clone();
        let receipt = tokio::task::spawn_blocking(move || {
            crate::wireguard::broker::execute_reviewed(
                &paths,
                &original_request_id,
                &config,
                &fresh_plan,
            )
            .map_err(|error| Failure::new(error.0))
        })
        .await
        .map_err(|_| Failure::new("wireguard_execution_failed"))??;
        return serde_json::to_value(TunnelApplyReceipt {
            operation_id: receipt.operation_id,
            home: expected_home,
            action,
            config: receipt_config,
            state: "observed",
            target_state: receipt.target_state,
        })
        .map_err(|_| Failure::new("wireguard_outcome_unknown"));
    }
    let paths = AppPaths::new(None).map_err(|_| Failure::new("configuration_unavailable"))?;
    if request.method == "wireguard.bridge.status" {
        let input: BridgeStatusRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        verify_home(&paths, &input.expected_home)?;
        // The protected broker is deliberately not inferred from files, user
        // configuration, or process privilege. Until a platform-native broker
        // is installed and authenticated, report a non-executable state.
        let projection = crate::wireguard::broker::status();
        let platform = if cfg!(target_os = "windows") {
            "windows"
        } else if cfg!(target_os = "macos") {
            "macos"
        } else if cfg!(target_os = "linux") {
            "linux"
        } else {
            "unsupported"
        };
        return serde_json::to_value(BridgeStatus {
            version: 1,
            home: input.expected_home,
            platform,
            state: projection.state,
            installation: projection.installation,
            approval: projection.approval,
            protocol: projection.protocol,
            authentication: projection.authentication,
            execution: projection.execution,
        })
        .map_err(|_| Failure::new("configuration_unavailable"));
    }
    if request.method == "wireguard.tunnel.plan" {
        let input: TunnelPlanRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        verify_home(&paths, &input.expected_home)?;
        if input.config.as_ref().is_some_and(|path| {
            !path.is_absolute()
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
                || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
        }) {
            return Err(Failure::new("invalid_params"));
        }
        let result =
            crate::wireguard::tunnel::plan(&paths, input.action, input.config.as_deref(), canceled)
                .await
                .map_err(|error| Failure::new(error.0))?;
        return serde_json::to_value(result).map_err(|_| Failure::new("configuration_unavailable"));
    }
    if request.method == "wireguard.check" {
        let input: CheckRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        verify_home(&paths, &input.expected_home)?;
        if input
            .config
            .as_ref()
            .is_some_and(|path| !path.is_absolute())
        {
            return Err(Failure::new("invalid_params"));
        }
        let result = tokio::task::spawn_blocking(move || {
            crate::wireguard::inspection::check(&paths, input.config.as_deref())
        })
        .await
        .map_err(|_| Failure::new("configuration_unavailable"))?
        .map_err(|error| Failure::new(error.0))?;
        return serde_json::to_value(result).map_err(|_| Failure::new("configuration_unavailable"));
    }
    if request.method == "wireguard.status" {
        let input: StatusRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        verify_home(&paths, &input.expected_home)?;
        let result = crate::wireguard::status::inspect(&paths, canceled)
            .await
            .map_err(|error| Failure::new(error.0))?;
        return serde_json::to_value(result).map_err(|_| Failure::new("configuration_unavailable"));
    }
    if request.method == "wireguard.config.plan" {
        let input: PlanRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.expected_home.is_absolute()
            || input
                .output
                .as_ref()
                .is_some_and(|path| !path.is_absolute())
        {
            return Err(Failure::new("invalid_params"));
        }
        if crate::setup::absolute_home(&paths)
            .map_err(|_| Failure::new("configuration_unavailable"))?
            != input.expected_home
        {
            return Err(Failure::new("configuration_changed"));
        }
        let plan = tokio::task::spawn_blocking(move || {
            configuration::plan(&paths, input.output.as_deref())
        })
        .await
        .map_err(|_| Failure::new("configuration_unavailable"))?
        .map_err(|error| Failure::new(error.0))?;
        serde_json::to_value(plan).map_err(|_| Failure::new("configuration_unavailable"))
    } else {
        let input: ApplyRequest = serde_json::from_value(request.params.clone())
            .map_err(|_| Failure::new("invalid_params"))?;
        if !input.confirmed {
            return Err(Failure::new("confirmation_required"));
        }
        if !input.expected_plan.home.is_absolute()
            || !input.expected_plan.output.path.is_absolute()
            || !input.expected_plan.output.anchor_path.is_absolute()
        {
            return Err(Failure::new("invalid_params"));
        }
        let outcome = configuration::apply_cancellable(&paths, &input.expected_plan, canceled)
            .await
            .map_err(|error| Failure::new(error.0))?;
        let mut value =
            serde_json::to_value(outcome).map_err(|_| Failure::new("wireguard_outcome_unknown"))?;
        value["operation_id"] = Value::String(request.request_id.clone());
        Ok(value)
    }
}

fn validate_tunnel_config(config: Option<&PathBuf>) -> Result<(), Failure> {
    if config.is_some_and(|path| {
        !path.is_absolute()
            || path.components().any(|part| {
                matches!(
                    part,
                    std::path::Component::CurDir | std::path::Component::ParentDir
                )
            })
            || path.components().collect::<PathBuf>().as_os_str() != path.as_os_str()
    }) {
        return Err(Failure::new("invalid_params"));
    }
    Ok(())
}

fn valid_tunnel_plan_shape(value: &Value) -> bool {
    let Some(plan) = value.as_object() else {
        return false;
    };
    if !exact_keys(
        plan,
        &[
            "version", "home", "platform", "action", "config", "binding", "tools", "target",
            "issues",
        ],
    ) {
        return false;
    }
    let Some(config) = plan.get("config").and_then(Value::as_object) else {
        return false;
    };
    if !exact_keys(
        config,
        &[
            "path",
            "state",
            "addresses",
            "dns",
            "mtu",
            "peer_count",
            "unsupported_directives",
        ],
    ) {
        return false;
    }
    if let Some(binding) = plan.get("binding") {
        if let Some(binding) = binding.as_object() {
            if !exact_keys(binding, &["file_identity", "content_sha256", "public_key"]) {
                return false;
            }
        } else if !binding.is_null() {
            return false;
        }
    }
    let Some(tools) = plan.get("tools").and_then(Value::as_array) else {
        return false;
    };
    if tools.len() != 2
        || tools.iter().any(|tool| {
            tool.as_object().is_none_or(|tool| {
                !exact_keys(tool, &["name", "state", "path", "identity", "sha256"])
            })
        })
    {
        return false;
    }
    let Some(target) = plan.get("target").and_then(Value::as_object) else {
        return false;
    };
    if !exact_keys(
        target,
        &[
            "logical_name",
            "state",
            "reason",
            "status_state",
            "identity",
        ],
    ) {
        return false;
    }
    if let Some(identity) = target.get("identity") {
        if !identity.is_null() {
            let Some(identity) = identity.as_object() else {
                return false;
            };
            let Some(kind) = identity.get("kind").and_then(Value::as_str) else {
                return false;
            };
            let keys = match kind {
                "linux_interface" => &["kind", "name", "index", "namespace", "public_key"][..],
                "macos_interface" => &[
                    "kind",
                    "name",
                    "index",
                    "mapping_identity",
                    "socket_identity",
                    "public_key",
                ][..],
                "windows_service" => &[
                    "kind",
                    "service_name",
                    "binary_path",
                    "config_path",
                    "config_identity",
                    "service_state",
                    "start_type",
                    "account",
                    "public_key",
                ][..],
                _ => return false,
            };
            if !exact_keys(identity, keys) {
                return false;
            }
        }
    }
    plan.get("issues")
        .and_then(Value::as_array)
        .is_some_and(|issues| issues.iter().all(Value::is_string))
}

fn exact_keys(value: &serde_json::Map<String, Value>, expected: &[&str]) -> bool {
    value.len() == expected.len() && expected.iter().all(|key| value.contains_key(*key))
}

fn verify_home(paths: &AppPaths, expected: &std::path::Path) -> Result<(), Failure> {
    if !expected.is_absolute() {
        return Err(Failure::new("invalid_params"));
    }
    let actual = crate::setup::absolute_home(paths)
        .map_err(|_| Failure::new("configuration_unavailable"))?;
    if actual != expected {
        return Err(Failure::new("configuration_changed"));
    }
    Ok(())
}
