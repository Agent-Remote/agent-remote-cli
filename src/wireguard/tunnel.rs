//! Read-only tunnel planning. No plan is executable until a protected bridge exists.

use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use serde::{Deserialize, Serialize};

use crate::config::AppPaths;

use super::configuration::ConfigError;
use super::inspection::{self, ConfigBinding, ConfigInspection};
use super::target::{self, TargetIdentity, TargetObservation, TargetState};
use super::tool_snapshot::{self, ToolSnapshot};
use super::tools;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Up,
    Down,
}

#[derive(Serialize)]
pub struct TunnelPlan {
    pub version: u32,
    pub home: PathBuf,
    pub platform: &'static str,
    pub action: Action,
    pub config: ConfigInspection,
    pub binding: Option<ConfigBinding>,
    pub tools: Vec<ToolSnapshot>,
    pub target: TargetObservation,
    pub issues: Vec<&'static str>,
}

pub async fn plan(
    paths: &AppPaths,
    action: Action,
    config: Option<&Path>,
    canceled: Arc<AtomicBool>,
) -> Result<TunnelPlan, ConfigError> {
    let home =
        crate::setup::absolute_home(paths).map_err(|_| ConfigError("configuration_unavailable"))?;
    let path = config.map(Path::to_path_buf).unwrap_or_else(|| {
        PathBuf::from(format!("{}/wireguard/agent-remote.conf", home.display()))
    });
    let inventory = tools::inspect(paths);
    let cancel_read = canceled.clone();
    let (config, binding, tools) = tokio::task::spawn_blocking(move || {
        let (config, binding) = inspection::inspect_snapshot(&path)?;
        let tools: Vec<ToolSnapshot> = inventory
            .into_iter()
            .map(|tool| tool_snapshot::snapshot(tool, &cancel_read))
            .collect();
        Ok::<_, ConfigError>((config, binding, tools))
    })
    .await
    .map_err(|_| ConfigError("configuration_unavailable"))??;
    if canceled.load(Ordering::Acquire) {
        return Err(ConfigError("canceled"));
    }
    let logical_name = config
        .path
        .file_stem()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    let target = target::observe(paths, logical_name, canceled.clone()).await?;
    if canceled.load(Ordering::Acquire) {
        return Err(ConfigError("canceled"));
    }
    // A clean target/config observation is still insufficient on its own:
    // execution must cross the platform-native protected broker.  Read the
    // broker projection only after the complete plan inputs have been
    // observed, and keep the plan blocked unless that projection explicitly
    // reports execution=ready.  This is a passive query; it never installs,
    // elevates, or executes a tunnel.
    let bridge_ready = crate::wireguard::broker::status().execution == "ready";
    let issues = issues_for_bridge(
        action,
        &config,
        binding.as_ref(),
        &tools,
        &target,
        bridge_ready,
    );
    Ok(TunnelPlan {
        version: 1,
        home,
        platform: std::env::consts::OS,
        action,
        config,
        binding,
        tools,
        target,
        issues,
    })
}

fn issues(
    action: Action,
    config: &ConfigInspection,
    binding: Option<&ConfigBinding>,
    tools: &[ToolSnapshot],
    target: &TargetObservation,
) -> Vec<&'static str> {
    // Unit tests and callers that do not have a native broker observation use
    // the fail-closed projection.  The production planner calls
    // `issues_for_bridge` with the actual read-only broker status.
    issues_for_bridge(action, config, binding, tools, target, false)
}

fn issues_for_bridge(
    action: Action,
    config: &ConfigInspection,
    binding: Option<&ConfigBinding>,
    tools: &[ToolSnapshot],
    target: &TargetObservation,
    bridge_ready: bool,
) -> Vec<&'static str> {
    let mut issues = Vec::new();
    if !matches!(config.state, "ready" | "unsupported") {
        issues.push("config_not_ready");
    }
    if config.state == "unsupported" {
        issues.push("config_unsupported");
    }
    if tools.iter().any(|tool| tool.state != "available") {
        issues.push("tool_unavailable");
    }
    if tools
        .iter()
        .any(|tool| tool.state == "available" && tool.identity.is_none())
    {
        issues.push("tool_snapshot_unavailable");
    }
    match target.state {
        TargetState::Unknown => issues.push("target_unknown"),
        TargetState::Conflict => issues.push("target_conflict"),
        TargetState::Present if action == Action::Up => issues.push("target_already_present"),
        TargetState::Absent if action == Action::Down => issues.push("target_absent"),
        _ => {}
    }
    if action == Action::Down && target.state == TargetState::Present {
        let key = target
            .identity
            .as_ref()
            .and_then(|identity| match identity {
                TargetIdentity::LinuxInterface { public_key, .. }
                | TargetIdentity::MacosInterface { public_key, .. }
                | TargetIdentity::WindowsService { public_key, .. } => public_key.as_ref(),
            });
        if let (Some(binding), Some(key)) = (binding, key) {
            if key != &binding.public_key {
                issues.push("config_target_mismatch");
            }
        }
        if key.is_none() {
            issues.push("target_key_unobserved");
        }
        if let Some(TargetIdentity::WindowsService {
            config_identity, ..
        }) = &target.identity
        {
            if binding
                .is_none_or(|binding| config_identity.as_ref() != Some(&binding.file_identity))
            {
                issues.push("service_config_mismatch");
            }
        }
    }
    // The read-only plan cannot grant execution. Until a protected,
    // authenticated broker is installed and observed ready, keep this
    // blocking issue explicit so callers cannot mistake a clean observation
    // for permission. A ready projection is necessary but not sufficient:
    // apply still rechecks the complete frozen plan and the broker re-observes
    // the target before touching it.
    if !bridge_ready {
        issues.push("execution_bridge_required");
    }
    issues
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_tunnel.rs"]
mod tests;
