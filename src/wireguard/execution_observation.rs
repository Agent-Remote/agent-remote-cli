//! Validate persisted native facts without interpreting observation as success.

use super::execution_request::digest;
use super::target::{self, TargetIdentity, TargetObservation, TargetReason, TargetState};
use super::validation;

pub(super) fn valid(observation: &TargetObservation) -> bool {
    let queried = match observation.status_state.as_str() {
        "not_queried" => false,
        "observed"
        | "tool_missing"
        | "tool_not_executable"
        | "query_failed"
        | "timed_out"
        | "output_too_large"
        | "invalid_output" => true,
        _ => return false,
    };
    if observation.logical_name.is_empty() {
        return observation.state == TargetState::Unknown
            && observation.reason == Some(TargetReason::InvalidName)
            && !queried
            && observation.identity.is_none();
    }
    if !target::valid_name(&observation.logical_name) {
        return false;
    }
    match observation.state {
        TargetState::Absent => {
            !cfg!(target_os = "macos")
                && observation.reason.is_none()
                && observation.identity.is_none()
                && !queried
        }
        TargetState::Unknown => {
            if observation.identity.is_some() {
                return false;
            }
            match observation.reason {
                Some(TargetReason::TargetChanged) => queried || cfg!(unix),
                Some(TargetReason::NativeQueryFailed) => !queried,
                Some(
                    TargetReason::MappingMissing
                    | TargetReason::MappingUnsafe
                    | TargetReason::MappingStale,
                ) => cfg!(target_os = "macos") && !queried,
                _ => false,
            }
        }
        TargetState::Conflict => {
            observation.identity.is_none()
                && !queried
                && (cfg!(target_os = "linux")
                    && observation.reason == Some(TargetReason::InterfaceNotWireguard)
                    || cfg!(windows) && observation.reason == Some(TargetReason::ServiceInvalid))
        }
        TargetState::Present => {
            let Some(identity) = &observation.identity else {
                return false;
            };
            if !queried || !valid_identity(identity, &observation.logical_name) {
                return false;
            }
            let key = match identity {
                TargetIdentity::LinuxInterface { public_key, .. }
                | TargetIdentity::MacosInterface { public_key, .. }
                | TargetIdentity::WindowsService { public_key, .. } => public_key.as_deref(),
            };
            if observation.status_state == "observed" {
                match observation.reason {
                    None => key.is_none_or(validation::public_key),
                    Some(TargetReason::TargetNotInStatus) => key.is_none(),
                    _ => false,
                }
            } else {
                observation.reason == Some(TargetReason::StatusUnavailable) && key.is_none()
            }
        }
    }
}

fn valid_identity(identity: &TargetIdentity, logical_name: &str) -> bool {
    match identity {
        TargetIdentity::LinuxInterface {
            name,
            index,
            namespace,
            ..
        } => {
            cfg!(target_os = "linux")
                && name == logical_name
                && (1..=i32::MAX as u32).contains(index)
                && digest(namespace)
        }
        TargetIdentity::MacosInterface {
            name,
            index,
            mapping_identity,
            socket_identity,
            ..
        } => {
            cfg!(target_os = "macos")
                && *index != 0
                && digest(mapping_identity)
                && digest(socket_identity)
                && name.strip_prefix("utun").is_some_and(|number| {
                    number
                        .parse::<u32>()
                        .is_ok_and(|number| format!("utun{number}") == *name)
                })
        }
        TargetIdentity::WindowsService {
            service_name,
            binary_path,
            config_path,
            config_identity,
            service_state,
            start_type,
            account,
            ..
        } => {
            cfg!(windows)
                && service_name == &format!("WireGuardTunnel${logical_name}")
                && valid_path(binary_path)
                && valid_path(config_path)
                && binary_path
                    .extension()
                    .and_then(|ext| ext.to_str())
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("exe"))
                && config_identity.as_deref().is_none_or(digest)
                && (1..=7).contains(service_state)
                && *start_type <= 4
                && !account.is_empty()
                && account.len() <= 512
                && !account.chars().any(char::is_control)
        }
    }
}

fn valid_path(path: &std::path::Path) -> bool {
    path.is_absolute()
        && path
            .to_str()
            .is_some_and(|text| text.len() <= 4096 && !text.chars().any(char::is_control))
        && !path.components().any(|component| {
            matches!(
                component,
                std::path::Component::CurDir | std::path::Component::ParentDir
            )
        })
        && path
            .components()
            .collect::<std::path::PathBuf>()
            .as_os_str()
            == path.as_os_str()
}

#[cfg(test)]
#[path = "../../tests/unit/src/wireguard_execution_observation.rs"]
mod tests;
