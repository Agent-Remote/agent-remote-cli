use super::*;

pub(super) fn binding_recovery(
    binding: &EgoBrowserBindingData,
    connected: bool,
) -> Option<(&'static str, String)> {
    let action = match binding.status.as_str() {
        "paused" => "resume",
        "active" if !connected => "pause",
        _ => return None,
    };
    Some((
        action,
        format!("agent-remote ego-browser {action} {}", binding.id),
    ))
}

pub(super) fn status_recovery(
    metadata: Option<&LocalDeviceMetadata>,
    server_url: &str,
    bindings: &[EgoBrowserBindingData],
    connected: bool,
) -> Option<(&'static str, String)> {
    let metadata = metadata.filter(|item| item.server_url == server_url)?;
    if connected {
        return None;
    }
    bindings
        .iter()
        .filter(|binding| binding.ego_browser_device_id == metadata.device_id)
        .find_map(|binding| binding_recovery(binding, false))
}

pub(super) async fn reject_existing_local_binding(paths: &AppPaths) -> Result<()> {
    let Some(handoff) = load_local_active_binding_handoff(paths)? else {
        return Ok(());
    };
    let (server_url, token) = load_control_token(paths).await?;
    let binding = match ApiClient::new(server_url.clone())?
        .get_ego_browser_binding(&token, &handoff.binding_id)
        .await
    {
        Ok(binding) => binding,
        Err(error) if error.status_code() == Some(404) => return Ok(()),
        Err(error) => return Err(map_api_error(error, "status")),
    };
    if binding.id != handoff.binding_id || binding.ego_browser_device_id != handoff.device_id {
        bail!("local binding handoff does not match the registered device")
    }
    if binding.status != "pending_device" && !lifecycle_binding_is_eligible(&binding, false) {
        return Ok(());
    }
    let local = local_admission_snapshot(paths)?;
    let metadata = load_local_device_metadata(paths)?;
    let connected = local_binding_is_connected(
        &local,
        metadata.as_ref(),
        &server_url,
        std::slice::from_ref(&binding),
    );
    let (action, command) = binding_recovery(&binding, connected)
        .unwrap_or_else(|| ("status", "agent-remote ego-browser status".to_owned()));
    // A rejected duplicate claim must not invalidate an unrelated live generation.
    Err(lifecycle_error(
        "binding_conflict",
        &binding.status,
        &local.state,
        action,
        &command,
        false,
    ))
}
