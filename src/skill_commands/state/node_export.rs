//! Frozen directory selection uses the original snapshot and current local SSH registration.

use anyhow::{Context, Result};
use std::time::Duration;

use super::Query;
use crate::{
    api::{
        skill_node_export::{self, Binding, Request},
        ApiClient,
    },
    cli::skills::StateExportArgs,
    config::{AppPaths, Config},
    local_state::LocalState,
    skill_commands::remote_result,
};

pub(super) async fn prepare(
    paths: AppPaths,
    client: &ApiClient,
    token: &str,
    args: StateExportArgs,
) -> Result<Query> {
    let snapshot = args.snapshot.context("snapshot missing")?;
    let account = args.account_id.context("account missing")?;
    let known_hosts = paths.ssh_dir().join("known_hosts");
    let request = tokio::task::spawn_blocking(move || {
        let config = Config::load(&paths)?;
        let device_id = config.active_device_id.context(
            "Register this local device with agent-remote login before exporting Node data.",
        )?;
        let state = LocalState::open(&paths)?;
        state.init_schema()?;
        let device = state
            .get_device(&device_id)?
            .context("Local device registration is missing.")?;
        anyhow::ensure!(
            Some(&device.server_url) == config.server_url.as_ref(),
            "Local device belongs to another Server."
        );
        let ssh_key_id = device.ssh_key_id.context(
            "Register the local SSH key with agent-remote login before exporting Node data.",
        )?;
        paths.ensure_base_dirs()?;
        Ok::<_, anyhow::Error>(Request {
            device_id,
            ssh_key_id,
        })
    })
    .await??;
    let authorization = tokio::time::timeout(Duration::from_secs(60), async {
        let mut original: Option<Binding> = None;
        loop {
            let authorization = client.authorize_skill_node_export(token, &snapshot, &request).await?;
            if authorization.binding.account_id != account || original.as_ref().is_some_and(|binding| binding != &authorization.binding) {
                return Err(remote_result::failure("STATE_SCOPE_MISMATCH", "Frozen snapshot does not match the selected original account or identity.", Some(snapshot.clone())));
            }
            original = Some(authorization.binding.clone());
            if authorization.authorization_task_status == "succeeded" {
                break Ok(authorization);
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }).await.map_err(|_| remote_result::failure("STATE_EXPORT_UNAVAILABLE", "Source Node SSH key synchronization did not complete within 60 seconds. Retry when the Node is available.", Some(snapshot)))??;
    let (bundle, result) =
        skill_node_export::download(authorization, known_hosts, args.output).await?;
    Ok(Query::FrozenExport { bundle, result })
}
