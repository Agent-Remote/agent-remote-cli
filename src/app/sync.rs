async fn sync_ensure(paths: AppPaths, args: crate::cli::SyncEnsureArgs) -> Result<()> {
    let sync =
        ensure_workspace_sync(&paths, args.workspace.as_deref(), args.yes, args.dry_run).await?;
    terminal::success_line("Workspace synchronization ready");
    let mut details = Details::new()
        .field("Workspace", sync.workspace_id)
        .field("Sync session", sync.id)
        .status("Status", sync.status)
        .field("Remote path", sync.remote_path);
    if let Some(endpoint) = sync.remote_endpoint {
        details = details.field("Endpoint", endpoint);
    }
    details.render();
    Ok(())
}

async fn sync_status(paths: AppPaths, args: crate::cli::SyncStatusArgs) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let Some(local_workspace) =
        state.get_workspace_by_project_key(&server_url, &identity.project_key)?
    else {
        terminal::note("Workspace is not registered.");
        Details::new()
            .field("Path", identity.local_path.display())
            .render();
        return Ok(());
    };
    let Some(local_sync) = state.get_sync_session_for_workspace(&local_workspace.id)? else {
        Details::new()
            .field("Workspace", local_workspace.id)
            .status("Sync session", "missing")
            .render();
        return Ok(());
    };
    let client = ApiClient::new(server_url.clone())?;
    let sync = client.get_sync_session(&token, &local_sync.id).await?;
    persist_sync_session(&state, &server_url, &sync)?;
    let mutagen_status = mutagen::status(&paths, &sync)?;
    terminal::section("Workspace Sync");
    Details::new()
        .field("Workspace", local_workspace.id)
        .field("Path", local_workspace.local_path)
        .field("Sync session", sync.id)
        .status("Status", sync.status)
        .status("Conflicts", sync.conflict_status.clone())
        .status(
            "Mutagen",
            if !mutagen_status.installed {
                "missing"
            } else if mutagen_status.session_exists {
                "active"
            } else if mutagen_status.session_missing {
                "session missing"
            } else {
                "unavailable"
            },
        )
        .render();
    if !mutagen_status.output.is_empty() {
        terminal::section("Mutagen");
        println!("{}", mutagen_status.output.trim());
    }
    if sync.conflict_status != "none" || mutagen_status.has_conflicts {
        if args.fail_on_conflict {
            bail!("workspace sync has unresolved conflicts");
        }
        terminal::warning_line("Workspace sync has unresolved conflicts");
    }
    Ok(())
}

async fn sync_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::SyncActionArgs,
) -> Result<()> {
    let (server_url, _device_id, token) = load_device_token(&paths).await?;
    let identity = workspace::identify_workspace(args.workspace.as_deref())?;
    let state = LocalState::open(&paths)?;
    state.init_schema()?;
    let local_workspace = state
        .get_workspace_by_project_key(&server_url, &identity.project_key)?
        .context("workspace is not registered; run agent-remote sync ensure")?;
    let local_sync = state
        .get_sync_session_for_workspace(&local_workspace.id)?
        .context("sync session is missing; run agent-remote sync ensure")?;
    let client = ApiClient::new(server_url.clone())?;
    let current = client.get_sync_session(&token, &local_sync.id).await?;
    match action {
        "pause" => {
            mutagen::pause(&paths, &current, args.dry_run)?;
            let sync = client.pause_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync paused ({})", sync.id));
        }
        "resume" => {
            let sync = client.resume_sync_session(&token, &current.id).await?;
            mutagen::resume(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync resumed ({})", sync.id));
        }
        "resolve" => {
            mutagen::resolve(&paths, &current, args.dry_run)?;
            let sync = client.resolve_sync_session(&token, &current.id).await?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync conflicts resolved ({})", sync.id));
        }
        "reset" => {
            let sync = client.reset_sync_session(&token, &current.id).await?;
            mutagen::reset(&paths, &sync, args.dry_run)?;
            persist_sync_session(&state, &server_url, &sync)?;
            terminal::success_line(format!("Sync reset ({})", sync.id));
        }
        _ => bail!("unsupported sync action: {action}"),
    }
    Ok(())
}

async fn ensure_workspace_sync(
    paths: &AppPaths,
    workspace_path: Option<&std::path::Path>,
    assume_yes: bool,
    dry_run: bool,
) -> Result<SyncSessionData> {
    let (server_url, device_id, token) = load_device_token(paths).await?;
    let identity = workspace::identify_workspace(workspace_path)?;
    let state = LocalState::open(paths)?;
    state.init_schema()?;
    let client = ApiClient::new(server_url.clone())?;

    let local_workspace = state.get_workspace_by_project_key(&server_url, &identity.project_key)?;
    if local_workspace.is_none() && !assume_yes {
        terminal::section("Workspace Setup");
        Details::new()
            .field("Workspace", identity.local_path.display())
            .render();
        terminal::note("A remote synchronization relationship is required for this directory.");
        if !prompt_yes_no("Create workspace sync now? [y/N] ")? {
            bail!("workspace sync not confirmed; remote session will not be started");
        }
    }
    let workspace = client
        .create_workspace(
            &token,
            &CreateWorkspaceRequest {
                device_id: device_id.clone(),
                project_key: identity.project_key.clone(),
                local_start_path: identity.local_path.to_string_lossy().to_string(),
                display_name: identity.display_name.clone(),
                sync_git: true,
                git_sync_policy: GitSyncPolicy::default(),
            },
        )
        .await?;
    if let Some(local) = &local_workspace {
        if local.id != workspace.id {
            if let Some(stale_sync) = state.get_sync_session_for_workspace(&local.id)? {
                if let Some(name) = stale_sync.mutagen_session_id.as_deref() {
                    let _ = mutagen::terminate_session(paths, name, dry_run);
                }
            }
            state.delete_workspace_mapping(&local.id)?;
        }
    }
    persist_workspace(&state, &server_url, &workspace)?;

    let local_sync = state.get_sync_session_for_workspace(&workspace.id)?;
    let mut sync = client
        .create_sync_session(
            &token,
            &CreateSyncSessionRequest {
                workspace_id: workspace.id.clone(),
                node_id: None,
                local_path: Some(identity.local_path.to_string_lossy().to_string()),
                sync_mode: "two_way".to_string(),
                sync_git: true,
                exclude: workspace::DEFAULT_EXCLUDES
                    .iter()
                    .map(|value| (*value).to_string())
                    .collect(),
            },
        )
        .await?;
    if let Some(local) = &local_sync {
        if local.id != sync.id {
            if let Some(name) = local.mutagen_session_id.as_deref() {
                let _ = mutagen::terminate_session(paths, name, dry_run);
            }
            state.delete_sync_session(&local.id)?;
        }
    }
    persist_sync_session(&state, &server_url, &sync)?;
    if sync.status != "active" {
        sync = wait_until_sync_active(&client, &token, sync).await?;
        persist_sync_session(&state, &server_url, &sync)?;
    }
    if sync.status == "active" {
        mutagen::ensure(paths, &sync, dry_run)?;
    }
    Ok(sync)
}

async fn wait_until_sync_active(
    client: &ApiClient,
    token: &str,
    initial: SyncSessionData,
) -> Result<SyncSessionData> {
    if initial.status == "active" {
        return Ok(initial);
    }
    let deadline = Instant::now() + Duration::from_secs(30);
    while Instant::now() < deadline {
        sleep(Duration::from_secs(1)).await;
        let sync = client.get_sync_session(token, &initial.id).await?;
        if sync.status == "active" {
            return Ok(sync);
        }
        if sync.status == "failed" || sync.status == "stopped" {
            bail!("sync session {} became {}", sync.id, sync.status);
        }
    }
    bail!(
        "sync session {} was not prepared within 30 seconds",
        initial.id
    )
}

fn persist_workspace(
    state: &LocalState,
    server_url: &str,
    workspace: &WorkspaceData,
) -> Result<()> {
    state.upsert_workspace(&LocalWorkspace {
        id: workspace.id.clone(),
        server_url: server_url.to_string(),
        project_key: workspace.project_key.clone(),
        local_path: workspace.local_start_path.clone(),
        display_name: workspace.display_name.clone(),
        remote_path: workspace.remote_path.clone(),
    })
}

fn persist_sync_session(
    state: &LocalState,
    server_url: &str,
    sync: &SyncSessionData,
) -> Result<()> {
    state.upsert_sync_session(&LocalSyncSession {
        id: sync.id.clone(),
        server_url: server_url.to_string(),
        workspace_id: sync.workspace_id.clone(),
        node_id: sync.node_id.clone(),
        status: sync.status.clone(),
        conflict_status: sync.conflict_status.clone(),
        mutagen_session_id: sync.mutagen_session_id.clone(),
        remote_endpoint: sync.remote_endpoint.clone(),
    })
}

