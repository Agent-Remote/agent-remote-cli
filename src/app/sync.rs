async fn sync_review(
    paths: &AppPaths,
    path: Option<&std::path::Path>,
) -> Result<crate::sync_operations::Status> {
    let identity = workspace::identify_workspace(path)?;
    let config = Config::load_strict(paths)?;
    let context = crate::account_defaults::Context {
        home: paths.home().to_path_buf(),
        server_url: config.server_url,
        active_device_id: config.active_device_id,
    };
    crate::sync_operations::status(
        paths,
        context,
        identity
            .local_path
            .to_str()
            .context("workspace path must be UTF-8")?,
    )
    .await
    .map_err(Into::into)
}
async fn sync_ensure(paths: AppPaths, args: crate::cli::SyncEnsureArgs) -> Result<()> {
    let review = match sync_review(&paths, args.workspace.as_deref()).await {
        Ok(review) => review,
        Err(error) if error.downcast_ref::<crate::sync_operations::Error>().is_some_and(|e| e.code == "sync_not_found") => {
            return sync_recover_missing(&paths, args.workspace.as_deref(), args.dry_run).await;
        }
        Err(error) => return Err(error),
    };
    if review.target.workspace_id.is_none() && !args.yes {
        terminal::section("Workspace Setup");
        Details::new()
            .field("Workspace", &review.target.local_path)
            .render();
        terminal::note("A remote synchronization relationship is required for this directory.");
        if !prompt_yes_no("Create workspace sync now? [y/N] ")? {
            bail!("workspace sync not confirmed; remote session will not be started");
        }
    }
    sync_apply_review(&paths, review, "ensure", args.dry_run).await
}
async fn sync_status(paths: AppPaths, args: crate::cli::SyncStatusArgs) -> Result<()> {
    let review = sync_review(&paths, args.workspace.as_deref()).await?;
    if review.target.workspace_id.is_none() {
        terminal::note("Workspace is not registered.");
        return Ok(());
    }
    let Some(sync) = review.sync else {
        terminal::note("Sync session is missing.");
        return Ok(());
    };
    terminal::section("Workspace Sync");
    Details::new()
        .field("Workspace", sync.workspace_id)
        .field("Path", sync.local_path)
        .field("Sync session", sync.id)
        .status("Status", sync.status)
        .status("Conflicts", &sync.conflict_status)
        .status("Mutagen", review.mutagen.state)
        .status("Observed conflicts", review.mutagen.conflicts)
        .render();
    if sync.conflict_status != "none" || review.mutagen.conflicts == "detected" {
        if args.fail_on_conflict {
            bail!("workspace sync has unresolved conflicts");
        }
        terminal::warning_line("Workspace sync has unresolved conflicts");
    } else if args.fail_on_conflict && review.mutagen.conflicts == "unknown" {
        bail!("workspace sync conflict status is unavailable");
    }
    Ok(())
}
async fn sync_action(
    paths: AppPaths,
    action: &str,
    args: crate::cli::SyncActionArgs,
) -> Result<()> {
    let review = sync_review(&paths, args.workspace.as_deref()).await?;
    sync_apply_review(&paths, review, action, args.dry_run).await
}
async fn sync_apply_review(
    paths: &AppPaths,
    review: crate::sync_operations::Status,
    action: &str,
    dry_run: bool,
) -> Result<()> {
    if dry_run {
        terminal::warning_line(
            "Dry run skips local Mutagen changes; Server and local metadata may still change.",
        );
    }
    let receipt = crate::sync_operations::mutate(
        paths,
        review.context,
        review.target,
        &format!("sync.{action}"),
        dry_run,
    )
    .await?;
    if receipt.outcome != "completed" {
        bail!("sync operation {} ({}); inspect agent-remote sync status before deciding whether to retry", receipt.outcome, receipt.error_code.unwrap_or("sync_local_failed"));
    }
    let message = if dry_run {
        "Server sync operation completed; local Mutagen changes skipped"
    } else {
        match action {
            "ensure" => "Workspace synchronization configured",
            "pause" => "Sync paused",
            "resume" => "Sync resumed",
            "resolve" => "Sync flush completed; Server conflict marker cleared",
            "reset" => "Sync reset",
            _ => "Sync operation completed",
        }
    };
    terminal::success_line(message);
    if let Some(sync) = receipt.sync {
        Details::new()
            .field("Workspace", sync.workspace_id)
            .field("Sync session", sync.id)
            .status("Status", sync.status)
            .field("Remote path", sync.remote_path)
            .render();
    }
    if action == "resolve" {
        terminal::note("Flush does not choose winning file versions. Inspect sync status and resolve remaining conflicts manually.");
    }
    Ok(())
}


async fn sync_recover_missing(
    paths: &AppPaths,
    path: Option<&std::path::Path>,
    dry_run: bool,
) -> Result<()> {
    let identity = workspace::identify_workspace(path)?;
    let config = Config::load_strict(paths)?;
    let context = crate::account_defaults::Context {
        home: paths.home().to_path_buf(),
        server_url: config.server_url,
        active_device_id: config.active_device_id,
    };
    let plan = crate::sync_operations::recovery::preview(
        paths,
        context.clone(),
        identity.local_path.to_str().context("workspace path must be UTF-8")?,
    ).await?;
    terminal::section("Obsolete Workspace Sync");
    Details::new()
        .field("Home", paths.home().display().to_string())
        .field("Server", context.server_url.as_deref().unwrap_or_default())
        .field("Device", context.active_device_id.as_deref().unwrap_or_default())
        .field("Path", &plan.target.local_path)
        .field("Workspace", plan.target.workspace_id.as_deref().unwrap_or_default())
        .field("Sync session", plan.target.sync_session_id.as_deref().unwrap_or_default())
        .status("Server observation", &plan.server_state)
        .render();
    if let Some(sync) = &plan.mapping.sync {
        Details::new()
            .field("Old Mutagen name", sync.mutagen_session_id.as_deref().unwrap_or_default())
            .field("Old endpoint", sync.remote_endpoint.as_deref().unwrap_or_default())
            .render();
    }
    terminal::warning_line("Recovery terminates only the reviewed old local Mutagen relationship and removes its exact obsolete metadata. Project files and remote resources are retained.");
    if dry_run {
        bail!("recovery requires local execution; no recovery changes were made");
    }
    if !plan.recoverable {
        bail!("recovery blocked ({}); repair the managed Mutagen environment and inspect again", plan.error_code.as_deref().unwrap_or("sync_mutagen_unavailable"));
    }
    // --yes authorizes ordinary creation. Removing an obsolete relationship has
    // its own review and confirmation, and cannot authorize a replacement target.
    if !prompt_yes_no("Remove this exact obsolete local sync relationship? [y/N] ")? {
        bail!("sync recovery not confirmed; metadata and local session retained");
    }
    let receipt = crate::sync_operations::recovery::apply(paths, context, plan).await?;
    if receipt.outcome != "completed" {
        bail!("sync recovery {} ({}); inspect again before deciding the next action", receipt.outcome, receipt.error_code.unwrap_or("sync_local_failed"));
    }
    terminal::success_line("Obsolete local sync relationship removed");
    terminal::note("Run agent-remote sync ensure again to review and create or reuse a synchronization target.");
    Ok(())
}
