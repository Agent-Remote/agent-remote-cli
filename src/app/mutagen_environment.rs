#[derive(Debug)]
struct MutagenEnvironmentPrintedFailure;
impl std::fmt::Display for MutagenEnvironmentPrintedFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Mutagen environment operation was not completed")
    }
}
impl std::error::Error for MutagenEnvironmentPrintedFailure {}

fn mutagen_environment_failure(error: &anyhow::Error, json: bool) {
    let code = error
        .downcast_ref::<crate::mutagen_environment::Error>()
        .map(|e| e.code)
        .unwrap_or("sync_mutagen_environment_unavailable");
    if json {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"kind":"mutagen_environment_error","error_code":code,"retryable":false})
        );
    } else {
        eprintln!("{} {code}", terminal::failure("ERROR"));
    }
}

async fn mutagen_environment_command(
    paths: AppPaths,
    args: crate::cli::MutagenEnvironmentArgs,
    json: bool,
) -> Result<()> {
    let home =
        crate::setup::absolute_home(&paths).map_err(|_| crate::mutagen_environment::Error {
            code: "configuration_unavailable",
        })?;
    let home = home.to_str().context("selected home must be UTF-8")?;
    let plan = crate::mutagen_environment::preview(&paths, home).await?;
    if !args.repair {
        if json {
            println!(
                "{}",
                serde_json::json!({"schema_version":1,"kind":"mutagen_environment_preview","plan":plan})
            );
        } else {
            print!("{}", mutagen_environment_review(&plan));
        }
        return Ok(());
    }
    if !plan.repairable {
        return Err(crate::mutagen_environment::Error {
            code: "sync_mutagen_environment_blocked",
        }
        .into());
    }
    if !std::io::stdin().is_terminal() {
        return Err(crate::mutagen_environment::Error {
            code: "interactive_confirmation_required",
        }
        .into());
    }
    // Reviews/prompts go to stderr so JSON stdout always remains one document.
    eprint!("{}", mutagen_environment_review(&plan));
    use std::io::Write;
    eprint!("Restart this entire reviewed Mutagen namespace? [y/N] ");
    std::io::stderr().flush()?;
    let mut confirmation = String::new();
    std::io::stdin().read_line(&mut confirmation)?;
    if !matches!(
        confirmation.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ) {
        return Err(crate::mutagen_environment::Error {
            code: "confirmation_required",
        }
        .into());
    }
    let receipt = tokio::select! {
        result = crate::mutagen_environment::apply(&paths, home, &plan.fingerprint) => result?,
        _ = tokio::signal::ctrl_c() => return Err(crate::mutagen_environment::Error {
            code: "sync_mutagen_environment_outcome_unknown",
        }.into()),
    };
    let completed = receipt.outcome == "completed";
    if json {
        println!(
            "{}",
            serde_json::json!({"schema_version":1,"kind":"mutagen_environment_receipt","home":home,"method":"mutagen.environment.apply","receipt":receipt})
        );
    } else {
        for stage in &receipt.stages {
            Details::new()
                .field("Stage", &stage.name)
                .status("Result", &stage.state)
                .render();
        }
        if completed {
            terminal::success_line("Mutagen environment repaired; original session configuration and pause states verified");
            terminal::note("Inspect the original project sync or recovery again before deciding its next action.");
        } else {
            terminal::warning_line(format!("Mutagen environment operation {} ({}). Inspect the environment before deciding the next action; this operation is not replayed.",receipt.outcome,receipt.error_code.as_deref().unwrap_or("sync_mutagen_environment_unavailable")));
        }
    }
    if completed {
        Ok(())
    } else {
        Err(MutagenEnvironmentPrintedFailure.into())
    }
}

fn mutagen_environment_review(plan: &crate::mutagen::desktop::environment::Plan) -> String {
    use std::fmt::Write;
    let mut out = String::from("Mutagen Environment — Entire Namespace\n");
    let _ = writeln!(
        out,
        "Home: {}\nData directory: {}\nDaemon: {}\nRegistration: {}\nRepairable: {}",
        plan.home, plan.data_directory, plan.daemon_state, plan.registration, plan.repairable
    );
    if let Some(previous) = &plan.previous {
        let _ = writeln!(
            out,
            "Previous home: {}\nPrevious SSH directory: {}",
            previous.home, previous.ssh_directory
        );
    }
    let _ = writeln!(
        out,
        "Selected home: {}\nSelected SSH directory: {}",
        plan.desired.home, plan.desired.ssh_directory
    );
    for tool in &plan.tools {
        let _ = writeln!(
            out,
            "Tool {}: {} ({})",
            tool.name, tool.path, tool.fingerprint
        );
    }
    let _ = writeln!(out, "Affected sessions: {}", plan.sessions.len());
    for session in &plan.sessions {
        let _ = writeln!(
            out,
            "  {} {} | {} | paused={}\n    source: {}\n    destination: {}",
            session.kind,
            session.identifier,
            session.name,
            session.paused,
            mutagen_environment_endpoint(&session.source),
            mutagen_environment_endpoint(&session.destination)
        );
    }
    if let Some(code) = &plan.error_code {
        let _ = writeln!(out, "Blocked: {code}");
    }
    let _ = writeln!(out, "Review fingerprint: {}", plan.fingerprint);
    out.push_str("Repair restarts this entire namespace, including other projects and forwarding sessions. It preserves saved configuration and paused states, but interrupts active connections. It does not replay project operations.\n");
    out
}
fn mutagen_environment_endpoint(
    endpoint: &crate::mutagen::desktop::environment::Endpoint,
) -> String {
    if endpoint.protocol == "local" {
        endpoint.path.clone()
    } else {
        format!(
            "{}://{}@{}:{}/{}",
            endpoint.protocol, endpoint.user, endpoint.host, endpoint.port, endpoint.path
        )
    }
}
