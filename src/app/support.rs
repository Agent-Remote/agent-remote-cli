fn default_account_key(tool: &str) -> String {
    format!("default_tool_account:{tool}")
}
fn deps_status(paths: AppPaths, fix: bool) -> Result<()> {
    let manager = DependencyManager::new(paths);
    if fix {
        manager.ensure_manifest()?;
    }
    let mut table = Table::new(["DEPENDENCY", "STATUS", "PATH", "LICENSE"]);
    for dependency in manager.check_all()? {
        table.row([
            dependency.name,
            if dependency.installed {
                "present".to_string()
            } else {
                "missing".to_string()
            },
            dependency.binary_path.display().to_string(),
            dependency.license,
        ]);
    }
    table.render();
    Ok(())
}

pub(crate) fn normalize_server_url(raw: &str) -> String {
    raw.trim().trim_end_matches('/').to_string()
}

pub(crate) fn prompt_line(prompt: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("empty value is not allowed")
    }
    Ok(value)
}

fn prompt_line_default(prompt: &str, default: &str) -> Result<String> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(format!("{prompt} [{default}]: ")));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim();
    if value.is_empty() {
        Ok(default.to_string())
    } else {
        Ok(value.to_string())
    }
}

fn prompt_optional_line(prompt: &str) -> Result<Option<String>> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let value = value.trim().to_string();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value))
    }
}

pub(crate) fn prompt_yes_no(prompt: &str) -> Result<bool> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn prompt_yes_no_default(prompt: &str, default: bool) -> Result<bool> {
    use std::io::{self, Write};

    print!("{}", terminal::prompt(prompt));
    io::stdout().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return Ok(default);
    }
    Ok(matches!(normalized.as_str(), "y" | "yes"))
}

fn init_ssh_public_key(
    explicit: Option<PathBuf>,
    skip_device_registration: bool,
) -> Result<Option<PathBuf>> {
    if skip_device_registration {
        return Ok(explicit);
    }
    if explicit.is_some() {
        return Ok(explicit);
    }
    if let Some(default_path) = platform::default_ssh_public_key_path() {
        terminal::note(format!("Using SSH public key {}", default_path.display()));
        return Ok(Some(default_path));
    }
    let path = prompt_optional_line("SSH public key path: ")?;
    Ok(path.map(PathBuf::from))
}

fn resolve_ssh_public_key(explicit: Option<&std::path::Path>) -> Result<String> {
    let path = match explicit {
        Some(path) => path.to_path_buf(),
        None => platform::default_ssh_public_key_path().context(
            "missing SSH public key; pass --ssh-public-key or use --skip-device-registration",
        )?,
    };
    let value = std::fs::read_to_string(&path)
        .with_context(|| format!("failed to read SSH public key at {}", path.display()))?;
    let value = value.trim().to_string();
    if value.is_empty() {
        bail!("SSH public key at {} is empty", path.display());
    }
    Ok(value)
}

