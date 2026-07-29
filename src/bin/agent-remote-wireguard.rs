use std::env;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use agent_remote_cli::cli::VERSION;
use agent_remote_cli::terminal::{self, ColorChoice, Details};
use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};

#[cfg(windows)]
#[path = "agent-remote-wireguard/windows.rs"]
mod windows_elevation;

#[derive(Debug, Parser)]
#[command(
    name = "agent-remote-wireguard",
    version = VERSION,
    about = "Operate the WireGuard tunnel bundled with agent-remote",
    after_help = "Examples:\n  agent-remote-wireguard check --config ~/.config/agent-remote/wireguard/agent-remote.conf\n  agent-remote-wireguard status\n  agent-remote-wireguard up --config ./agent-remote.conf --dry-run\n  agent-remote-wireguard down --config ./agent-remote.conf"
)]
struct Cli {
    /// Control colored output.
    #[arg(
        long,
        env = "AGENT_REMOTE_COLOR",
        global = true,
        value_enum,
        default_value_t = ColorChoice::Auto
    )]
    color: ColorChoice,

    #[command(subcommand)]
    command: WireGuardCommand,
}

#[derive(Debug, Subcommand)]
enum WireGuardCommand {
    /// Validate a WireGuard configuration and locate the platform tunnel tool.
    Check(ConfigArgs),
    /// Show active interfaces, peers, handshakes, and transfer counters.
    Status,
    /// Bring a WireGuard interface up.
    Up(ActionArgs),
    /// Bring a WireGuard interface down.
    Down(ActionArgs),
}

#[derive(Debug, Args)]
struct ConfigArgs {
    /// WireGuard configuration file.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,
}

#[derive(Debug, Args)]
struct ActionArgs {
    /// WireGuard configuration file.
    #[arg(long, value_name = "PATH")]
    config: PathBuf,

    /// Print the platform tunnel command without changing interface state.
    #[arg(long)]
    dry_run: bool,
}

fn main() {
    let cli = Cli::parse();
    terminal::configure(cli.color);
    if let Err(error) = run(cli.command) {
        eprintln!("{} {error:#}", terminal::failure("ERROR"));
        std::process::exit(1);
    }
}

fn run(command: WireGuardCommand) -> Result<()> {
    if matches!(command, WireGuardCommand::Status) {
        return show_status();
    }
    let (action, config, dry_run) = match command {
        WireGuardCommand::Check(args) => ("check", args.config, false),
        WireGuardCommand::Up(args) => ("up", args.config, args.dry_run),
        WireGuardCommand::Down(args) => ("down", args.config, args.dry_run),
        WireGuardCommand::Status => unreachable!(),
    };
    if !config.exists() {
        bail!("WireGuard config does not exist: {}", config.display());
    }
    #[cfg(windows)]
    if let Some(arguments) = windows_elevation::tunnel_arguments(action, &config, dry_run) {
        if !windows_elevation::is_elevated()? {
            return windows_elevation::relaunch(&arguments);
        }
    }
    match action {
        "check" => {
            terminal::success_line("WireGuard configuration is readable");
            if let Some(path) = find_tunnel_tool() {
                Details::new()
                    .field("Config", config.display())
                    .field("Tunnel tool", path.display())
                    .render();
                Ok(())
            } else {
                bail!("WireGuard tunnel tool is missing; {}", install_hint());
            }
        }
        "up" | "down" => run_tunnel_tool(action, &config, dry_run),
        value => bail!("unknown action {value}"),
    }
}

fn show_status() -> Result<()> {
    let wg = find_wg_tool().context("wg is missing from this release or system installation")?;
    let output = Command::new(&wg)
        .arg("show")
        .output()
        .with_context(|| format!("failed to execute {}", wg.display()))?;

    if !output.status.success() && wg_requires_elevation(&output.stderr) {
        #[cfg(unix)]
        return show_status_elevated(&wg);
        #[cfg(windows)]
        return windows_elevation::relaunch(&["status".into()]);
    }

    present_wg_output(&output)?;
    if !output.status.success() {
        bail!("wg show exited with {}", output.status);
    }
    if output.stdout.is_empty() {
        terminal::note("No active WireGuard interfaces.");
    }
    Ok(())
}

fn present_wg_output(output: &Output) -> Result<()> {
    io::stdout().write_all(&output.stdout)?;
    io::stderr().write_all(&output.stderr)?;
    Ok(())
}

fn wg_requires_elevation(output: &[u8]) -> bool {
    let stderr = String::from_utf8_lossy(output).to_ascii_lowercase();
    stderr.contains("permission denied")
        || stderr.contains("operation not permitted")
        || stderr.contains("access is denied")
}

#[cfg(unix)]
fn show_status_elevated(wg: &Path) -> Result<()> {
    let sudo = find_sudo_tool().context(
        "sudo is required to inspect WireGuard status; install sudo or run from a root shell",
    )?;
    let status = Command::new(&sudo)
        .arg("--")
        .arg(wg)
        .arg("show")
        .status()
        .with_context(|| format!("failed to execute {}", sudo.display()))?;
    if !status.success() {
        bail!("elevated wg show exited with {status}");
    }
    Ok(())
}

#[cfg(windows)]
fn run_tunnel_tool(action: &str, config: &Path, dry_run: bool) -> Result<()> {
    run_wireguard_windows(action, config, dry_run)
}

#[cfg(not(windows))]
fn run_tunnel_tool(action: &str, config: &Path, dry_run: bool) -> Result<()> {
    run_wg_quick(action, config, dry_run)
}

#[cfg(not(windows))]
fn run_wg_quick(action: &str, config: &Path, dry_run: bool) -> Result<()> {
    let wg_quick = if dry_run {
        find_tunnel_tool().unwrap_or_else(|| PathBuf::from("wg-quick"))
    } else {
        find_tunnel_tool().context("wg-quick is missing from this release or PATH")?
    };
    if dry_run {
        terminal::note(format!(
            "Dry run: {}",
            terminal::command(format!(
                "{} {} {}",
                wg_quick.display(),
                action,
                config.display()
            ))
        ));
        return Ok(());
    }
    let managed_bin = env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(|parent| parent.to_path_buf()));
    let mut command = Command::new(wg_quick);
    if let Some(managed_bin) = managed_bin {
        let mut paths = vec![managed_bin];
        paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
        command.env(
            "PATH",
            env::join_paths(paths).context("failed to build managed PATH")?,
        );
    }
    let status = command
        .arg(action)
        .arg(config)
        .status()
        .context("failed to execute wg-quick")?;
    if !status.success() {
        bail!("wg-quick exited with {status}");
    }
    terminal::success_line(format!("WireGuard interface {action} complete"));
    Ok(())
}

#[cfg(windows)]
fn run_wireguard_windows(action: &str, config: &Path, dry_run: bool) -> Result<()> {
    let wireguard = if dry_run {
        find_tunnel_tool().unwrap_or_else(|| PathBuf::from("wireguard.exe"))
    } else {
        find_tunnel_tool().context(
            "wireguard.exe is missing; install WireGuard for Windows from wireguard.com/install",
        )?
    };
    let (argument, value) = if action == "up" {
        ("/installtunnelservice", config.as_os_str().to_owned())
    } else {
        let tunnel_name = config
            .file_stem()
            .context("WireGuard configuration has no tunnel name")?;
        ("/uninstalltunnelservice", tunnel_name.to_owned())
    };
    if dry_run {
        terminal::note(format!(
            "Dry run: {}",
            terminal::command(format!(
                "{} {} {}",
                wireguard.display(),
                argument,
                value.to_string_lossy()
            ))
        ));
        return Ok(());
    }
    let status = Command::new(&wireguard)
        .arg(argument)
        .arg(&value)
        .status()
        .with_context(|| format!("failed to execute {}", wireguard.display()))?;
    if !status.success() {
        bail!("WireGuard for Windows exited with {status}; run from an elevated terminal");
    }
    terminal::success_line(format!("WireGuard interface {action} complete"));
    Ok(())
}

#[cfg(not(windows))]
fn find_tunnel_tool() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_WG_QUICK") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join("wg-quick");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    for candidate in [
        PathBuf::from("/opt/homebrew/bin/wg-quick"),
        PathBuf::from("/usr/local/bin/wg-quick"),
        PathBuf::from("/usr/bin/wg-quick"),
    ] {
        if candidate.exists() {
            return Some(candidate);
        }
    }
    let path_value = env::var_os("PATH")?;
    for dir in env::split_paths(&path_value) {
        let candidate = dir.join("wg-quick");
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(not(windows))]
fn find_wg_tool() -> Option<PathBuf> {
    find_executable(
        "AGENT_REMOTE_WG",
        "wg",
        &["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin"],
    )
}

#[cfg(unix)]
fn find_sudo_tool() -> Option<PathBuf> {
    find_executable("AGENT_REMOTE_SUDO", "sudo", &["/usr/bin", "/bin"])
}

#[cfg(not(windows))]
fn find_executable(env_name: &str, name: &str, fixed_dirs: &[&str]) -> Option<PathBuf> {
    if let Some(path) = env::var_os(env_name) {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    for directory in fixed_dirs {
        let candidate = Path::new(directory).join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    for directory in env::split_paths(&env::var_os("PATH")?) {
        let candidate = directory.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

#[cfg(windows)]
fn find_tunnel_tool() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_WIREGUARD") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Some(path);
        }
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join("wireguard.exe");
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    agent_remote_cli::platform::windows_wireguard_path()
}

#[cfg(windows)]
fn find_wg_tool() -> Option<PathBuf> {
    if let Some(path) = env::var_os("AGENT_REMOTE_WG") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Some(path);
        }
    }
    if let Ok(current_exe) = env::current_exe() {
        if let Some(parent) = current_exe.parent() {
            let candidate = parent.join("wg.exe");
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    agent_remote_cli::platform::windows_wg_path()
}

fn install_hint() -> &'static str {
    if cfg!(target_os = "macos") {
        "reinstall agent-remote to restore the managed WireGuard tools"
    } else if cfg!(windows) {
        "install WireGuard for Windows from https://www.wireguard.com/install/"
    } else {
        "install the wireguard-tools package for this system"
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::env;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    #[cfg(unix)]
    use std::sync::Mutex;

    use clap::{Command, CommandFactory};

    use super::Cli;
    #[cfg(unix)]
    use super::{find_executable, run, wg_requires_elevation, WireGuardCommand};

    #[cfg(unix)]
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn assert_documented(command: &Command, path: &str) {
        assert!(
            command.get_about().is_some() || command.get_long_about().is_some(),
            "{path} is missing command help"
        );
        for argument in command.get_arguments() {
            if matches!(argument.get_id().as_str(), "help" | "version") {
                continue;
            }
            assert!(
                argument.get_help().is_some() || argument.get_long_help().is_some(),
                "{path} argument {} is missing help",
                argument.get_id()
            );
        }
        for child in command.get_subcommands() {
            assert_documented(child, &format!("{path} {}", child.get_name()));
        }
    }

    #[test]
    fn every_wireguard_command_and_argument_has_help() {
        let command = Cli::command();
        command.clone().debug_assert();
        assert_documented(&command, "agent-remote-wireguard");
    }

    #[cfg(unix)]
    #[test]
    fn status_uses_the_configured_wg_and_propagates_failures() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let wg = dir.path().join("wg");
        fs::write(&wg, "#!/bin/sh\n[ \"$1\" = show ]\n").unwrap();
        fs::set_permissions(&wg, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("AGENT_REMOTE_WG", &wg);
        run(WireGuardCommand::Status).unwrap();

        let sudo = dir.path().join("sudo");
        fs::write(
            &wg,
            "#!/bin/sh\nif [ \"$AGENT_REMOTE_TEST_ELEVATED\" = 1 ]; then echo 'interface: elevated'; exit 0; fi\necho 'Unable to access interface: Permission denied' >&2\nexit 1\n",
        )
        .unwrap();
        fs::write(
            &sudo,
            "#!/bin/sh\n[ \"$1\" = -- ] || exit 64\nshift\nAGENT_REMOTE_TEST_ELEVATED=1 exec \"$@\"\n",
        )
        .unwrap();
        fs::set_permissions(&sudo, fs::Permissions::from_mode(0o700)).unwrap();
        env::set_var("AGENT_REMOTE_SUDO", &sudo);
        run(WireGuardCommand::Status).unwrap();

        fs::write(&sudo, "#!/bin/sh\nexit 7\n").unwrap();
        let error = run(WireGuardCommand::Status).unwrap_err().to_string();
        assert!(error.contains("elevated wg show exited"));

        fs::write(&wg, "#!/bin/sh\nexit 9\n").unwrap();
        let error = run(WireGuardCommand::Status).unwrap_err().to_string();
        assert!(error.contains("wg show exited"));
        env::remove_var("AGENT_REMOTE_WG");
        env::remove_var("AGENT_REMOTE_SUDO");
    }

    #[cfg(unix)]
    #[test]
    fn status_recognizes_platform_permission_errors() {
        assert!(wg_requires_elevation(b"Permission denied"));
        assert!(wg_requires_elevation(b"Operation not permitted"));
        assert!(wg_requires_elevation(b"Access is denied."));
        assert!(!wg_requires_elevation(b"Invalid interface"));
    }

    #[cfg(unix)]
    #[test]
    fn executable_lookup_supports_environment_fixed_and_path_locations() {
        let _guard = ENV_LOCK.lock().unwrap();
        let dir = tempfile::tempdir().unwrap();
        let tool = dir.path().join("test-wg");
        fs::write(&tool, "#!/bin/sh\n").unwrap();

        env::set_var("TEST_AGENT_REMOTE_WG", &tool);
        assert_eq!(
            find_executable("TEST_AGENT_REMOTE_WG", "missing", &[]),
            Some(tool.clone())
        );
        env::remove_var("TEST_AGENT_REMOTE_WG");

        assert_eq!(
            find_executable(
                "TEST_AGENT_REMOTE_WG",
                "test-wg",
                &[dir.path().to_str().unwrap()]
            ),
            Some(tool.clone())
        );

        let previous_path = env::var_os("PATH");
        env::set_var("PATH", dir.path());
        assert_eq!(
            find_executable("TEST_AGENT_REMOTE_WG", "test-wg", &[]),
            Some(tool)
        );
        if let Some(path) = previous_path {
            env::set_var("PATH", path);
        } else {
            env::remove_var("PATH");
        }
    }
}
