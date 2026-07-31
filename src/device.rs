use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{bail, Context, Result};
use semver::Version;
use sha1::{Digest, Sha1};

use crate::broker_credentials::delete_active_broker_credential;
use crate::platform;
use crate::terminal::{self, Details};

const APP_NAME: &str = "Agent Remote Device.app";
const APP_BUNDLE_IDENTIFIER: &str = "dev.agentremote.device";
const APP_EXECUTABLE: &str = "AgentRemoteDevice";
const NETWORK_BROKER_XPC: &str = "AgentRemoteNetworkBroker.xpc";
const GUI_EXECUTOR_XPC: &str = "AgentRemoteGUIExecutor.xpc";
const NETWORK_BROKER_BUNDLE_IDENTIFIER: &str = "dev.agentremote.device.network-broker";
const GUI_EXECUTOR_BUNDLE_IDENTIFIER: &str = "dev.agentremote.device.gui-executor";
const NETWORK_BROKER_EXECUTABLE: &str = "AgentRemoteNetworkBroker";
const GUI_EXECUTOR_EXECUTABLE: &str = "AgentRemoteGUIExecutor";
const DEVICE_TEAM_IDENTIFIER: Option<&str> = option_env!("AGENT_REMOTE_DEVICE_TEAM_IDENTIFIER");
const DEVICE_SIGNER_CERTIFICATE_SHA1: Option<&str> =
    option_env!("AGENT_REMOTE_DEVICE_SIGNER_CERTIFICATE_SHA1");
const DEVICE_BUNDLE_IDENTIFIERS: [&str; 3] = [
    APP_BUNDLE_IDENTIFIER,
    NETWORK_BROKER_BUNDLE_IDENTIFIER,
    GUI_EXECUTOR_BUNDLE_IDENTIFIER,
];

#[derive(Debug, Clone, PartialEq, Eq)]
struct DeviceAppInspection {
    path: PathBuf,
    version: Option<String>,
    bundle_identifier_valid: bool,
    code_signature_valid: bool,
    signing_identity_valid: bool,
    gatekeeper_required: bool,
    gatekeeper_accepted: bool,
    network_broker_present: bool,
    gui_executor_present: bool,
    running: bool,
}

impl DeviceAppInspection {
    fn valid_for_install(&self) -> bool {
        self.bundle_identifier_valid
            && self.code_signature_valid
            && self.signing_identity_valid
            && (!self.gatekeeper_required || self.gatekeeper_accepted)
            && self.network_broker_present
            && self.gui_executor_present
    }
}

/// Verifies and atomically installs a signed device application bundle.
pub fn install(source: &Path) -> Result<()> {
    ensure_macos()?;
    let expected_identity = expected_signing_identity()?;
    let source = validated_bundle_path(source).context("invalid device app source")?;
    let source_status = inspect(&source, &expected_identity)?;
    if !source_status.valid_for_install() {
        bail!("device app failed signature, Gatekeeper, bundle ID, or XPC validation")
    }

    let destination = default_app_path()?;
    let applications = destination
        .parent()
        .context("device app destination has no parent")?;
    fs::create_dir_all(applications)
        .with_context(|| format!("failed to create {}", applications.display()))?;
    reject_symbolic_link(&destination)?;
    if destination.exists() {
        let installed_status = inspect(&destination, &expected_identity)?;
        ensure_not_downgrade(
            installed_status.version.as_deref(),
            source_status.version.as_deref(),
        )?;
    }

    let process_id = std::process::id();
    let staging = applications.join(format!(".{APP_NAME}.install-{process_id}"));
    let backup = applications.join(format!(".{APP_NAME}.backup-{process_id}"));
    remove_known_temporary_bundle(&staging, applications)?;
    remove_known_temporary_bundle(&backup, applications)?;

    let copied = Command::new("ditto")
        .arg(&source)
        .arg(&staging)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .context("failed to execute ditto")?;
    if !copied.success() {
        remove_known_temporary_bundle(&staging, applications)?;
        bail!("ditto failed while staging the device app")
    }
    let staged_status = inspect(&staging, &expected_identity)?;
    if !staged_status.valid_for_install() {
        remove_known_temporary_bundle(&staging, applications)?;
        bail!("staged device app failed post-copy verification")
    }
    if matches!(
        expected_identity,
        DeviceSigningIdentity::CommunityCertificateSHA1(_)
    ) && !command_success(
        "xattr",
        &[
            OsStr::new("-dr"),
            OsStr::new("com.apple.quarantine"),
            staging.as_os_str(),
        ],
    )? {
        remove_known_temporary_bundle(&staging, applications)?;
        bail!("failed to remove quarantine from the verified community app")
    }

    let had_existing = destination.exists();
    if had_existing {
        fs::rename(&destination, &backup).with_context(|| {
            format!(
                "failed to move existing {} into a local backup",
                destination.display()
            )
        })?;
    }
    if let Err(error) = fs::rename(&staging, &destination) {
        if had_existing {
            if let Err(rollback_error) = fs::rename(&backup, &destination) {
                bail!(
                    "failed to activate the staged device app: {error}; rollback also failed: \
                     {rollback_error}; the previous app remains at {}",
                    backup.display()
                )
            }
        }
        return Err(error).context("failed to activate the staged device app");
    }
    remove_known_temporary_bundle(&backup, applications)?;

    terminal::success_line(format!("Installed {}", destination.display()));
    if let Some(version) = staged_status.version {
        Details::new().field("Version", version).render();
    }
    Ok(())
}

/// Removes the fixed local app and all device-bridge-only local state.
pub fn uninstall() -> Result<()> {
    ensure_macos()?;
    let paths = crate::config::AppPaths::new(None)?;
    let destination = default_app_path()?;
    let home = platform::user_home_dir().context("HOME is not set")?;
    ensure_no_visibility_journal(&home)?;

    match fs::symlink_metadata(&destination) {
        Ok(_) => {
            validate_installed_bundle_for_removal(&destination)?;
            if command_success("pgrep", &[OsStr::new("-x"), OsStr::new(APP_EXECUTABLE)])? {
                bail!("quit Agent Remote Device before uninstalling it")
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("failed to inspect device app destination"),
    }

    delete_active_broker_credential(&paths)
        .context("failed to delete Network Broker credential")?;
    reset_device_permissions()?;
    remove_device_bundle(&destination)?;
    remove_device_state(&home)?;
    terminal::success_line("Removed the local Agent Remote Device installation");
    terminal::note("Remote device registration was not revoked; use `agent-remote device revoke`.");
    Ok(())
}

/// Displays the installed device application's verification and process status.
pub fn status() -> Result<()> {
    ensure_macos()?;
    let expected_identity = expected_signing_identity()?;
    terminal::section("Device App Status");
    let destination = default_app_path()?;
    if !destination.exists() {
        Details::new()
            .field("Path", destination.display())
            .status("Installed", "missing")
            .render();
        return Ok(());
    }
    render_inspection(&inspect(&destination, &expected_identity)?);
    Ok(())
}

/// Runs strict platform, signature, and installation diagnostics.
pub fn diagnose() -> Result<()> {
    ensure_macos()?;
    let expected_identity = expected_signing_identity()?;
    terminal::section("Device App Diagnostics");
    let destination = default_app_path()?;
    if !destination.exists() {
        terminal::failure_line(format!(
            "Device app is missing at {}",
            destination.display()
        ));
        bail!("install a signed app with agent-remote device install --source <APP>")
    }
    let inspection = inspect(&destination, &expected_identity)?;
    render_inspection(&inspection);
    let macos_version = command_stdout("sw_vers", &[OsStr::new("-productVersion")])?;
    Details::new().field("macOS", macos_version).render();
    if !inspection.valid_for_install() {
        bail!("device app diagnostics failed")
    }
    terminal::success_line("Device app installation checks passed");
    Ok(())
}

fn render_inspection(inspection: &DeviceAppInspection) {
    Details::new()
        .field("Path", inspection.path.display())
        .field(
            "Version",
            inspection.version.as_deref().unwrap_or("unknown"),
        )
        .status(
            "Bundle ID",
            if inspection.bundle_identifier_valid {
                "ok"
            } else {
                "invalid"
            },
        )
        .status(
            "Code signature",
            if inspection.code_signature_valid {
                "ok"
            } else {
                "invalid"
            },
        )
        .status(
            "Signing identity",
            if inspection.signing_identity_valid {
                "trusted"
            } else {
                "untrusted"
            },
        )
        .status(
            "Gatekeeper",
            if !inspection.gatekeeper_required {
                "manual trust"
            } else if inspection.gatekeeper_accepted {
                "accepted"
            } else {
                "rejected"
            },
        )
        .status(
            "Network broker XPC",
            if inspection.network_broker_present {
                "present"
            } else {
                "missing"
            },
        )
        .status(
            "GUI executor XPC",
            if inspection.gui_executor_present {
                "present"
            } else {
                "missing"
            },
        )
        .status(
            "Process",
            if inspection.running {
                "running"
            } else {
                "stopped"
            },
        )
        .render();
}

fn inspect(path: &Path, expected_identity: &DeviceSigningIdentity) -> Result<DeviceAppInspection> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("device app path must be a non-symlink directory")
    }
    let info_plist = path.join("Contents/Info.plist");
    let executable = path.join("Contents/MacOS").join(APP_EXECUTABLE);
    if !info_plist.is_file() || !executable.is_file() {
        bail!("device app bundle is incomplete")
    }
    let code_signature_valid = command_success(
        "codesign",
        &[
            OsStr::new("--verify"),
            OsStr::new("--deep"),
            OsStr::new("--strict"),
            path.as_os_str(),
        ],
    )?;
    let signing_identity_valid = expected_identity.matches(path)?;
    let gatekeeper_accepted = command_success(
        "spctl",
        &[
            OsStr::new("--assess"),
            OsStr::new("--type"),
            OsStr::new("execute"),
            path.as_os_str(),
        ],
    )?;
    let bundle_identifier = plist_value(&info_plist, "CFBundleIdentifier").ok();
    let version = plist_value(&info_plist, "CFBundleShortVersionString").ok();
    let xpc_root = path.join("Contents/XPCServices");
    let network_broker_present = inspect_xpc_bundle(
        &xpc_root.join(NETWORK_BROKER_XPC),
        NETWORK_BROKER_BUNDLE_IDENTIFIER,
        NETWORK_BROKER_EXECUTABLE,
        expected_identity,
    )?;
    let gui_executor_present = inspect_xpc_bundle(
        &xpc_root.join(GUI_EXECUTOR_XPC),
        GUI_EXECUTOR_BUNDLE_IDENTIFIER,
        GUI_EXECUTOR_EXECUTABLE,
        expected_identity,
    )?;
    Ok(DeviceAppInspection {
        path: path.to_path_buf(),
        version,
        bundle_identifier_valid: bundle_identifier.as_deref() == Some(APP_BUNDLE_IDENTIFIER),
        code_signature_valid,
        signing_identity_valid,
        gatekeeper_required: matches!(expected_identity, DeviceSigningIdentity::AppleTeam(_)),
        gatekeeper_accepted,
        network_broker_present,
        gui_executor_present,
        running: command_success("pgrep", &[OsStr::new("-x"), OsStr::new(APP_EXECUTABLE)])?,
    })
}

fn inspect_xpc_bundle(
    path: &Path,
    expected_identifier: &str,
    expected_executable: &str,
    expected_identity: &DeviceSigningIdentity,
) -> Result<bool> {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return Ok(false);
    };
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Ok(false);
    }
    let info_plist = path.join("Contents/Info.plist");
    let executable = path.join("Contents/MacOS").join(expected_executable);
    Ok(executable.is_file()
        && plist_value(&info_plist, "CFBundleIdentifier")
            .is_ok_and(|value| value == expected_identifier)
        && plist_value(&info_plist, "CFBundleExecutable")
            .is_ok_and(|value| value == expected_executable)
        && expected_identity.matches(path)?)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum DeviceSigningIdentity {
    AppleTeam(String),
    CommunityCertificateSHA1(String),
}

impl DeviceSigningIdentity {
    fn matches(&self, path: &Path) -> Result<bool> {
        match self {
            Self::AppleTeam(expected) => {
                Ok(codesign_team_identifier(path)?.as_deref() == Some(expected))
            }
            Self::CommunityCertificateSHA1(expected) => {
                Ok(codesign_certificate_sha1(path)?.as_deref() == Some(expected))
            }
        }
    }
}

fn expected_signing_identity() -> Result<DeviceSigningIdentity> {
    match (DEVICE_TEAM_IDENTIFIER, DEVICE_SIGNER_CERTIFICATE_SHA1) {
        (Some(team), None)
            if team.len() == 10
                && team.bytes().all(|character| {
                    character.is_ascii_uppercase() || character.is_ascii_digit()
                }) =>
        {
            Ok(DeviceSigningIdentity::AppleTeam(team.to_string()))
        }
        (None, Some(fingerprint))
            if fingerprint.len() == 40
                && fingerprint.bytes().all(|character| {
                    character.is_ascii_digit() || (b'A'..=b'F').contains(&character)
                }) =>
        {
            Ok(DeviceSigningIdentity::CommunityCertificateSHA1(
                fingerprint.to_string(),
            ))
        }
        _ => bail!("this CLI build does not pin exactly one valid device signing identity"),
    }
}

fn codesign_certificate_sha1(path: &Path) -> Result<Option<String>> {
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_nanos();
    let directory = std::env::temp_dir().join(format!(
        "agent-remote-codesign-certificate-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&directory)
        .with_context(|| format!("failed to create {}", directory.display()))?;
    let result = (|| -> Result<Option<String>> {
        let output = Command::new("codesign")
            .args(["--display", "--extract-certificates"])
            .arg(path)
            .current_dir(&directory)
            .output()
            .context("failed to extract the device signing certificate")?;
        if !output.status.success() {
            return Ok(None);
        }
        let certificate = fs::read(directory.join("codesign0"))
            .context("device signature did not contain a leaf certificate")?;
        Ok(Some(format!("{:X}", Sha1::digest(certificate))))
    })();
    let cleanup = fs::remove_dir_all(&directory)
        .with_context(|| format!("failed to remove {}", directory.display()));
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
    }
}

fn codesign_team_identifier(path: &Path) -> Result<Option<String>> {
    let output = Command::new("codesign")
        .args(["--display", "--verbose=4"])
        .arg(path)
        .output()
        .context("failed to inspect the device app signing identity")?;
    if !output.status.success() {
        return Ok(None);
    }
    if output.stdout.len() + output.stderr.len() > 16 * 1024 {
        bail!("codesign identity output exceeds 16 KiB")
    }
    let mut details = String::from_utf8(output.stdout).context("codesign output is not UTF-8")?;
    details
        .push_str(&String::from_utf8(output.stderr).context("codesign error output is not UTF-8")?);
    Ok(parse_team_identifier(&details))
}

fn parse_team_identifier(details: &str) -> Option<String> {
    let mut identifiers = details
        .lines()
        .filter_map(|line| line.strip_prefix("TeamIdentifier="));
    let identifier = identifiers.next()?;
    if identifiers.next().is_some()
        || identifier.len() != 10
        || !identifier
            .bytes()
            .all(|character| character.is_ascii_uppercase() || character.is_ascii_digit())
    {
        return None;
    }
    Some(identifier.to_string())
}

fn validated_bundle_path(path: &Path) -> Result<PathBuf> {
    if path.file_name().and_then(|value| value.to_str()) != Some(APP_NAME) {
        bail!("source must be named {APP_NAME}")
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        bail!("source must be a non-symlink app bundle")
    }
    path.canonicalize()
        .with_context(|| format!("failed to resolve {}", path.display()))
}

fn default_app_path() -> Result<PathBuf> {
    Ok(platform::user_home_dir()
        .context("HOME is not set")?
        .join("Applications")
        .join(APP_NAME))
}

fn validate_installed_bundle_for_removal(path: &Path) -> Result<()> {
    reject_symbolic_link(path)?;
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {}", path.display()))?;
    if !metadata.is_dir()
        || plist_value(&path.join("Contents/Info.plist"), "CFBundleIdentifier")?
            != APP_BUNDLE_IDENTIFIER
    {
        bail!("refusing to remove a path that is not the fixed device app bundle")
    }
    Ok(())
}

fn reset_device_permissions() -> Result<()> {
    for service in ["Accessibility", "ScreenCapture"] {
        for bundle_identifier in DEVICE_BUNDLE_IDENTIFIERS {
            if !command_success(
                "tccutil",
                &[
                    OsStr::new("reset"),
                    OsStr::new(service),
                    OsStr::new(bundle_identifier),
                ],
            )? {
                bail!("failed to reset {service} permission for {bundle_identifier}")
            }
        }
    }
    Ok(())
}

fn ensure_no_visibility_journal(home: &Path) -> Result<()> {
    let library = home.join("Library");
    let journals = [
        library
            .join("Containers")
            .join(GUI_EXECUTOR_BUNDLE_IDENTIFIER)
            .join("Data/Library/Application Support/Agent Remote Device/hidden-applications.json"),
        library.join("Application Support/Agent Remote Device/hidden-applications.json"),
    ];
    for journal in journals {
        match fs::symlink_metadata(&journal) {
            Ok(_) => bail!(
                "hidden-application recovery state remains at {}; launch the app and end the \
                 session before uninstalling",
                journal.display()
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to inspect recovery state {}", journal.display())
                })
            }
        }
    }
    Ok(())
}

fn remove_device_bundle(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error).context("failed to inspect device app for removal"),
    }
    reject_symbolic_link(path)?;
    fs::remove_dir_all(path)
        .with_context(|| format!("failed to remove device app {}", path.display()))
}

fn remove_device_state(home: &Path) -> Result<()> {
    let library = home.join("Library");
    let mut paths = DEVICE_BUNDLE_IDENTIFIERS
        .into_iter()
        .flat_map(|identifier| {
            [
                library.join("Containers").join(identifier),
                library.join("Caches").join(identifier),
                library
                    .join("Preferences")
                    .join(format!("{identifier}.plist")),
                library
                    .join("Saved Application State")
                    .join(format!("{identifier}.savedState")),
            ]
        })
        .collect::<Vec<_>>();
    paths.push(library.join("Application Support/Agent Remote Device"));
    for path in paths {
        remove_fixed_state_path(&path, &library)?;
    }
    Ok(())
}

fn remove_fixed_state_path(path: &Path, library: &Path) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("failed to inspect {}", path.display()))
        }
    };
    if !path.starts_with(library) || path == library {
        bail!("refusing to remove state outside the user Library directory")
    }
    reject_symbolic_link(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)
    } else if metadata.is_file() {
        fs::remove_file(path)
    } else {
        bail!("refusing to remove an unsupported device state entry")
    }
    .with_context(|| format!("failed to remove device state {}", path.display()))
}

fn ensure_not_downgrade(installed: Option<&str>, candidate: Option<&str>) -> Result<()> {
    let installed = Version::parse(installed.context("installed device app version is missing")?)
        .context("installed device app version is not semantic")?;
    let candidate = Version::parse(candidate.context("candidate device app version is missing")?)
        .context("candidate device app version is not semantic")?;
    if candidate < installed {
        bail!("refusing to downgrade device app from {installed} to {candidate}")
    }
    Ok(())
}

fn reject_symbolic_link(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            bail!("refusing to replace a symbolic-link device app destination")
        }
        Ok(_) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("failed to inspect device app destination"),
    }
}

fn remove_known_temporary_bundle(path: &Path, expected_parent: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    if path.parent() != Some(expected_parent)
        || !path
            .file_name()
            .and_then(|value| value.to_str())
            .is_some_and(|name| name.starts_with(&format!(".{APP_NAME}.")))
    {
        bail!("refusing to remove an unexpected device app path")
    }
    reject_symbolic_link(path)?;
    fs::remove_dir_all(path)
        .with_context(|| format!("failed to remove temporary bundle {}", path.display()))
}

fn plist_value(info_plist: &Path, key: &str) -> Result<String> {
    command_stdout(
        "plutil",
        &[
            OsStr::new("-extract"),
            OsStr::new(key),
            OsStr::new("raw"),
            OsStr::new("-o"),
            OsStr::new("-"),
            info_plist.as_os_str(),
        ],
    )
}

fn command_success(command: &str, args: &[&OsStr]) -> Result<bool> {
    let status: ExitStatus = Command::new(command)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .with_context(|| format!("failed to execute {command}"))?;
    Ok(status.success())
}

fn command_stdout(command: &str, args: &[&OsStr]) -> Result<String> {
    let output = Command::new(command)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {command}"))?;
    if !output.status.success() {
        bail!("{command} failed")
    }
    if output.stdout.len() > 4096 {
        bail!("{command} output exceeds 4 KiB")
    }
    let value = String::from_utf8(output.stdout).context("command output is not UTF-8")?;
    Ok(value.trim().to_string())
}

fn ensure_macos() -> Result<()> {
    if cfg!(target_os = "macos") {
        Ok(())
    } else {
        bail!("local device control is currently supported only on macOS")
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[cfg(unix)]
    use std::os::unix::fs::symlink;

    use tempfile::tempdir;

    use super::{
        ensure_no_visibility_journal, ensure_not_downgrade, parse_team_identifier,
        remove_device_state, remove_fixed_state_path, remove_known_temporary_bundle,
        validated_bundle_path, APP_NAME, GUI_EXECUTOR_BUNDLE_IDENTIFIER,
    };

    #[test]
    fn source_requires_the_fixed_non_symlink_app_name() {
        let directory = tempdir().unwrap();
        let wrong = directory.path().join("Other.app");
        fs::create_dir(&wrong).unwrap();
        assert!(validated_bundle_path(&wrong).is_err());

        let expected = directory.path().join(APP_NAME);
        fs::create_dir(&expected).unwrap();
        assert_eq!(
            validated_bundle_path(&expected).unwrap(),
            expected.canonicalize().unwrap()
        );
    }

    #[test]
    fn cleanup_refuses_paths_outside_the_fixed_staging_namespace() {
        let directory = tempdir().unwrap();
        let unrelated = directory.path().join("unrelated.app");
        fs::create_dir(&unrelated).unwrap();
        assert!(remove_known_temporary_bundle(&unrelated, directory.path()).is_err());
        assert!(unrelated.exists());

        let staging = directory.path().join(format!(".{APP_NAME}.install-1"));
        fs::create_dir(&staging).unwrap();
        remove_known_temporary_bundle(&staging, directory.path()).unwrap();
        assert!(!staging.exists());
    }

    #[test]
    fn installation_rejects_downgrades_and_unparseable_versions() {
        ensure_not_downgrade(Some("1.2.3"), Some("1.2.3")).unwrap();
        ensure_not_downgrade(Some("1.2.3"), Some("1.3.0")).unwrap();
        assert!(ensure_not_downgrade(Some("1.2.3"), Some("1.2.2")).is_err());
        assert!(ensure_not_downgrade(Some("invalid"), Some("1.2.3")).is_err());
        assert!(ensure_not_downgrade(Some("1.2.3"), None).is_err());
    }

    #[test]
    fn signing_team_identifier_parser_requires_one_canonical_identifier() {
        assert_eq!(
            parse_team_identifier("Executable=/tmp/App\nTeamIdentifier=ABC123DEF4\n"),
            Some("ABC123DEF4".to_string())
        );
        assert_eq!(parse_team_identifier("TeamIdentifier=not-valid\n"), None);
        assert_eq!(
            parse_team_identifier("TeamIdentifier=ABC123DEF4\nTeamIdentifier=ABC123DEF4\n"),
            None
        );
        assert_eq!(
            parse_team_identifier("Identifier=dev.agentremote.device\n"),
            None
        );
    }

    #[test]
    fn uninstall_removes_only_fixed_device_state_paths() {
        let directory = tempdir().unwrap();
        let library = directory.path().join("Library");
        let container = library
            .join("Containers")
            .join(GUI_EXECUTOR_BUNDLE_IDENTIFIER);
        fs::create_dir_all(container.join("Data")).unwrap();
        let unrelated = library.join("Containers/com.example.unrelated");
        fs::create_dir_all(&unrelated).unwrap();

        remove_device_state(directory.path()).unwrap();

        assert!(!container.exists());
        assert!(unrelated.exists());
        assert!(remove_fixed_state_path(directory.path(), &library).is_err());
    }

    #[test]
    fn uninstall_refuses_hidden_application_recovery_state() {
        let directory = tempdir().unwrap();
        let journal = directory
            .path()
            .join("Library/Containers")
            .join(GUI_EXECUTOR_BUNDLE_IDENTIFIER)
            .join("Data/Library/Application Support/Agent Remote Device/hidden-applications.json");
        fs::create_dir_all(journal.parent().unwrap()).unwrap();
        fs::write(&journal, b"[]").unwrap();

        assert!(ensure_no_visibility_journal(directory.path()).is_err());
        assert!(journal.exists());
    }

    #[cfg(unix)]
    #[test]
    fn uninstall_refuses_dangling_state_links() {
        let directory = tempdir().unwrap();
        let library = directory.path().join("Library");
        let state = library.join("Caches/dev.agentremote.device");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        symlink(directory.path().join("missing"), &state).unwrap();

        assert!(remove_fixed_state_path(&state, &library).is_err());
        assert!(fs::symlink_metadata(&state).is_ok());
    }
}
