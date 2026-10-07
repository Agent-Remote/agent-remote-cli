fn device_uninstall(args: DeviceUninstallArgs) -> Result<()> {
    if !args.yes
        && !prompt_yes_no(
            "Remove the local Agent Remote Device app, credentials, permissions, and data? [y/N] ",
        )?
    {
        terminal::note("Device app removal cancelled.");
        return Ok(());
    }
    device::uninstall()
}

async fn device_revoke(paths: AppPaths, args: DeviceRevokeArgs) -> Result<()> {
    let mut config = Config::load(&paths)?;
    let server_url = config
        .server_url
        .clone()
        .context("server URL is not configured")?;
    let device_id = args
        .device
        .or_else(|| config.active_device_id.clone())
        .context("no device selected; pass --device or register an active device")?;
    let secret_store = SecretStore::new(paths.clone());
    let user_token = auth::load_user_token(&paths, &server_url).await?.context(
        "a user token is required; run agent-remote login --skip-device-registration first",
    )?;
    if !args.yes
        && !prompt_yes_no(&format!(
            "Revoke device {device_id} and invalidate its remote access? [y/N] "
        ))?
    {
        terminal::note("Device revocation cancelled.");
        return Ok(());
    }

    ApiClient::new(server_url.clone())?
        .revoke_device(&user_token, &device_id)
        .await
        .context("failed to revoke device")?;

    let mut cleanup_errors = Vec::new();
    if let Err(error) = delete_broker_credential_if_matches(&paths, &server_url, &device_id) {
        cleanup_errors.push(format!("Network Broker credential: {error}"));
    }
    if let Err(error) = secret_store.delete_secret(&device_token_key(&server_url, &device_id)) {
        cleanup_errors.push(format!("device credential: {error}"));
    }
    if let Err(error) = clear_device_token_refresh(&paths, &server_url, &device_id) {
        cleanup_errors.push(format!("device refresh state: {error}"));
    }
    if config.active_device_id.as_deref() == Some(device_id.as_str()) {
        config.active_device_id = None;
        if let Err(error) = config.save(&paths) {
            cleanup_errors.push(format!("active device configuration: {error}"));
        }
    }
    match LocalState::open(&paths).and_then(|state| {
        state.init_schema()?;
        if let Some(mut device) = state.get_device(&device_id)? {
            device.status = "revoked".to_string();
            state.upsert_device(&device)?;
        }
        Ok(())
    }) {
        Ok(()) => {}
        Err(error) => cleanup_errors.push(format!("local device metadata: {error}")),
    }

    if !cleanup_errors.is_empty() {
        bail!(
            "device {device_id} was revoked remotely, but local cleanup is incomplete: {}",
            cleanup_errors.join("; ")
        )
    }
    terminal::success_line(format!("Revoked device {device_id}"));
    Ok(())
}

async fn device_rotate_token(paths: AppPaths, args: DeviceRotateTokenArgs) -> Result<()> {
    let config = Config::load(&paths)?;
    let server_url = config.server_url.context("server URL is not configured")?;
    let device_id = config
        .active_device_id
        .context("no active device is configured")?;
    let user_token = auth::load_user_token(&paths, &server_url).await?.context(
        "a user token is required; run agent-remote login --skip-device-registration first",
    )?;
    if !args.yes
        && !prompt_yes_no(
            "Rotate the active device token and replace its local credential? [y/N] ",
        )?
    {
        terminal::note("Device token rotation cancelled.");
        return Ok(());
    }

    let rotated = ApiClient::new(server_url.clone())?
        .rotate_device_token(&user_token, &device_id)
        .await
        .context("failed to rotate device token")?;
    if let Err(error) = store_device_token(&paths, &server_url, &device_id, &rotated) {
        bail!(
            "device token was rotated remotely, but local credential replacement is incomplete: \
             {error:#}"
        )
    }
    terminal::success_line(format!("Rotated credential for device {device_id}"));
    Ok(())
}

/// Issues a secret-free Node join flow and re-resolves the target before delivery.
async fn node_install(paths: AppPaths, args: NodeInstallArgs) -> Result<()> {
    let config = Config::load(&paths)?;
    let server_url = config
        .server_url
        .clone()
        .context("server URL is not configured; run agent-remote login first")?;
    if !valid_node_install_server_url(&server_url) {
        bail!("configured server URL is not a canonical HTTP(S) origin; run login again")
    }
    let token = auth::load_user_token(&paths, &server_url)
        .await?
        .context("a logged-in user credential is required; run agent-remote login first")?;
    let client = ApiClient::new(server_url.clone())?;
    let listed = client
        .list_nodes(&token)
        .await
        .context("failed to list managed Nodes")?;
    let node_id = resolve_id(
        &args.node,
        "managed Node",
        listed.iter().map(|node| node.id.as_str()),
    )?;
    if !uuid::Uuid::parse_str(&node_id).is_ok_and(|value| value.to_string() == node_id) {
        bail!("control plane returned a non-canonical Node ID")
    }
    let selected = listed
        .iter()
        .find(|node| node.id == node_id)
        .context("selected Node disappeared")?;
    let refreshed = client
        .list_nodes(&token)
        .await
        .context("failed to refresh managed Node list")?;
    let current = refreshed
        .iter()
        .find(|node| node.id == node_id)
        .filter(|node| node_fingerprint(node) == node_fingerprint(selected))
        .context("selected Node state is stale; refresh and retry")?;
    if !current.enrollment_admission {
        bail!("selected Node enrollment admission is closed")
    }
    let host = current
        .ssh_host
        .as_deref()
        .filter(|value| !value.is_empty())
        .context("selected Node has no managed SSH host")?;
    if !valid_managed_ssh_host(host) {
        bail!("selected Node has an invalid managed SSH host")
    }
    let user = current
        .ssh_user
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("agent-remote");
    if !valid_managed_ssh_user(user) {
        bail!("selected Node has an invalid managed SSH user")
    }
    let port = current.ssh_port.unwrap_or(22);
    if port == 0 {
        bail!("selected Node has an invalid managed SSH port")
    }
    if !args.yes {
        if !std::io::stdin().is_terminal() || !std::io::stdout().is_terminal() {
            bail!("error_code=confirmation_required next_action=select_node")
        }
        let intent = if args.enable_ego_browser {
            " and explicitly enable the verified ego-browser capability"
        } else {
            ""
        };
        if !prompt_yes_no(&format!(
            "Install signed Node release {} and enroll {} over SSH{}? [y/N] ",
            MANAGED_NODE_VERSION, current.name, intent
        ))? {
            terminal::note("Node installation cancelled.");
            return Ok(());
        }
    }
    let ssh = std::env::var_os("AGENT_REMOTE_NODE_SSH").unwrap_or_else(|| "ssh".into());
    let release_target = detect_remote_node_release_target(&ssh, user, host, port).await?;
    let fingerprint = node_install_fingerprint(current);
    let created_at_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before the Unix epoch")?
        .as_secs();
    let pending = node_install_state::load(&paths)?;
    let resuming_release_installed = pending
        .as_ref()
        .is_some_and(|state| state.stage == NodeInstallStage::ReleaseInstalled);
    let mut exchange = match pending {
        Some(state) => {
            if !state.matches(
                &server_url,
                &node_id,
                &fingerprint,
                args.enable_ego_browser,
                MANAGED_NODE_VERSION,
                &release_target,
            ) {
                bail!(
                    "error_code=exchange_conflict state=exchange_pending \
                     next_action=finish_or_revoke_pending_node_install"
                )
            }
            state
        }
        None => {
            let state = NodeInstallExchangeState::prepared(
                server_url.clone(),
                node_id.clone(),
                fingerprint,
                args.enable_ego_browser,
                MANAGED_NODE_VERSION.to_owned(),
                release_target.clone(),
                created_at_unix,
            )?;
            node_install_state::save(&paths, &state)?;
            state
        }
    };

    if exchange.stage == NodeInstallStage::Prepared {
        let release = node_release::obtain(&release_target)
            .await
            .context("error_code=release_verification_failed state=release_pending")?;
        if !remote_node_release_is_staged(
            &ssh,
            user,
            host,
            port,
            MANAGED_NODE_VERSION,
            &release_target,
            Some(release.sha256()),
        )
        .await?
        {
            transfer_node_release(&ssh, user, host, port, &release)
                .await
                .context(
                    "error_code=transport_unavailable state=release_pending \
                     next_action=retry_same_command",
                )?;
        }
        // A staging marker proves arrival only; installation must finish before code issue.
        install_staged_node_release(&ssh, user, host, port, &release)
            .await
            .context(
                "error_code=transport_unavailable state=release_pending \
                 next_action=retry_same_command",
            )?;
        exchange.mark_release_installed(release.sha256().to_owned())?;
        node_install_state::save(&paths, &exchange)?;
    }

    // After a lost issue response, revoke the unconsumed exchange before rotating its ID.
    if exchange.stage == NodeInstallStage::ReleaseInstalled && resuming_release_installed {
        let revocation = client
            .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
            .await
            .context("failed to revoke an incomplete Node join-code issuance")?;
        if revocation == NodeJoinCodeRevokeState::Consumed {
            bail!("error_code=unknown_result state=exchange_pending next_action=retry_same_command")
        }
        let release_sha256 = exchange
            .release_sha256
            .clone()
            .context("release-installed exchange has no artifact digest")?;
        node_install_state::clear(&paths)?;
        exchange = NodeInstallExchangeState::prepared(
            server_url.clone(),
            node_id.clone(),
            node_install_fingerprint(current),
            args.enable_ego_browser,
            MANAGED_NODE_VERSION.to_owned(),
            release_target.clone(),
            created_at_unix,
        )?;
        exchange.mark_release_installed(release_sha256)?;
        node_install_state::save(&paths, &exchange)?;
    }

    let requested_intent = args.enable_ego_browser.then_some(true);
    let mut join_code = None;
    if exchange.stage == NodeInstallStage::ReleaseInstalled {
        let join = client
            .issue_node_join_code(&token, &node_id, requested_intent, &exchange.exchange_id)
            .await
            .context("failed to issue Node join code")?;
        if join.node_id != node_id
            || !valid_join_code(join.code.trim())
            || !valid_join_code_expiry(join.expires_at.trim())
            || join.ego_browser_enabled != requested_intent
        {
            if client
                .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
                .await
                .is_ok_and(|state| state != NodeJoinCodeRevokeState::Consumed)
            {
                node_install_state::clear(&paths)?;
            }
            bail!("control plane returned an invalid Node join code")
        }
        exchange.mark_issued(join.expires_at.trim().to_owned())?;
        node_install_state::save(&paths, &exchange)?;
        join_code = Some(join.code.trim().to_owned());
    }
    let remote_command = node_enrollment_command(
        &exchange.exchange_id,
        &server_url,
        &node_id,
        join_code.is_some(),
        args.enable_ego_browser,
    );
    let mut command = AsyncCommand::new(ssh);
    command
        .arg("-T")
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{user}@{host}"))
        .arg(remote_command)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    if join_code.is_some() {
        command.stdin(std::process::Stdio::piped());
    } else {
        command.stdin(std::process::Stdio::null());
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => {
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await)
        }
    };
    if let Some(join_code) = join_code {
        let mut stdin = match child.stdin.take() {
            Some(stdin) => stdin,
            None => {
                let _ = child.kill().await;
                let _ = child.wait().await;
                return Err(node_install_transport_failure(
                    &client, &token, &node_id, &exchange, &paths,
                )
                .await);
            }
        };
        if stdin.write_all(join_code.as_bytes()).await.is_err()
            || stdin.write_all(b"\n").await.is_err()
        {
            drop(stdin);
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await);
        }
        drop(stdin);
    }
    let output = match child.wait_with_output().await {
        Ok(output) => output,
        Err(_) => {
            return Err(node_install_transport_failure(
                &client, &token, &node_id, &exchange, &paths,
            )
            .await)
        }
    };
    if !output.status.success() {
        return Err(
            node_install_transport_failure(&client, &token, &node_id, &exchange, &paths).await,
        );
    }
    client
        .revoke_node_join_code(&token, &node_id, &exchange.exchange_id)
        .await
        .context(
            "Node enrolled, but join-code cleanup is pending; retry the same Node install command",
        )?;
    node_install_state::clear(&paths)?;
    cleanup_staged_node_release(
        std::env::var_os("AGENT_REMOTE_NODE_SSH").unwrap_or_else(|| "ssh".into()),
        user,
        host,
        port,
        MANAGED_NODE_VERSION,
        &release_target,
        exchange.release_sha256.as_deref(),
    )
    .await;
    terminal::success_line(format!(
        "Node {} enrolled; ego-browser intent remains {}.",
        current.name,
        if args.enable_ego_browser {
            "enabled"
        } else {
            "unchanged"
        }
    ));
    Ok(())
}

fn node_ssh_command(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    remote_command: &str,
) -> AsyncCommand {
    let mut command = AsyncCommand::new(ssh);
    command
        .arg("-T")
        .arg("-p")
        .arg(port.to_string())
        .arg("--")
        .arg(format!("{user}@{host}"))
        .arg(remote_command);
    command
}

async fn detect_remote_node_release_target(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
) -> Result<String> {
    let probe = r#"set -eu
test "$(uname -s)" = Linux
case "$(uname -m)" in
  x86_64|amd64) arch=amd64 ;;
  aarch64|arm64) arch=arm64 ;;
  *) exit 64 ;;
esac
libc=glibc
if ldd --version 2>&1 | grep -qi musl || ls /lib/ld-musl-*.so.1 >/dev/null 2>&1; then
  libc=musl
fi
printf 'linux-%s-%s\n' "$arch" "$libc"
"#;
    let output = node_ssh_command(ssh, user, host, port, probe)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .context("failed to probe the managed Node release target over SSH")?;
    if !output.status.success() || output.stdout.len() > 128 {
        bail!("error_code=transport_unavailable state=target_unknown next_action=repair_node_ssh")
    }
    let value = std::str::from_utf8(&output.stdout)
        .context("remote Node release target is not UTF-8")?
        .trim();
    Ok(node_release::validate_target(value)?.to_owned())
}

fn remote_node_release_root(version: &str, target: &str) -> String {
    format!(
        "$HOME/.cache/agent-remote-node/releases/{version}/{target}",
        version = version,
        target = target
    )
}

async fn remote_node_release_digest(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
) -> Result<String> {
    node_release::validate_target(target)?;
    let stage = remote_node_release_root(version, target);
    let command = format!(
        "set -eu\nmarker={}/RELEASE\npython3 - \"$marker\" {} {} <<'PY'\n",
        stage,
        posix_shell_quote(version),
        posix_shell_quote(target)
    ) + r#"import os
import stat
import sys

path, version, target = sys.argv[1:]
descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
with os.fdopen(descriptor, "r", encoding="ascii") as source:
    metadata = os.fstat(source.fileno())
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise SystemExit(1)
    fields = source.read(256).split()
if len(fields) != 3 or fields[0] != version or fields[1] != target:
    raise SystemExit(1)
digest = fields[2]
if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
    raise SystemExit(1)
print(digest)
PY
"#;
    let output = node_ssh_command(ssh, user, host, port, &command)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .context("failed to inspect the staged Node release over SSH")?;
    if !output.status.success() || output.stdout.len() > 128 {
        bail!("staged Node release is unavailable")
    }
    let digest = std::str::from_utf8(&output.stdout)?.trim().to_owned();
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("staged Node release digest is invalid")
    }
    Ok(digest)
}

async fn remote_node_release_is_staged(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
    expected_sha256: Option<&str>,
) -> Result<bool> {
    match remote_node_release_digest(ssh, user, host, port, version, target).await {
        Ok(digest) => Ok(expected_sha256.is_none_or(|expected| expected == digest)),
        Err(_) => Ok(false),
    }
}

fn node_release_stage_command(release: &node_release::VerifiedNodeRelease) -> String {
    let version = MANAGED_NODE_VERSION;
    let target = release.target();
    let digest = release.sha256();
    let package = release.archive_name().trim_end_matches(".tar.gz");
    let stage = remote_node_release_root(version, target);
    let header = format!(
        "set -eu\numask 077\nversion={}\ntarget={}\ndigest={}\npackage={}\nstage={}\n",
        posix_shell_quote(version),
        posix_shell_quote(target),
        posix_shell_quote(digest),
        posix_shell_quote(package),
        stage,
    );
    header
        + r#"root=${stage%/*}
parent=${root%/*}
mkdir -p "$HOME/.cache" "$HOME/.cache/agent-remote-node" "$HOME/.cache/agent-remote-node/releases" "$parent" "$root"
chmod 700 "$HOME/.cache/agent-remote-node" "$HOME/.cache/agent-remote-node/releases" "$parent" "$root"
lock="$root/.install-lock"
if ! mkdir "$lock" 2>/dev/null; then
  echo local_lock_busy >&2
  exit 75
fi
work="$root/.incoming.$$"
cleanup() {
  [ -z "$work" ] || rm -rf -- "$work"
  rmdir "$lock" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM
mkdir "$work"
chmod 700 "$work"
archive="$work/release.tar.gz"
cat > "$archive"
chmod 600 "$archive"
if command -v sha256sum >/dev/null 2>&1; then
  actual=$(sha256sum "$archive" | awk '{print $1}')
else
  actual=$(shasum -a 256 "$archive" | awk '{print $1}')
fi
test "$actual" = "$digest"
extract="$work/unpacked"
mkdir "$extract"
python3 - "$archive" "$extract" "$package" "$version" <<'PY'
import os
import shutil
import stat
import sys
import tarfile
from pathlib import PurePosixPath

archive_path, destination, package, version = sys.argv[1:]
seen = set()
total = 0
with tarfile.open(archive_path, "r:gz") as source:
    members = source.getmembers()
    if not members or len(members) > 10000:
        raise SystemExit("Node release archive inventory is invalid")
    for member in members:
        path = PurePosixPath(member.name)
        parts = path.parts
        if (
            not parts
            or parts[0] != package
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in parts)
            or member.name in seen
            or not (member.isdir() or member.isfile())
        ):
            raise SystemExit("Node release archive contains an unsafe entry")
        seen.add(member.name)
        total += member.size
        if total > 8 * 1024 * 1024 * 1024:
            raise SystemExit("Node release archive expands beyond its size limit")
    for member in members:
        parts = PurePosixPath(member.name).parts
        output = os.path.join(destination, *parts)
        if member.isdir():
            os.makedirs(output, mode=0o700, exist_ok=True)
            continue
        os.makedirs(os.path.dirname(output), mode=0o700, exist_ok=True)
        payload = source.extractfile(member)
        if payload is None:
            raise SystemExit("Node release archive file is unreadable")
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with payload, os.fdopen(descriptor, "wb") as destination_file:
            shutil.copyfileobj(payload, destination_file)
        os.chmod(output, (member.mode & 0o777) | stat.S_IRUSR | stat.S_IWUSR)
release = os.path.join(destination, package)
required = ("VERSION", "install.sh", "agent-remote-node", "agent-remote-attach", "agent-remote-runtime")
for name in required:
    path = os.path.join(release, name)
    metadata = os.lstat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise SystemExit("Node release archive is incomplete")
with open(os.path.join(release, "VERSION"), encoding="ascii") as source:
    if source.read().strip() != version:
        raise SystemExit("Node release archive version is incorrect")
PY
printf '%s %s %s\n' "$version" "$target" "$digest" > "$work/RELEASE"
chmod 600 "$work/RELEASE"
rm -rf -- "$stage.previous"
if [ -e "$stage" ] || [ -L "$stage" ]; then
  mv "$stage" "$stage.previous"
fi
mv "$work" "$stage"
work=""
rm -rf -- "$stage.previous"
"#
}

async fn transfer_node_release(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    release: &node_release::VerifiedNodeRelease,
) -> Result<()> {
    let remote = node_release_stage_command(release);
    let mut command = node_ssh_command(ssh, user, host, port, &remote);
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut child = command
        .spawn()
        .context("failed to open the Node release transfer channel")?;
    let mut input = File::open(release.archive())?;
    let mut stdin = child
        .stdin
        .take()
        .context("failed to open the Node release transfer stdin")?;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if stdin.write_all(&buffer[..count]).await.is_err() {
            drop(stdin);
            let _ = child.kill().await;
            let _ = child.wait().await;
            bail!("managed Node release transfer failed")
        }
    }
    drop(stdin);
    let status = child.wait().await?;
    if !status.success() {
        bail!("managed Node rejected the authenticated release transfer")
    }
    Ok(())
}

fn staged_node_install_command(release: &node_release::VerifiedNodeRelease) -> String {
    let stage = remote_node_release_root(MANAGED_NODE_VERSION, release.target());
    let package = release.archive_name().trim_end_matches(".tar.gz");
    format!(
        "set -eu\nstage={}\nexpected={}\narchive=\"$stage/release.tar.gz\"\n\
         test -f \"$stage/RELEASE\"\ntest ! -L \"$stage/RELEASE\"\n\
         test \"$(cat \"$stage/RELEASE\")\" = {}\n\
         test -f \"$archive\"\ntest ! -L \"$archive\"\n\
         if command -v sha256sum >/dev/null 2>&1; then\n\
           actual=$(sha256sum \"$archive\" | awk '{{print $1}}')\n\
         else\n\
           actual=$(shasum -a 256 \"$archive\" | awk '{{print $1}}')\n\
         fi\n\
         test \"$actual\" = \"$expected\"\n\
         installer=\"$stage/unpacked/{}/install.sh\"\n\
         test -f \"$installer\"\ntest ! -L \"$installer\"\n\
         if [ \"$(id -u)\" -eq 0 ]; then\n\
           exec env USE_SUDO=0 bash \"$installer\" --version {} --no-start\n\
         fi\n\
         exec sudo -n env USE_SUDO=0 bash \"$installer\" --version {} --no-start\n",
        stage,
        posix_shell_quote(release.sha256()),
        posix_shell_quote(&format!(
            "{} {} {}",
            MANAGED_NODE_VERSION,
            release.target(),
            release.sha256()
        )),
        package,
        posix_shell_quote(MANAGED_NODE_VERSION),
        posix_shell_quote(MANAGED_NODE_VERSION),
    )
}

async fn install_staged_node_release(
    ssh: &OsStr,
    user: &str,
    host: &str,
    port: u16,
    release: &node_release::VerifiedNodeRelease,
) -> Result<()> {
    let remote = staged_node_install_command(release);
    let status = node_ssh_command(ssh, user, host, port, &remote)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await
        .context("failed to launch the authenticated Node release installer")?;
    if !status.success() {
        bail!("authenticated Node release installation failed")
    }
    Ok(())
}

fn node_enrollment_command(
    exchange_id: &str,
    server_url: &str,
    node_id: &str,
    has_join_code: bool,
    enable_ego_browser: bool,
) -> String {
    let mut arguments = format!(
        "install --config /etc/agent-remote-node/config.json --system-install \
         --version {} --exchange-id {} --server-url {} --node-id {}",
        posix_shell_quote(MANAGED_NODE_VERSION),
        posix_shell_quote(exchange_id),
        posix_shell_quote(server_url),
        posix_shell_quote(node_id),
    );
    if has_join_code {
        arguments.push_str(" --join-code-stdin");
    }
    if enable_ego_browser {
        arguments.push_str(" --enable-ego-browser");
    }
    format!(
        "set -eu\nnode=/usr/local/bin/agent-remote-node\ntest -x \"$node\"\n\
         if [ \"$(id -u)\" -eq 0 ] && id agent-remote >/dev/null 2>&1; then\n\
           runuser -u agent-remote -- \"$node\" {arguments}\n\
         else\n\
           \"$node\" {arguments}\n\
         fi\n\
         privileged() {{\n\
           if [ \"$(id -u)\" -eq 0 ]; then \"$@\"; else sudo -n \"$@\"; fi\n\
         }}\n\
         privileged systemctl enable agent-remote-runtime.service\n\
         privileged systemctl restart agent-remote-runtime.service\n\
         privileged systemctl enable wg-quick@agent-remote.service\n\
         privileged systemctl restart wg-quick@agent-remote.service\n\
         privileged systemctl enable agent-remote-node.service\n\
         privileged systemctl restart agent-remote-node.service\n\
         privileged systemctl is-active --quiet agent-remote-runtime.service\n\
         privileged systemctl is-active --quiet agent-remote-node.service\n"
    )
}

async fn cleanup_staged_node_release(
    ssh: impl AsRef<OsStr>,
    user: &str,
    host: &str,
    port: u16,
    version: &str,
    target: &str,
    expected_sha256: Option<&str>,
) {
    let Some(expected) = expected_sha256 else {
        return;
    };
    if expected.len() != 64 || node_release::validate_target(target).is_err() {
        return;
    }
    let stage = remote_node_release_root(version, target);
    let command = format!(
        "set -eu\nstage={}\nmarker=\"$stage/RELEASE\"\n\
         test \"$(cat \"$marker\")\" = {}\nrm -rf -- \"$stage\"\n",
        stage,
        posix_shell_quote(&format!("{version} {target} {expected}")),
    );
    let _ = node_ssh_command(ssh.as_ref(), user, host, port, &command)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

fn valid_join_code(value: &str) -> bool {
    (16..=4096).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && !byte.is_ascii_whitespace())
}

fn valid_node_install_server_url(value: &str) -> bool {
    if value.is_empty() || value.len() > 2048 || !value.is_ascii() {
        return false;
    }
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
        && url.username().is_empty()
        && url.password().is_none()
        && url.host_str().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.as_str().trim_end_matches('/') == value
}

fn valid_managed_ssh_host(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && value.bytes().any(|byte| byte.is_ascii_alphanumeric())
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b':' | b'-' | b'_' | b'%')
        })
}

fn valid_managed_ssh_user(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

fn posix_shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn valid_join_code_expiry(value: &str) -> bool {
    let Some(timestamp) = parse_rfc3339_seconds(value) else {
        return false;
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    timestamp > now
}

fn parse_rfc3339_seconds(value: &str) -> Option<u64> {
    if value.len() < 20 {
        return None;
    }
    let bytes = value.as_bytes();
    if bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return None;
    }
    let number = |start: usize, end: usize| -> Option<u32> { value.get(start..end)?.parse().ok() };
    let year = number(0, 4)? as i64;
    let month = number(5, 7)?;
    let day = number(8, 10)?;
    let hour = number(11, 13)?;
    let minute = number(14, 16)?;
    let second = number(17, 19)?;
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[(month - 1) as usize] {
        return None;
    }
    let mut cursor = 19;
    if bytes.get(cursor) == Some(&b'.') {
        cursor += 1;
        let fraction_start = cursor;
        while bytes.get(cursor).is_some_and(u8::is_ascii_digit) {
            cursor += 1;
        }
        if cursor == fraction_start || cursor - fraction_start > 9 {
            return None;
        }
    }
    let offset_minutes: i64 = match bytes.get(cursor..) {
        Some(b"Z") => 0,
        Some(offset)
            if offset.len() == 6
                && (offset[0] == b'+' || offset[0] == b'-')
                && offset[3] == b':' =>
        {
            let hours: i64 = std::str::from_utf8(&offset[1..3]).ok()?.parse().ok()?;
            let minutes: i64 = std::str::from_utf8(&offset[4..6]).ok()?.parse().ok()?;
            if hours > 23 || minutes > 59 {
                return None;
            }
            let total = hours * 60 + minutes;
            if offset[0] == b'-' {
                -total
            } else {
                total
            }
        }
        _ => return None,
    };
    let adjusted_year = year - i64::from(month <= 2);
    let era = (if adjusted_year >= 0 {
        adjusted_year
    } else {
        adjusted_year - 399
    }) / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_prime = month as i64 + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day as i64 - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = era * 146097 + day_of_era - 719468;
    let utc = days
        .checked_mul(86_400)?
        .checked_add(i64::from(hour) * 3600 + i64::from(minute) * 60 + i64::from(second))?
        .checked_sub(offset_minutes * 60)?;
    u64::try_from(utc).ok()
}

async fn node_install_transport_failure(
    client: &ApiClient,
    token: &str,
    node_id: &str,
    exchange: &NodeInstallExchangeState,
    paths: &AppPaths,
) -> anyhow::Error {
    match client
        .revoke_node_join_code(token, node_id, &exchange.exchange_id)
        .await
    {
        Ok(NodeJoinCodeRevokeState::Revoked | NodeJoinCodeRevokeState::Missing)
            if node_install_state::clear(paths).is_ok() =>
        {
            anyhow::anyhow!(
                "error_code=transport_unavailable state=join_code_revoked next_action=retry_node_install"
            )
        }
        _ => node_install_pending_transport_failure(),
    }
}

fn node_install_pending_transport_failure() -> anyhow::Error {
    anyhow::anyhow!(
        "error_code=transport_unavailable state=exchange_pending next_action=retry_same_command"
    )
}

fn node_install_fingerprint(node: &NodeData) -> String {
    use std::fmt::Write as _;

    let transport = format!(
        "{}\0{}\0{}\0{}",
        node.id,
        node.ssh_host.as_deref().unwrap_or(""),
        node.ssh_port.unwrap_or(22),
        node.ssh_user.as_deref().unwrap_or("agent-remote")
    );
    let digest = Sha256::digest(transport.as_bytes());
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(encoded, "{byte:02x}");
    }
    encoded
}

fn node_fingerprint(node: &NodeData) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        node.id,
        node.name,
        node.status,
        node.ssh_host.as_deref().unwrap_or(""),
        node.ssh_port.unwrap_or_default(),
        node.ssh_user.as_deref().unwrap_or(""),
        node.version.as_deref().unwrap_or(""),
        node.configured_enabled,
        node.effective_enabled,
        node.node_execution_allowed,
        node.ego_browser_enabled,
        node.enrollment_admission,
        node.execution_admission,
    )
}

struct DeviceRegistrationOptions {
    device_name: Option<String>,
    ssh_public_key: Option<PathBuf>,
    wireguard_public_key: Option<String>,
    skip_device_registration: bool,
}

