//! Exact-session attachment transfer over the separately authorized SSH gateway.
//!
//! The terminal and transfer channels are deliberately independent.  The
//! transfer gateway first offers the Node-generated lease, then accepts only
//! frames bound to the reviewed session and device.  No account path is sent
//! by the client and the legacy receiver is never used for this flow.

use super::{archive::Archive, set_private_directory};
use crate::{api::AttachSessionData, config::AppPaths, platform};
use anyhow::{bail, Context, Result};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    io::Read,
    process::Stdio,
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

const RECEIVER_COMMAND: &str = "agent-remote-attach";
const MAX_FRAME_BYTES: usize = 64 * 1024;
const MAX_BATCH_BYTES: u64 = 256 * 1024 * 1024;
const MAX_ENTRIES: usize = 32;

#[derive(Clone, Debug)]
pub(super) struct Transfer {
    endpoint: Endpoint,
    session_id: String,
    expected_device_id: String,
    node_id: String,
    connection: std::sync::Arc<Mutex<Option<Connection>>>,
}

#[derive(Clone, Debug)]
struct Endpoint {
    host: String,
    port: u16,
    user: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LeaseOffer {
    version: u32,
    operation: String,
    node_id: String,
    session_id: String,
    expected_device_id: String,
    ssh_key_id: String,
    lease_id: String,
    expires_at: String,
    max_bytes: u64,
    max_entries: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenAck {
    version: u32,
    operation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadAck {
    version: u32,
    operation: String,
    batch_id: String,
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanupReceipt {
    version: u32,
    operation: String,
    node_id: String,
    session_id: String,
    expected_device_id: String,
    ssh_key_id: String,
    lease_id: String,
    status: String,
    removed_batches: usize,
    receipt_id: String,
}

impl Transfer {
    #[allow(dead_code)]
    pub(super) fn new(attach: &AttachSessionData, expected_device_id: &str) -> Result<Self> {
        for (name, value) in [
            ("session", attach.session_id.as_str()),
            ("device", expected_device_id),
            ("node", attach.node_id.as_str()),
        ] {
            if !canonical_uuid(value) {
                bail!("invalid exact attachment {name} identity");
            }
        }
        if attach.ssh_host.is_empty()
            || attach.ssh_host.starts_with('-')
            || attach
                .ssh_host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || attach.ssh_user.is_empty()
            || attach.ssh_user.starts_with('-')
            || !attach
                .ssh_user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || attach.ssh_port == 0
        {
            bail!("invalid exact attachment SSH endpoint");
        }
        Ok(Self {
            endpoint: Endpoint {
                host: attach.ssh_host.clone(),
                port: attach.ssh_port,
                user: attach.ssh_user.clone(),
            },
            session_id: attach.session_id.clone(),
            expected_device_id: expected_device_id.to_owned(),
            node_id: attach.node_id.clone(),
            connection: std::sync::Arc::new(Mutex::new(None)),
        })
    }

    pub(super) async fn upload(&self, paths: &AppPaths, archive: Archive) -> Result<Vec<String>> {
        let mut guard = self.connection.lock().await;
        if guard.is_none() {
            *guard = Some(Connection::open(paths, self).await?);
        }
        guard
            .as_mut()
            .context("exact attachment channel is unavailable")?
            .upload(&archive)
            .await
    }

    pub(super) async fn cleanup(&self, _paths: &AppPaths) -> Result<()> {
        let mut guard = self.connection.lock().await;
        let Some(mut connection) = guard.take() else {
            return Ok(());
        };
        connection
            .cleanup(&self.session_id, &self.expected_device_id)
            .await
    }
}

#[derive(Debug)]
struct Connection {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: BufReader<tokio::process::ChildStdout>,
    lease_id: String,
    node_id: String,
    session_id: String,
    expected_device_id: String,
    max_bytes: u64,
    max_entries: usize,
    pending_path: std::path::PathBuf,
}

impl Connection {
    async fn open(paths: &AppPaths, transfer: &Transfer) -> Result<Self> {
        let known_hosts = paths.ssh_dir().join("known_hosts");
        let mut command = tokio::process::Command::new(platform::ssh_binary());
        command
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
                "ClearAllForwardings=yes",
                "-o",
                "ForwardAgent=no",
                "-o",
                "PermitLocalCommand=no",
                "-o",
                "StrictHostKeyChecking=accept-new",
                "-o",
            ])
            .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
            .args(["-p", &transfer.endpoint.port.to_string()])
            .arg(format!(
                "{}@{}",
                transfer.endpoint.user, transfer.endpoint.host
            ))
            .args([
                RECEIVER_COMMAND,
                "--session",
                &transfer.session_id,
                "--expected-device",
                &transfer.expected_device_id,
                "--attachment-transfer",
                "1",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .context("failed to start exact attachment SSH")?;
        let input = child
            .stdin
            .take()
            .context("missing exact attachment stdin")?;
        let output = child
            .stdout
            .take()
            .context("missing exact attachment stdout")?;
        let mut connection = Self {
            child,
            input,
            output: BufReader::new(output),
            lease_id: String::new(),
            node_id: transfer.node_id.clone(),
            session_id: transfer.session_id.clone(),
            expected_device_id: transfer.expected_device_id.clone(),
            max_bytes: 0,
            max_entries: 0,
            pending_path: std::path::PathBuf::new(),
        };
        let offer: LeaseOffer = connection.read_frame().await?;
        if offer.version != 1
            || offer.operation != "lease_offer"
            || offer.node_id != transfer.node_id
            || offer.session_id != transfer.session_id
            || offer.expected_device_id != transfer.expected_device_id
            || !canonical_uuid(&offer.ssh_key_id)
            || !canonical_uuid(&offer.lease_id)
            || offer.max_bytes == 0
            || offer.max_bytes > MAX_BATCH_BYTES
            || offer.max_entries == 0
            || offer.max_entries > MAX_ENTRIES
            || !future_rfc3339(&offer.expires_at)
        {
            bail!("exact attachment lease offer does not match the reviewed session");
        }
        connection.lease_id = offer.lease_id;
        connection.max_bytes = offer.max_bytes;
        connection.max_entries = offer.max_entries;
        connection.pending_path = write_pending_receipt(paths, transfer, &connection.lease_id)?;
        connection
            .write_frame(&serde_json::json!({
                "version": 1,
                "operation": "open",
                "session_id": transfer.session_id,
                "expected_device_id": transfer.expected_device_id,
                "lease_id": connection.lease_id,
            }))
            .await?;
        let ack: OpenAck = connection.read_frame().await?;
        if ack.version != 1 || ack.operation != "open_ack" {
            bail!("exact attachment gateway did not acknowledge open");
        }
        Ok(connection)
    }

    async fn upload(&mut self, archive: &Archive) -> Result<Vec<String>> {
        let file = archive.file.try_clone()?;
        let mut zip = zip::ZipArchive::new(file).context("invalid attachment archive")?;
        let mut paths = Vec::new();
        let mut total = 0_u64;
        let mut count = 0_usize;
        for index in 0..zip.len() {
            let mut entry = zip.by_index(index)?;
            if entry.is_dir() {
                continue;
            }
            let raw_name = entry.name()?.replace('\\', "-");
            let leaf = raw_name.rsplit('/').next().unwrap_or_default();
            let name = format!("{count}-{leaf}");
            if leaf.is_empty() || name.len() > 255 || name.chars().any(char::is_control) {
                bail!("attachment name cannot be represented by exact gateway");
            }
            let mut bytes = Vec::with_capacity(entry.size().min(MAX_BATCH_BYTES) as usize);
            entry.read_to_end(&mut bytes)?;
            let size = bytes.len() as u64;
            total = total
                .checked_add(size)
                .context("attachment size overflow")?;
            if size == 0 || size > self.max_bytes || total > self.max_bytes {
                bail!("attachment exceeds the exact lease byte limit");
            }
            count += 1;
            if count > self.max_entries {
                bail!("attachment exceeds the exact lease entry limit");
            }
            let batch_id = Uuid::new_v4().to_string();
            let mut digest = Sha256::new();
            digest.update(&bytes);
            let kind = if leaf.starts_with("image.") {
                "image"
            } else {
                "file"
            };
            self.write_frame(&serde_json::json!({
                "version": 1,
                "operation": "upload",
                "session_id": self.session_id.as_str(),
                "expected_device_id": self.expected_device_id.as_str(),
                "lease_id": self.lease_id.as_str(),
                "batch_id": batch_id,
                "kind": kind,
                "name": name,
                "size": size,
                "sha256": format!("{:x}", digest.finalize()),
            }))
            .await?;
            self.input.write_all(&bytes).await?;
            self.input.flush().await?;
            let ack: UploadAck = self.read_frame().await?;
            if ack.version != 1
                || ack.operation != "upload_ack"
                || ack.batch_id != batch_id
                || !safe_remote_path(&ack.path)
            {
                bail!("exact attachment upload acknowledgement is invalid");
            }
            paths.push(ack.path);
        }
        if paths.is_empty() {
            bail!("attachment archive has no files");
        }
        Ok(paths)
    }

    async fn cleanup(&mut self, session_id: &str, device_id: &str) -> Result<()> {
        self.write_frame(&serde_json::json!({
            "version": 1,
            "operation": "cleanup",
            "session_id": session_id,
            "expected_device_id": device_id,
            "lease_id": self.lease_id.as_str(),
        }))
        .await?;
        let receipt: CleanupReceipt = match self.read_frame().await {
            Ok(receipt) => receipt,
            Err(error) => {
                let _ = update_pending_receipt(&self.pending_path, "unknown", 0, None);
                return Err(error.context("exact attachment cleanup response was lost"));
            }
        };
        if receipt.version != 1
            || receipt.operation != "cleanup_receipt"
            || receipt.node_id != self.node_id
            || receipt.session_id != session_id
            || receipt.expected_device_id != device_id
            || !canonical_uuid(&receipt.ssh_key_id)
            || receipt.lease_id != self.lease_id
            || !matches!(
                receipt.status.as_str(),
                "cleaned" | "pending" | "unknown" | "rejected"
            )
            || receipt.removed_batches > MAX_ENTRIES
            || !canonical_uuid(&receipt.receipt_id)
        {
            let _ = update_pending_receipt(&self.pending_path, "unknown", 0, None);
            bail!("exact attachment cleanup receipt is invalid");
        }
        update_pending_receipt(
            &self.pending_path,
            &receipt.status,
            receipt.removed_batches,
            Some(&receipt.receipt_id),
        )?;
        if let Err(error) = self.input.shutdown().await {
            let _ = update_pending_receipt(
                &self.pending_path,
                "unknown",
                receipt.removed_batches,
                Some(&receipt.receipt_id),
            );
            return Err(error.into());
        }
        let status = match self.child.wait().await {
            Ok(status) => status,
            Err(error) => {
                let _ = update_pending_receipt(
                    &self.pending_path,
                    "unknown",
                    receipt.removed_batches,
                    Some(&receipt.receipt_id),
                );
                return Err(error.into());
            }
        };
        if !status.success() || receipt.status != "cleaned" {
            bail!("exact attachment cleanup is {}", receipt.status);
        }
        std::fs::remove_file(&self.pending_path)
            .context("exact attachment cleanup receipt could not be removed")?;
        Ok(())
    }

    async fn write_frame(&mut self, value: &serde_json::Value) -> Result<()> {
        let bytes = serde_json::to_vec(value)?;
        if bytes.len() > MAX_FRAME_BYTES {
            bail!("exact attachment frame is too large");
        }
        self.input.write_all(&bytes).await?;
        self.input.write_all(b"\n").await?;
        Ok(())
    }

    async fn read_frame<T: DeserializeOwned>(&mut self) -> Result<T> {
        let mut line = Vec::new();
        let count = tokio::time::timeout(
            Duration::from_secs(15),
            self.output.read_until(b'\n', &mut line),
        )
        .await
        .context("exact attachment response timed out")??;
        if count == 0 || line.len() > MAX_FRAME_BYTES || !line.ends_with(b"\n") {
            bail!("exact attachment response is invalid");
        }
        Ok(serde_json::from_slice(&line[..line.len() - 1])?)
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct PendingReceipt {
    version: u32,
    node_id: String,
    session_id: String,
    expected_device_id: String,
    lease_id: String,
    status: String,
    removed_batches: usize,
    receipt_id: Option<String>,
}

fn write_pending_receipt(
    paths: &AppPaths,
    transfer: &Transfer,
    lease_id: &str,
) -> Result<std::path::PathBuf> {
    let root = paths.home().join("attachments/exact-pending");
    std::fs::create_dir_all(&root)?;
    set_private_directory(&root)?;
    let receipt = PendingReceipt {
        version: 1,
        node_id: transfer.node_id.clone(),
        session_id: transfer.session_id.clone(),
        expected_device_id: transfer.expected_device_id.clone(),
        lease_id: lease_id.to_owned(),
        status: "pending".into(),
        removed_batches: 0,
        receipt_id: None,
    };
    let path = root.join(format!("{lease_id}.json"));
    let mut temporary = tempfile::NamedTempFile::new_in(&root)?;
    serde_json::to_writer(&mut temporary, &receipt)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&path)
        .map_err(|error| error.error)?;
    Ok(path)
}

fn update_pending_receipt(
    path: &std::path::Path,
    status: &str,
    removed_batches: usize,
    receipt_id: Option<&str>,
) -> Result<()> {
    let bytes = std::fs::read(path)?;
    let mut receipt: PendingReceipt = serde_json::from_slice(&bytes)?;
    receipt.status = status.to_owned();
    receipt.removed_batches = removed_batches;
    receipt.receipt_id = receipt_id.map(str::to_owned);
    let parent = path
        .parent()
        .context("missing exact attachment receipt root")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    serde_json::to_writer(&mut temporary, &receipt)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

fn canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id != Uuid::nil() && id.to_string() == value)
}

fn future_rfc3339(value: &str) -> bool {
    let Ok(parsed) = parse_rfc3339_utc(value) else {
        return false;
    };
    parsed > SystemTime::now()
}

fn parse_rfc3339_utc(value: &str) -> Result<SystemTime> {
    if !value.ends_with('Z') || value.len() < 20 || value.len() > 40 {
        bail!("invalid lease expiry");
    }
    let prefix = value.get(0..19).context("invalid lease expiry")?;
    if prefix.as_bytes().get(4) != Some(&b'-')
        || prefix.as_bytes().get(7) != Some(&b'-')
        || prefix.as_bytes().get(10) != Some(&b'T')
        || prefix.as_bytes().get(13) != Some(&b':')
        || prefix.as_bytes().get(16) != Some(&b':')
    {
        bail!("invalid lease expiry");
    }
    let year = prefix[0..4].parse::<i64>()?;
    let month = prefix[5..7].parse::<i64>()?;
    let day = prefix[8..10].parse::<i64>()?;
    let hour = prefix[11..13].parse::<i64>()?;
    let minute = prefix[14..16].parse::<i64>()?;
    let second = prefix[17..19].parse::<i64>()?;
    if !(1..=12).contains(&month)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        bail!("invalid lease expiry");
    }
    let days_in_month = [
        31,
        28 + i64::from(is_leap(year)),
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
    if !(1..=days_in_month[(month - 1) as usize]).contains(&day) {
        bail!("invalid lease expiry");
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        bail!("invalid lease expiry");
    }
    let seconds = days
        .checked_mul(86_400)
        .and_then(|v| v.checked_add(hour * 3_600 + minute * 60 + second))
        .context("invalid lease expiry")?;
    Ok(std::time::UNIX_EPOCH + Duration::from_secs(seconds as u64))
}

fn is_leap(year: i64) -> bool {
    year % 4 == 0 && (year % 100 != 0 || year % 400 == 0)
}

// Howard Hinnant's proleptic Gregorian civil-date calculation, expressed in
// days since 1970-01-01 so the CLI can validate a lease without another crate.
fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = year - i64::from(month <= 2);
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let yoe = year - era * 400;
    let month = month + if month > 2 { -3 } else { 9 };
    let doy = (153 * month + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn safe_remote_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() <= 4096
        && !value.chars().any(char::is_control)
        && !value.split('/').any(|part| part == ".." || part == ".")
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/exact_transfer.rs"]
mod tests;
