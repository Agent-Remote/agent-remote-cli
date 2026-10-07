//! Reused, owned SSH transfers with durable, connection-scoped cleanup receipts.
use super::{archive::Archive, set_private_directory, validate_session_id};
use crate::{api::AttachSessionData, config::AppPaths};
use anyhow::{bail, Context, Result};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    io::{Read, Write},
    path::PathBuf,
    process::Stdio,
    time::Duration,
};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;

const RECEIVER: &str = include_str!("receiver.py");
// All variable data travels over stdin. No path or API text becomes shell code.
const COMMAND: &str = "/usr/bin/python3 -c 'import sys; exec(compile(sys.stdin.buffer.read(int(sys.stdin.buffer.readline())), \"attachment-receiver\", \"exec\"))'";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
struct Endpoint {
    host: String,
    port: u16,
    user: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct Receipt {
    endpoint: Endpoint,
    account: String,
    session: String,
    lease: String,
}

#[derive(Debug)]
struct Journal {
    _lock: File,
    receipt: Receipt,
    connection: Option<Connection>,
    #[allow(dead_code)]
    path: PathBuf,
}

#[derive(Debug)]
pub(super) struct Transfer {
    receipt: Receipt,
    visible_account: String,
    journal: Mutex<Option<Journal>>,
}

pub(super) fn unique_id() -> String {
    let mut bytes = [0; 16];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl Transfer {
    #[allow(dead_code)]
    pub(super) fn new(attach: &AttachSessionData, account: String, backend: &str) -> Result<Self> {
        validate_session_id(&attach.session_id)?;
        if !account.starts_with('/')
            || account.len() > 4096
            || account[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || account.chars().any(char::is_control)
        {
            bail!("invalid remote attachment account directory");
        }
        if attach.ssh_host.is_empty()
            || attach.ssh_host.starts_with('-')
            || attach
                .ssh_host
                .chars()
                .any(|c| c.is_whitespace() || c.is_control())
            || attach.ssh_user.is_empty()
            || !attach
                .ssh_user
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            || attach.ssh_port == 0
        {
            bail!("invalid attachment SSH endpoint");
        }
        let visible_account = match backend {
            "native" => "/account".to_owned(),
            "docker_sandbox" => account.clone(),
            _ => bail!("unsupported attachment runtime backend"),
        };
        Ok(Self {
            receipt: Receipt {
                endpoint: Endpoint {
                    host: attach.ssh_host.clone(),
                    port: attach.ssh_port,
                    user: attach.ssh_user.clone(),
                },
                account,
                session: attach.session_id.clone(),
                lease: unique_id(),
            },
            visible_account,
            journal: Mutex::new(None),
        })
    }

    pub(super) async fn upload(&self, paths: &AppPaths, archive: Archive) -> Result<Vec<String>> {
        let mut journal = self.journal.lock().await;
        // A cancelled request drops its owned channel. Use a fresh lease when
        // reconnecting so the old receiver's EOF cleanup cannot erase new data.
        if journal
            .as_ref()
            .is_some_and(|active| active.connection.is_none())
        {
            *journal = None;
        }
        if journal.is_none() {
            let _ = tokio::time::timeout(Duration::from_secs(12), self.recover(paths)).await;
            let mut receipt = self.receipt.clone();
            receipt.lease = unique_id();
            let mut active = Self::write_receipt(paths, receipt)?;
            active.connection = Some(Connection::open(paths, &active.receipt).await?);
            *journal = Some(active);
        }
        let active = journal.as_mut().context("missing attachment channel")?;
        let mut connection = active
            .connection
            .take()
            .context("attachment channel closed")?;
        let batch = unique_id();
        connection
            .request(&active.receipt, Some((&archive, &batch)))
            .await?;
        active.connection = Some(connection);
        Ok(archive
            .names
            .iter()
            .map(|name| {
                format!(
                    "{}/.agent-remote-attachments/{}/{}/{batch}/{name}",
                    self.visible_account, active.receipt.session, active.receipt.lease
                )
            })
            .collect())
    }

    #[allow(dead_code)]
    pub(super) async fn cleanup(&self, _paths: &AppPaths) -> Result<()> {
        let mut journal = self.journal.lock().await;
        if let Some(active) = journal.as_mut() {
            if let Some(mut connection) = active.connection.take() {
                tokio::time::timeout(Duration::from_secs(3), async {
                    connection.request(&active.receipt, None).await?;
                    connection.close().await
                })
                .await
                .context("attachment cleanup deferred until reconnect")??;
                std::fs::remove_file(&active.path)?;
                *journal = None;
            } else {
                // Its receiver cleans on EOF; retain the receipt until a later
                // connection can verify it. Never delay detach on a new login.
                bail!("attachment cleanup will be verified on the next transfer");
            }
        }
        Ok(())
    }

    fn write_receipt(paths: &AppPaths, receipt: Receipt) -> Result<Journal> {
        let root = paths.home().join("attachments/pending");
        std::fs::create_dir_all(&root)?;
        set_private_directory(&root)?;
        let mut temporary = tempfile::NamedTempFile::new_in(&root)?;
        serde_json::to_writer(&mut temporary, &receipt)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        let path = root.join(format!("{}.json", receipt.lease));
        temporary
            .as_file()
            .try_lock()
            .context("failed to lock attachment receipt")?;
        let file = temporary.persist_noclobber(&path)?;
        Ok(Journal {
            _lock: file,
            path,
            receipt,
            connection: None,
        })
    }

    fn can_recover(&self, receipt: &Receipt) -> bool {
        receipt.endpoint == self.receipt.endpoint
            && receipt.account == self.receipt.account
            && validate_session_id(&receipt.session).is_ok()
            && validate_session_id(&receipt.lease).is_ok()
    }

    async fn recover(&self, paths: &AppPaths) -> Result<()> {
        let root = paths.home().join("attachments/pending");
        let Ok(entries) = std::fs::read_dir(root) else {
            return Ok(());
        };
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_file() || entry.metadata()?.len() > 16384 {
                continue;
            }
            let mut file = File::options().read(true).write(true).open(entry.path())?;
            if file.try_lock().is_err() {
                continue;
            }
            let mut bytes = Vec::new();
            Read::by_ref(&mut file)
                .take(16385)
                .read_to_end(&mut bytes)?;
            let Ok(receipt) = serde_json::from_slice::<Receipt>(&bytes) else {
                continue;
            };
            if !self.can_recover(&receipt) {
                continue;
            }
            let mut connection = Connection::open(paths, &receipt).await?;
            connection.request(&receipt, None).await?;
            connection.close().await?;
            std::fs::remove_file(entry.path())?;
        }
        Ok(())
    }
}

#[derive(Debug)]
struct Connection {
    child: tokio::process::Child,
    input: tokio::process::ChildStdin,
    output: BufReader<tokio::process::ChildStdout>,
}

impl Connection {
    async fn open(paths: &AppPaths, receipt: &Receipt) -> Result<Self> {
        let mut command = tokio::process::Command::new(crate::platform::ssh_binary());
        command
            .args([
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "ConnectTimeout=8",
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
            .arg(format!(
                "UserKnownHostsFile={}",
                paths.ssh_dir().join("known_hosts").display()
            ))
            .arg("-p")
            .arg(receipt.endpoint.port.to_string())
            .arg(format!(
                "{}@{}",
                receipt.endpoint.user, receipt.endpoint.host
            ))
            .arg(COMMAND)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .context("failed to start attachment SSH transfer")?;
        let input = child
            .stdin
            .take()
            .context("missing attachment input pipe")?;
        let output = BufReader::new(
            child
                .stdout
                .take()
                .context("missing attachment output pipe")?,
        );
        let mut channel = Self {
            child,
            input,
            output,
        };
        tokio::time::timeout(Duration::from_secs(15), async {
            channel
                .input
                .write_all(format!("{}\n", RECEIVER.len()).as_bytes())
                .await?;
            channel.input.write_all(RECEIVER.as_bytes()).await
        })
        .await
        .context("attachment connection timed out")??;
        Ok(channel)
    }

    async fn request(&mut self, receipt: &Receipt, upload: Option<(&Archive, &str)>) -> Result<()> {
        let mut header = serde_json::json!({"version":1,"operation":if upload.is_some(){"upload"}else{"cleanup"},"account":receipt.account,"session":receipt.session,"lease":receipt.lease});
        if let Some((archive, batch)) = upload {
            header["size"] = archive.size.into();
            header["sha256"] = archive.sha256.clone().into();
            header["batch"] = batch.into();
        }
        tokio::time::timeout(Duration::from_secs(300), async {
            self.input
                .write_all(serde_json::to_string(&header)?.as_bytes())
                .await?;
            self.input.write_all(b"\n").await?;
            if let Some((archive, _)) = upload {
                let mut source = tokio::fs::File::from_std(archive.file.try_clone()?);
                let mut buffer = vec![0; 65536];
                loop {
                    let count = source.read(&mut buffer).await?;
                    if count == 0 {
                        break;
                    }
                    tokio::time::timeout(
                        Duration::from_secs(15),
                        self.input.write_all(&buffer[..count]),
                    )
                    .await
                    .context("attachment transfer stopped making progress")??;
                }
            }
            self.input.flush().await?;
            let mut response = Vec::new();
            tokio::time::timeout(
                Duration::from_secs(15),
                (&mut self.output)
                    .take(4097)
                    .read_until(b'\n', &mut response),
            )
            .await
            .context("attachment acknowledgement timed out")??;
            if response.len() > 4096 {
                bail!("attachment acknowledgement too large");
            }
            let reply: serde_json::Value =
                serde_json::from_slice(&response).context("invalid attachment acknowledgement")?;
            if reply != serde_json::json!({"version":1,"ok":true}) {
                bail!("attachment was not acknowledged; no remote path was submitted");
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("attachment operation timed out")?
    }

    async fn close(mut self) -> Result<()> {
        self.input.shutdown().await?;
        drop(self.input);
        if !self.child.wait().await?.success() {
            bail!("attachment channel cleanup failed");
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/transfer.rs"]
mod tests;
