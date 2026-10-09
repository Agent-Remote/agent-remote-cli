//! Cross-platform PTY-backed SSH process used by the attachment bridge.
//!
//! OpenSSH only receives reliable window-size notifications when its standard
//! input is a terminal.  The attachment bridge must inspect input locally, so
//! it cannot connect SSH directly to the user's terminal.  This module gives
//! SSH a real local PTY and exposes the PTY master as Tokio I/O streams.

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::sync::{Arc, Mutex};

type Master = Box<dyn MasterPty + Send>;

#[cfg(any(windows, test))]
mod blocking;
#[cfg(windows)]
use blocking::{ReaderStream, WriterStream};
#[cfg(unix)]
mod unix;
#[cfg(unix)]
use unix::{ReaderStream, WriterStream};

pub struct Session {
    reader: ReaderStream,
    writer: WriterStream,
    master: Arc<Mutex<Master>>,
    child: Box<dyn Child + Send + Sync>,
}

impl Session {
    pub fn spawn(command: &tokio::process::Command, size: PtySize) -> Result<Self> {
        let std_command = command.as_std();
        let mut builder = CommandBuilder::new(std_command.get_program());
        builder.args(std_command.get_args());
        if let Some(directory) = std_command.get_current_dir() {
            builder.cwd(directory);
        }
        for (key, value) in std_command.get_envs() {
            match value {
                Some(value) => builder.env(key, value),
                None => builder.env_remove(key),
            }
        }

        let pty = native_pty_system()
            .openpty(size)
            .context("failed to allocate a local PTY for SSH")?;
        let master: Master = pty.master;
        let slave = pty.slave;
        let child = slave
            .spawn_command(builder)
            .context("failed to start SSH in the local PTY")?;
        // The child owns the slave side. Keeping it here would prevent EOF on
        // the master after SSH exits, especially on Windows ConPTY.
        drop(slave);
        #[cfg(unix)]
        let (reader, writer) = unix::streams(&*master)?;
        #[cfg(windows)]
        let (reader, writer) = (
            ReaderStream::new(
                master
                    .try_clone_reader()
                    .context("failed to open the SSH PTY reader")?,
            ),
            WriterStream::new(
                master
                    .take_writer()
                    .context("failed to open the SSH PTY writer")?,
            ),
        );
        let master = Arc::new(Mutex::new(master));
        Ok(Self {
            reader,
            writer,
            master,
            child,
        })
    }

    pub fn parts(self) -> (ReaderStream, WriterStream, ResizeHandle, PtyChild) {
        (
            self.reader,
            self.writer,
            ResizeHandle {
                master: self.master,
            },
            PtyChild { child: self.child },
        )
    }
}

#[derive(Clone)]
pub struct ResizeHandle {
    master: Arc<Mutex<Master>>,
}

impl ResizeHandle {
    pub fn resize(&self, size: PtySize) -> Result<()> {
        self.master
            .lock()
            .map_err(|_| anyhow::anyhow!("SSH PTY lock poisoned"))?
            .resize(size)
            .context("failed to resize the SSH PTY")
    }
}

pub struct PtyChild {
    child: Box<dyn Child + Send + Sync>,
}

impl PtyChild {
    pub fn killer(&self) -> Box<dyn portable_pty::ChildKiller + Send + Sync> {
        self.child.clone_killer()
    }

    pub async fn wait(self) -> Result<portable_pty::ExitStatus> {
        let mut child = self.child;
        tokio::task::spawn_blocking(move || child.wait().context("failed to wait for SSH"))
            .await
            .context("SSH wait task failed")?
    }
}

pub fn command_size() -> PtySize {
    let (rows, cols) = match terminal_size::terminal_size() {
        Some((terminal_size::Width(cols), terminal_size::Height(rows))) => (rows, cols),
        None => (48, 160),
    };
    PtySize {
        rows: rows.max(1),
        cols: cols.max(1),
        pixel_width: 0,
        pixel_height: 0,
    }
}

pub fn exit_status(status: portable_pty::ExitStatus) -> std::process::ExitStatus {
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        std::process::ExitStatus::from_raw((status.exit_code() as i32) << 8)
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::ExitStatusExt;
        std::process::ExitStatus::from_raw(status.exit_code())
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = status;
        unreachable!("unsupported platform")
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/ssh/pty.rs"]
mod tests;
