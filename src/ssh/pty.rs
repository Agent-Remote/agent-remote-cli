//! Cross-platform PTY-backed SSH process used by the attachment bridge.
//!
//! OpenSSH only receives reliable window-size notifications when its standard
//! input is a terminal.  The attachment bridge must inspect input locally, so
//! it cannot connect SSH directly to the user's terminal.  This module gives
//! SSH a real local PTY and exposes the PTY master as Tokio I/O streams.

use anyhow::{Context, Result};
use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

type Reader = Box<dyn Read + Send>;
type Writer = Box<dyn Write + Send>;
type Master = Box<dyn MasterPty + Send>;

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
        let reader = master
            .try_clone_reader()
            .context("failed to open the SSH PTY reader")?;
        let writer = master
            .take_writer()
            .context("failed to open the SSH PTY writer")?;
        let master = Arc::new(Mutex::new(master));
        Ok(Self {
            reader: ReaderStream::new(reader),
            writer: WriterStream::new(writer),
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
    pub async fn kill(self) -> Result<()> {
        let mut child = self.child;
        tokio::task::spawn_blocking(move || child.kill().context("failed to terminate SSH"))
            .await
            .context("SSH terminate task failed")?
    }

    pub async fn wait(self) -> Result<portable_pty::ExitStatus> {
        let mut child = self.child;
        tokio::task::spawn_blocking(move || child.wait().context("failed to wait for SSH"))
            .await
            .context("SSH wait task failed")?
    }
}

pub struct ReaderStream {
    reader: Arc<Mutex<Reader>>,
    pending: Option<JoinHandle<io::Result<Vec<u8>>>>,
    finished: bool,
}

impl ReaderStream {
    fn new(reader: Reader) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            pending: None,
            finished: false,
        }
    }
}

impl tokio::io::AsyncRead for ReaderStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        destination: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.finished {
            return std::task::Poll::Ready(Ok(()));
        }
        if self.pending.is_none() {
            let reader = Arc::clone(&self.reader);
            self.pending = Some(tokio::task::spawn_blocking(move || {
                let mut buffer = vec![0; 16 * 1024];
                let count = reader
                    .lock()
                    .map_err(|_| io::Error::other("SSH PTY reader lock poisoned"))?
                    .read(&mut buffer)?;
                buffer.truncate(count);
                Ok(buffer)
            }));
        }
        let pending = self.pending.as_mut().expect("pending PTY read");
        match std::pin::Pin::new(pending).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(result) => {
                self.pending = None;
                match result {
                    Ok(Ok(bytes)) => {
                        if bytes.is_empty() {
                            self.finished = true;
                        } else {
                            destination.put_slice(&bytes);
                        }
                        std::task::Poll::Ready(Ok(()))
                    }
                    Ok(Err(error)) => std::task::Poll::Ready(Err(error)),
                    Err(error) => std::task::Poll::Ready(Err(io::Error::other(error))),
                }
            }
        }
    }
}

pub struct WriterStream {
    writer: Arc<Mutex<Writer>>,
    pending: Option<JoinHandle<io::Result<usize>>>,
}

impl WriterStream {
    fn new(writer: Writer) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
            pending: None,
        }
    }

    fn poll_pending(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<usize>> {
        let pending = self.pending.as_mut().expect("pending PTY write");
        match std::pin::Pin::new(pending).poll(cx) {
            std::task::Poll::Pending => std::task::Poll::Pending,
            std::task::Poll::Ready(result) => {
                self.pending = None;
                match result {
                    Ok(result) => std::task::Poll::Ready(result),
                    Err(error) => std::task::Poll::Ready(Err(io::Error::other(error))),
                }
            }
        }
    }
}

impl tokio::io::AsyncWrite for WriterStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        if self.pending.is_some() {
            return self.poll_pending(cx);
        }
        let writer = Arc::clone(&self.writer);
        let bytes = bytes.to_vec();
        self.pending = Some(tokio::task::spawn_blocking(move || {
            writer
                .lock()
                .map_err(|_| io::Error::other("SSH PTY writer lock poisoned"))?
                .write(&bytes)
        }));
        self.poll_pending(cx)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        if self.pending.is_some() {
            match self.poll_pending(cx) {
                std::task::Poll::Ready(Ok(_)) => {}
                std::task::Poll::Ready(Err(error)) => return std::task::Poll::Ready(Err(error)),
                std::task::Poll::Pending => return std::task::Poll::Pending,
            }
        }
        let writer = Arc::clone(&self.writer);
        self.pending = Some(tokio::task::spawn_blocking(move || {
            writer
                .lock()
                .map_err(|_| io::Error::other("SSH PTY writer lock poisoned"))?
                .flush()
                .map(|()| 0)
        }));
        match self.poll_pending(cx) {
            std::task::Poll::Ready(Ok(_)) => std::task::Poll::Ready(Ok(())),
            std::task::Poll::Ready(Err(error)) => std::task::Poll::Ready(Err(error)),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::Poll::Ready(Ok(()))
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
