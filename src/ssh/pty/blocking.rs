//! Blocking ConPTY adapter, also exercised by platform-independent tests.
use std::future::Future;
use std::io::{self, Read, Write};
use std::sync::{Arc, Mutex};
use tokio::task::JoinHandle;

type Reader = Box<dyn Read + Send>;
type Writer = Box<dyn Write + Send>;

pub struct ReaderStream {
    reader: Arc<Mutex<Reader>>,
    pending: Option<JoinHandle<io::Result<Vec<u8>>>>,
    buffered: io::Cursor<Vec<u8>>,
    finished: bool,
}

impl ReaderStream {
    pub(super) fn new(reader: Reader) -> Self {
        Self {
            reader: Arc::new(Mutex::new(reader)),
            pending: None,
            buffered: io::Cursor::new(Vec::new()),
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
        if self.finished || destination.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        if self.buffered.position() < self.buffered.get_ref().len() as u64 {
            let count = self.buffered.read(destination.initialize_unfilled())?;
            destination.advance(count);
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
                            // The caller can change buffer sizes after a pending
                            // read. Preserve read-ahead instead of overflowing it.
                            self.buffered = io::Cursor::new(bytes);
                            let count = self.buffered.read(destination.initialize_unfilled())?;
                            destination.advance(count);
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
    flushing: Option<JoinHandle<io::Result<()>>>,
}

impl WriterStream {
    pub(super) fn new(writer: Writer) -> Self {
        Self {
            writer: Arc::new(Mutex::new(writer)),
            pending: None,
            flushing: None,
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

    fn poll_flushing(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let Some(flushing) = self.flushing.as_mut() else {
            return std::task::Poll::Ready(Ok(()));
        };
        let result = std::task::ready!(std::pin::Pin::new(flushing).poll(cx));
        self.flushing = None;
        std::task::Poll::Ready(result.map_err(io::Error::other)?)
    }
}

impl tokio::io::AsyncWrite for WriterStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bytes: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // A cancelled flush future still owns a blocking operation. Finish it
        // before writing, without treating its completion as a zero-byte write.
        std::task::ready!(self.poll_flushing(cx))?;
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
        if self.flushing.is_none() {
            let writer = Arc::clone(&self.writer);
            self.flushing = Some(tokio::task::spawn_blocking(move || {
                writer
                    .lock()
                    .map_err(|_| io::Error::other("SSH PTY writer lock poisoned"))?
                    .flush()
            }));
        }
        // Re-poll the same flush until it completes; starting another one here
        // can indefinitely stall the next keystroke behind flush().await.
        self.poll_flushing(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
