//! Readiness-driven PTY I/O: typing and redraws never queue behind blocking jobs.
use anyhow::{Context, Result};
use portable_pty::MasterPty;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context as TaskContext, Poll};
use tokio::io::{unix::AsyncFd, AsyncRead, AsyncWrite, ReadBuf};

pub(super) fn streams(master: &dyn MasterPty) -> Result<(ReaderStream, WriterStream)> {
    let raw = master
        .as_raw_fd()
        .context("SSH PTY has no file descriptor")?;
    // SAFETY: master owns this descriptor throughout the duplication. The new
    // owned descriptor has CLOEXEC and outlives the borrowed master independently.
    let fd = unsafe { BorrowedFd::borrow_raw(raw) }
        .try_clone_to_owned()
        .context("failed to duplicate the SSH PTY")?;
    // Nonblocking flags are shared by master duplicates, but never by the slave
    // terminal inherited by SSH. The remaining master only performs resize ioctls.
    // SAFETY: fd is owned and both fcntl commands use their documented arguments.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error()).context("failed to make the SSH PTY nonblocking");
    }
    let fd = Arc::new(AsyncFd::new(fd).context("failed to register SSH PTY readiness")?);
    Ok((
        ReaderStream {
            fd: fd.clone(),
            finished: false,
        },
        WriterStream { fd },
    ))
}

pub struct ReaderStream {
    fd: Arc<AsyncFd<OwnedFd>>,
    finished: bool,
}

impl AsyncRead for ReaderStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        destination: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.finished || destination.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            let result = {
                let mut guard = ready!(self.fd.poll_read_ready(cx))?;
                guard.try_io(|fd| {
                    let buffer = destination.initialize_unfilled();
                    // SAFETY: the owned descriptor is live; buffer is writable
                    // for exactly buffer.len() bytes. O_NONBLOCK bounds this call.
                    let count = unsafe {
                        libc::read(fd.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len())
                    };
                    if count < 0 {
                        let error = io::Error::last_os_error();
                        // Linux reports EIO when the last slave closes; BSD/macOS
                        // report EOF. Match the portable PTY adapter on both.
                        if error.raw_os_error() == Some(libc::EIO) {
                            return Ok(0);
                        }
                        return Err(error);
                    }
                    Ok(count as usize)
                })
            };
            match result {
                Ok(Ok(count)) => {
                    self.finished = count == 0;
                    destination.advance(count);
                    return Poll::Ready(Ok(()));
                }
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(Err(error)) => return Poll::Ready(Err(error)),
                Err(_) => continue, // WouldBlock cleared readiness; wait for a new event.
            }
        }
    }
}

pub struct WriterStream {
    fd: Arc<AsyncFd<OwnedFd>>,
}

impl AsyncWrite for WriterStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        loop {
            let mut guard = ready!(self.fd.poll_write_ready(cx))?;
            match guard.try_io(|fd| {
                // SAFETY: the owned descriptor is live and bytes is readable
                // for bytes.len() bytes. O_NONBLOCK bounds the syscall.
                let count =
                    unsafe { libc::write(fd.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
                if count < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(count as usize)
                }
            }) {
                Ok(Err(error)) if error.kind() == io::ErrorKind::Interrupted => continue,
                Ok(result) => return Poll::Ready(result),
                Err(_) => continue,
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        // Writes go straight to the PTY; there is no userspace buffer to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(cx)
    }
}
