//! Cancellable terminal input; Tokio's stdin uses an uncancellable blocking read.
use anyhow::{Context, Result};
use std::{io, thread};
use tokio::sync::mpsc;

pub(super) struct StdinReader {
    receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    thread: Option<thread::JoinHandle<()>>,
    // Keep raw mode until the thread is joined, including attach cancellation.
    _raw_mode: std::sync::Arc<super::RawModeGuard>,
}

impl StdinReader {
    pub(super) fn spawn(raw_mode: std::sync::Arc<super::RawModeGuard>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(8);
        let thread = thread::Builder::new()
            .name("agent-remote-stdin".into())
            .spawn(move || read_input(sender))
            .context("failed to start terminal input reader")?;
        Ok(Self {
            receiver,
            thread: Some(thread),
            _raw_mode: raw_mode,
        })
    }

    pub(super) async fn recv(&mut self) -> Result<Option<Vec<u8>>> {
        self.receiver.recv().await.transpose().map_err(Into::into)
    }
}

impl Drop for StdinReader {
    fn drop(&mut self) {
        // Also wakes a producer blocked on a full queue.
        self.receiver.close();
        if let Some(thread) = self.thread.take() {
            #[cfg(windows)]
            {
                use std::os::windows::io::AsRawHandle;
                use windows_sys::Win32::System::IO::CancelSynchronousIo;
                // Repeat to cover cancellation racing the start of ReadConsole.
                // Unlike injecting a newline, this never becomes shell input.
                while !thread.is_finished() {
                    // SAFETY: the JoinHandle owns this live thread handle.
                    unsafe { CancelSynchronousIo(thread.as_raw_handle()) };
                    thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            // Unix poll wakes at least every 20 ms, even with stdin held open.
            let _ = thread.join();
        }
    }
}

fn read_input(sender: mpsc::Sender<io::Result<Vec<u8>>>) {
    #[cfg(windows)]
    use std::io::Read;
    #[cfg(windows)]
    let mut stdin = std::io::stdin();
    let mut buffer = [0u8; 8192];
    while !sender.is_closed() {
        #[cfg(unix)]
        let result = read_ready_input(&sender, &mut buffer);
        #[cfg(windows)]
        let result = stdin.read(&mut buffer);
        match result {
            Ok(0) => break,
            Ok(count) => {
                if sender.blocking_send(Ok(buffer[..count].to_vec())).is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                let _ = sender.blocking_send(Err(error));
                break;
            }
        }
    }
}

#[cfg(unix)]
fn read_ready_input(
    sender: &mpsc::Sender<io::Result<Vec<u8>>>,
    buffer: &mut [u8],
) -> io::Result<usize> {
    let mut fd = libc::pollfd {
        fd: libc::STDIN_FILENO,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        if sender.is_closed() {
            return Ok(0);
        }
        // SAFETY: poll receives one initialized descriptor; it does not own it.
        let ready = unsafe { libc::poll(&mut fd, 1, 20) };
        if ready < 0 {
            return Err(io::Error::last_os_error());
        }
        if ready == 0 {
            continue;
        }
        if sender.is_closed() {
            return Ok(0);
        }
        // Only this reader consumes stdin during attach. Raw mode is enabled
        // before it starts and remains enabled until this thread has joined.
        // SAFETY: buffer is writable for its full length and stdin is borrowed.
        let count = unsafe { libc::read(fd.fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        return if count < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(count as usize)
        };
    }
}
