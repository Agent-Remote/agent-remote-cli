//! Cancellable terminal input; Tokio's stdin uses an uncancellable blocking read.
use anyhow::{Context, Result};
use std::{io, thread};
use tokio::sync::mpsc;

pub(super) struct StdinReader {
    pub(super) receiver: mpsc::Receiver<io::Result<Vec<u8>>>,
    thread: Option<thread::JoinHandle<()>>,
    #[cfg(windows)]
    console: std::sync::Arc<std::fs::File>,
    // Keep raw mode until the thread is joined, including attach cancellation.
    _raw_mode: std::sync::Arc<super::RawModeGuard>,
}

impl StdinReader {
    pub(super) fn spawn(raw_mode: std::sync::Arc<super::RawModeGuard>) -> Result<Self> {
        let (sender, receiver) = mpsc::channel(8);
        // Use a separate console open, not a duplicate of the process stdin
        // handle. Console read/cancellation state belongs to the open handle;
        // subsequent local readers must not inherit it after detach.
        #[cfg(windows)]
        let console = std::sync::Arc::new(
            std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open("CONIN$")
                .context("failed to open terminal input")?,
        );
        #[cfg(windows)]
        let reader_console = console.clone();
        let thread = thread::Builder::new()
            .name("agent-remote-stdin".into())
            .spawn(move || {
                #[cfg(windows)]
                read_input(sender, reader_console);
                #[cfg(unix)]
                read_input(sender);
            })
            .context("failed to start terminal input reader")?;
        Ok(Self {
            receiver,
            thread: Some(thread),
            #[cfg(windows)]
            console,
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
                use windows_sys::Win32::System::IO::{CancelIoEx, CancelSynchronousIo};
                // Repeat to cover cancellation racing the start of ReadConsole.
                // Unlike injecting a newline, this never becomes shell input.
                while !thread.is_finished() {
                    // SAFETY: the JoinHandle owns this live thread handle.
                    unsafe {
                        CancelIoEx(self.console.as_raw_handle(), std::ptr::null());
                        CancelSynchronousIo(thread.as_raw_handle());
                    };
                    thread::sleep(std::time::Duration::from_millis(5));
                }
            }
            // Unix poll wakes at least every 20 ms, even with stdin held open.
            let _ = thread.join();
        }
    }
}

#[cfg(unix)]
fn read_input(sender: mpsc::Sender<io::Result<Vec<u8>>>) {
    let mut buffer = [0u8; 8192];
    while !sender.is_closed() {
        let result = read_ready_input(&sender, &mut buffer);
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

#[cfg(windows)]
fn read_input(sender: mpsc::Sender<io::Result<Vec<u8>>>, console: std::sync::Arc<std::fs::File>) {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::System::Console::ReadConsoleW;
    let mut buffer = [0u16; 2048];
    let mut decoder = ConsoleUtf16::default();
    // Do not use std::io::stdin: it silently retries ReadConsoleW after a
    // successful zero-length read with ERROR_OPERATION_ABORTED, defeating
    // CancelIoEx and CancelSynchronousIo during detach.
    while !sender.is_closed() {
        let mut count = 0;
        // SAFETY: ReadConsoleW writes at most buffer.len() UTF-16 code units.
        let success = unsafe {
            ReadConsoleW(
                console.as_raw_handle(),
                buffer.as_mut_ptr().cast(),
                buffer.len() as u32,
                &mut count,
                std::ptr::null(),
            )
        };
        if sender.is_closed() {
            break;
        }
        if success == 0 {
            let _ = sender.blocking_send(Err(io::Error::last_os_error()));
            break;
        }
        if count == 0 {
            continue;
        }
        let bytes = decoder.feed(&buffer[..count as usize]);
        if !bytes.is_empty() && sender.blocking_send(Ok(bytes)).is_err() {
            break;
        }
    }
}

#[cfg(any(windows, test))]
#[derive(Default)]
struct ConsoleUtf16 {
    high_surrogate: Option<u16>,
}

#[cfg(any(windows, test))]
impl ConsoleUtf16 {
    fn feed(&mut self, input: &[u16]) -> Vec<u8> {
        let mut units: Vec<u16> = self
            .high_surrogate
            .take()
            .into_iter()
            .chain(input.iter().copied())
            .collect();
        if units
            .last()
            .is_some_and(|unit| (0xd800..=0xdbff).contains(unit))
        {
            self.high_surrogate = units.pop();
        }
        String::from_utf16_lossy(&units).into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::ConsoleUtf16;

    #[test]
    fn console_input_preserves_unicode_and_terminal_bytes_at_every_split() {
        let text = "中😀\u{2}d\u{1b}[<0;45;50m\u{16}";
        let units: Vec<_> = text.encode_utf16().collect();
        for split in 0..=units.len() {
            let mut decoder = ConsoleUtf16::default();
            let mut bytes = decoder.feed(&units[..split]);
            bytes.extend(decoder.feed(&units[split..]));
            assert_eq!(bytes, text.as_bytes());
        }
    }
}
