use super::blocking::WriterStream as BlockingWriterStream;
use super::*;
use std::io::{self, Write};
use std::sync::mpsc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

#[tokio::test]
async fn blocking_reader_preserves_redraw_bytes_with_small_read_buffers() {
    use tokio::io::AsyncReadExt;
    let expected = "\x1b[2J\x1b[H滚动内容\r\n\x1b[31mline\x1b[0m".as_bytes();
    let mut reader = blocking::ReaderStream::new(Box::new(io::Cursor::new(expected.to_vec())));
    assert_eq!(reader.read(&mut []).await.unwrap(), 0);
    let mut received = Vec::new();
    let mut byte = [0];
    while reader.read(&mut byte).await.unwrap() != 0 {
        received.push(byte[0]);
    }
    assert_eq!(received, expected);
}

struct ControlledWriter {
    events: Arc<Mutex<Vec<Vec<u8>>>>,
    started: Option<tokio::sync::oneshot::Sender<()>>,
    release: mpsc::Receiver<()>,
    fail_flush: bool,
}

impl Write for ControlledWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.events.lock().unwrap().push(bytes.to_vec());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(started) = self.started.take() {
            let _ = started.send(());
            self.release
                .recv_timeout(Duration::from_secs(5))
                .map_err(io::Error::other)?;
        }
        let mut events = self.events.lock().unwrap();
        if events.last().is_some_and(Vec::is_empty) {
            return Err(io::Error::other("flush repeated without new input"));
        }
        events.push(Vec::new());
        if self.fail_flush {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed PTY"))
        } else {
            Ok(())
        }
    }
}

struct Fixture {
    stream: BlockingWriterStream,
    events: Arc<Mutex<Vec<Vec<u8>>>>,
    started: tokio::sync::oneshot::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn fixture(fail_flush: bool) -> Fixture {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started) = tokio::sync::oneshot::channel();
    let (release, receiver) = mpsc::channel();
    let stream = BlockingWriterStream::new(Box::new(ControlledWriter {
        events: events.clone(),
        started: Some(started_tx),
        release: receiver,
        fail_flush,
    }));
    Fixture {
        stream,
        events,
        started,
        release,
    }
}

#[tokio::test]
async fn completed_pending_flush_allows_the_next_keystroke() {
    let mut fixture = fixture(false);
    fixture.stream.write_all(b"a").await.unwrap();
    let flush = fixture.stream.flush();
    tokio::pin!(flush);
    tokio::select! {
        result = &mut flush => panic!("flush completed before release: {result:?}"),
        result = &mut fixture.started => result.unwrap(),
    }
    fixture.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), flush)
        .await
        .expect("flush must finish when its blocking operation completes")
        .unwrap();
    fixture.stream.write_all(b"b").await.unwrap();
    fixture.stream.flush().await.unwrap();
    assert_eq!(
        *fixture.events.lock().unwrap(),
        vec![b"a".to_vec(), vec![], b"b".to_vec(), vec![]]
    );
}

#[tokio::test]
async fn input_after_cancelled_flush_is_written_and_shutdown_flushes_it() {
    let mut fixture = fixture(false);
    fixture.stream.write_all(b"a").await.unwrap();
    {
        let flush = fixture.stream.flush();
        tokio::pin!(flush);
        tokio::select! {
            result = &mut flush => panic!("flush completed before release: {result:?}"),
            result = &mut fixture.started => result.unwrap(),
        }
        // Drop the future while the blocking flush is still running.
    }
    fixture.release.send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(2), fixture.stream.write_all(b"b"))
        .await
        .expect("input must resume after the cancelled flush completes")
        .unwrap();
    fixture.stream.shutdown().await.unwrap();
    assert_eq!(
        *fixture.events.lock().unwrap(),
        vec![b"a".to_vec(), vec![], b"b".to_vec(), vec![]]
    );
}

#[tokio::test]
async fn pending_flush_failure_is_reported_without_retrying() {
    let mut fixture = fixture(true);
    fixture.stream.write_all(b"a").await.unwrap();
    let flush = fixture.stream.flush();
    tokio::pin!(flush);
    tokio::select! {
        result = &mut flush => panic!("flush completed before release: {result:?}"),
        result = &mut fixture.started => result.unwrap(),
    }
    fixture.release.send(()).unwrap();
    let error = tokio::time::timeout(Duration::from_secs(2), flush)
        .await
        .unwrap()
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
    assert_eq!(*fixture.events.lock().unwrap(), vec![b"a".to_vec(), vec![]]);
}

#[cfg(unix)]
#[tokio::test]
async fn real_pty_forwards_repeated_keystrokes_without_stalling() {
    use tokio::io::AsyncReadExt;
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "stty raw -echo && printf READY && exec cat"]);
    let session = Session::spawn(&command, PtySize::default()).unwrap();
    let (mut output, mut input, resize, child) = session.parts();
    let mut killer = child.killer();
    let result = tokio::time::timeout(Duration::from_secs(5), async {
        let mut buffer = [0; 16384];
        let mut ready = Vec::new();
        while ready.len() < 5 {
            let count = output.read(&mut buffer).await?;
            if count == 0 {
                return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
            }
            ready.extend_from_slice(&buffer[..count]);
        }
        if ready != b"READY" {
            return Err(io::Error::other("unexpected PTY readiness output"));
        }
        let mut elapsed = Vec::new();
        for byte in b"abcdefghijklmnopqrstuvwxyz0123456789" {
            let started = std::time::Instant::now();
            input.write_all(&[*byte]).await?;
            input.flush().await?;
            let count = output.read(&mut buffer).await?;
            if buffer[..count] != [*byte] {
                return Err(io::Error::other("keystroke was changed or lost"));
            }
            elapsed.push(started.elapsed());
        }
        Ok::<_, io::Error>(elapsed)
    })
    .await;
    // Reap the local echo process even when the relay times out.
    let _ = killer.kill();
    drop((input, output, resize));
    child.wait().await.unwrap();
    let mut elapsed = result.expect("local PTY input stalled").unwrap();
    let first = elapsed[0];
    elapsed.sort();
    eprintln!(
        "local PTY echo: first={first:?}, median={:?}, max={:?}",
        elapsed[elapsed.len() / 2],
        elapsed.last().unwrap()
    );
}

#[cfg(unix)]
#[test]
fn terminal_io_stays_responsive_when_blocking_workers_are_busy() {
    use tokio::io::AsyncReadExt;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .max_blocking_threads(2)
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.args(["-c", "stty raw -echo && printf READY && exec cat"]);
        let session = Session::spawn(&command, PtySize::default()).unwrap();
        let (mut output, mut input, resize, child) = session.parts();
        let mut killer = child.killer();
        let (started, mut ready) = tokio::sync::mpsc::unbounded_channel();
        let mut releases = Vec::new();
        let mut workers = Vec::new();
        let result = tokio::time::timeout(Duration::from_secs(5), async {
            let mut buffer = [0; 16384];
            let count = output.read(&mut buffer).await?;
            if &buffer[..count] != b"READY" {
                return Err(io::Error::other("unexpected PTY readiness output"));
            }
            for _ in 0..2 {
                let (release, held) = mpsc::channel::<()>();
                releases.push(release);
                let started = started.clone();
                workers.push(tokio::task::spawn_blocking(move || {
                    started.send(()).unwrap();
                    let _ = held.recv_timeout(Duration::from_secs(5));
                }));
            }
            ready.recv().await.unwrap();
            ready.recv().await.unwrap();
            tokio::time::timeout(Duration::from_millis(250), async {
                input.write_all(b"\x1b[<64;20;10M").await?;
                input.flush().await?;
                let count = output.read(&mut buffer).await?;
                if &buffer[..count] != b"\x1b[<64;20;10M" {
                    return Err(io::Error::other("wheel event changed or lost"));
                }
                Ok::<_, io::Error>(())
            })
            .await
            .map_err(io::Error::other)?
        })
        .await;
        drop(releases);
        for worker in workers {
            worker.await.unwrap();
        }
        let _ = killer.kill();
        drop((input, output, resize));
        child.wait().await.unwrap();
        result
            .unwrap()
            .expect("terminal I/O waited for unrelated blocking work");
    });
}

#[cfg(unix)]
#[tokio::test]
async fn real_pty_preserves_scroll_bursts_under_backpressure_and_reports_eof() {
    use tokio::io::AsyncReadExt;
    let mut command = tokio::process::Command::new("/bin/sh");
    command.args(["-c", "stty raw -echo && printf READY && exec cat"]);
    let session = Session::spawn(&command, PtySize::default()).unwrap();
    let (mut output, mut input, resize, child) = session.parts();
    let mut killer = child.killer();
    let payload = "\x1b[<64;20;10M\x1b[<65;20;10M\x1b[H\x1b[32m滚动内容\x1b[0m\r\n"
        .repeat(8192)
        .into_bytes();
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        assert_eq!(output.read(&mut []).await?, 0);
        let mut ready = [0; 5];
        output.read_exact(&mut ready).await?;
        if &ready != b"READY" {
            return Err(io::Error::other("unexpected PTY readiness output"));
        }
        let send = async {
            input.write_all(&payload).await?;
            input.flush().await
        };
        let receive = async {
            let mut received = Vec::new();
            let mut chunk = [0; 113];
            while received.len() < payload.len() {
                let count = output.read(&mut chunk).await?;
                if count == 0 {
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof));
                }
                received.extend_from_slice(&chunk[..count]);
            }
            if received != payload {
                return Err(io::Error::other("scroll burst was reordered or corrupted"));
            }
            Ok(())
        };
        tokio::try_join!(send, receive)?;
        Ok::<_, io::Error>(())
    })
    .await;
    let _ = killer.kill();
    child.wait().await.unwrap();
    let mut byte = [0];
    let eof = tokio::time::timeout(Duration::from_secs(2), output.read(&mut byte)).await;
    drop((input, output, resize));
    result.expect("scroll burst stalled").unwrap();
    assert_eq!(eof.unwrap().unwrap(), 0);
}
