use super::*;
use std::sync::mpsc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

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
    stream: WriterStream,
    events: Arc<Mutex<Vec<Vec<u8>>>>,
    started: tokio::sync::oneshot::Receiver<()>,
    release: mpsc::Sender<()>,
}

fn fixture(fail_flush: bool) -> Fixture {
    let events = Arc::new(Mutex::new(Vec::new()));
    let (started_tx, started) = tokio::sync::oneshot::channel();
    let (release, receiver) = mpsc::channel();
    let stream = WriterStream::new(Box::new(ControlledWriter {
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
