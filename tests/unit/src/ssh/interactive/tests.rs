use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

fn selection(text: &str) -> Vec<u8> {
    format!("\x1b]52;c;{}\x07", STANDARD.encode(text)).into_bytes()
}

#[tokio::test]
async fn eof_waits_for_slow_copy_and_the_latest_pending_selection() {
    let (mut sender, mut reader) = tokio::io::duplex(4096);
    let copied = Arc::new(Mutex::new(Vec::new()));
    let recorded = copied.clone();
    let started = Arc::new(tokio::sync::Notify::new());
    let producer_start = started.clone();
    let producer = tokio::spawn(async move {
        sender.write_all(&selection("first")).await.unwrap();
        producer_start.notified().await;
        sender.write_all(&selection("second")).await.unwrap();
        sender
            .write_all(&selection("最后选择\n  code"))
            .await
            .unwrap();
        // Drop SSH output while the first native helper is still running.
    });
    let mut visible = Vec::new();
    let feedback = observe(
        &mut reader,
        &mut visible,
        false,
        true,
        || (24, 80),
        move |text| {
            let copied = recorded.clone();
            let started = started.clone();
            async move {
                started.notify_one();
                tokio::time::sleep(Duration::from_millis(100)).await;
                copied.lock().unwrap().push(text);
                CopyResult::Native
            }
        },
        None,
    )
    .await
    .unwrap();
    producer.await.unwrap();
    assert_eq!(*copied.lock().unwrap(), ["first", "最后选择\n  code"]);
    assert!(visible.is_empty());
    assert!(!feedback.incomplete);
    assert_eq!(feedback.native_copy, Some(true));
}

#[tokio::test(start_paused = true)]
async fn hung_copy_is_cancelled_at_the_shutdown_deadline() {
    let bytes = selection("bounded wait");
    let mut reader = bytes.as_slice();
    let mut visible = Vec::new();
    let started = tokio::time::Instant::now();
    let feedback = observe(
        &mut reader,
        &mut visible,
        false,
        true,
        || (24, 80),
        |_| async { std::future::pending::<CopyResult>().await },
        None,
    )
    .await
    .unwrap();
    assert!(feedback.incomplete);
    assert_eq!(feedback.native_copy, None);
    assert_eq!(started.elapsed(), Duration::from_secs(3));
}

#[tokio::test]
async fn rejected_selection_alerts_without_rendering_content_or_copying_it() {
    let bytes = selection(&"x".repeat(65537));
    let mut reader = bytes.as_slice();
    let mut visible = Vec::new();
    let feedback = observe(
        &mut reader,
        &mut visible,
        false,
        true,
        || (24, 80),
        |_| async { panic!("invalid selection must never reach clipboard") },
        None,
    )
    .await
    .unwrap();
    assert!(feedback.incomplete);
    assert_eq!(visible, b"\x07");
}

#[tokio::test]
async fn terminal_fallback_is_flushed_even_when_ssh_has_already_exited() {
    let bytes = selection("text");
    let mut reader = bytes.as_slice();
    let mut visible = Vec::new();
    let feedback = observe(
        &mut reader,
        &mut visible,
        false,
        true,
        || (24, 80),
        |_| async {
            tokio::task::yield_now().await;
            CopyResult::Terminal("fallback".into())
        },
        None,
    )
    .await
    .unwrap();
    assert_eq!(visible, b"fallback");
    assert_eq!(feedback.native_copy, Some(false));
}
