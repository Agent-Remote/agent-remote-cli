use super::*;
use tokio::io::AsyncWriteExt;

const WIRE: &[u8] = include_bytes!("../../../tests/fixtures/skill-node-export-v1.bin");

fn fixture() -> (Header, usize, usize) {
    let header_end = 12 + u32::from_be_bytes(WIRE[8..12].try_into().unwrap()) as usize;
    let header: Header = serde_json::from_slice(&WIRE[12..header_end]).unwrap();
    let footer_start = WIRE
        .windows(b"{\"version\":".len())
        .rposition(|window| window == b"{\"version\":")
        .unwrap()
        - 4;
    (header, header_end, footer_start)
}

#[tokio::test(start_paused = true)]
async fn stopped_tree_scans_may_exceed_object_idle_timeout() {
    let (header, _, footer_start) = fixture();
    let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
    let producer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(31)).await;
        source.write_all(&WIRE[..footer_start]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(31)).await;
        source.write_all(&WIRE[footer_start..]).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let (bundle, result) = tokio::time::timeout(
        Duration::from_secs(900),
        receive(&mut reader, &header.binding, output.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result.tree_digest, header.tree_digest);
    assert!(!output.exists());
    drop(bundle);
    producer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn object_stall_still_fails_without_publishing() {
    let (header, header_end, _) = fixture();
    let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
    source.write_all(&WIRE[..header_end]).await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let started = tokio::time::Instant::now();
    assert!(receive(&mut reader, &header.binding, output.clone())
        .await
        .is_err());
    assert!(started.elapsed() >= Duration::from_secs(30));
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test(start_paused = true)]
async fn scan_wait_retains_outer_deadline_and_cancellation() {
    let (header, _, _) = fixture();
    let (_source, mut reader) = tokio::io::duplex(64);
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    assert!(tokio::time::timeout(
        Duration::from_secs(60),
        receive(&mut reader, &header.binding, output.clone()),
    )
    .await
    .is_err());
    assert!(!output.exists());
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}

#[tokio::test(start_paused = true)]
async fn both_scan_phases_have_their_own_finite_deadline() {
    let (header, _, footer_start) = fixture();
    for final_scan in [false, true] {
        let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
        if final_scan {
            source.write_all(&WIRE[..footer_start]).await.unwrap();
        }
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("bundle");
        let started = tokio::time::Instant::now();
        assert!(receive(&mut reader, &header.binding, output.clone())
            .await
            .is_err());
        assert!(started.elapsed() >= SCAN_TIMEOUT);
        assert!(started.elapsed() < SCAN_TIMEOUT + Duration::from_secs(1));
        assert!(!output.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}

#[tokio::test(start_paused = true)]
async fn continuous_partial_reads_can_outlive_original_grant() {
    let (header, _, _) = fixture();
    let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
    let producer = tokio::spawn(async move {
        for block in WIRE.chunks(16) {
            tokio::time::sleep(Duration::from_secs(20)).await;
            source.write_all(block).await.unwrap();
        }
    });
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let started = tokio::time::Instant::now();
    let (bundle, result) = receive(&mut reader, &header.binding, output.clone())
        .await
        .unwrap();
    assert!(started.elapsed() > Duration::from_secs(900));
    assert_eq!(result.tree_digest, header.tree_digest);
    assert!(!output.exists());
    drop(bundle);
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    producer.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn scan_budget_ends_when_first_prefix_byte_arrives() {
    let (header, _, footer_start) = fixture();
    for prefix in [1, footer_start + 1] {
        let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
        source.write_all(&WIRE[..prefix]).await.unwrap();
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("bundle");
        let started = tokio::time::Instant::now();
        assert!(receive(&mut reader, &header.binding, output.clone())
            .await
            .is_err());
        assert!(started.elapsed() >= READ_IDLE_TIMEOUT);
        assert!(started.elapsed() < READ_IDLE_TIMEOUT + Duration::from_secs(1));
        assert!(!output.exists());
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
    }
}
