use super::*;
use crate::api::skill_node_export::stream;
use serde_json::{json, Value};
use std::time::Duration;
use tokio::io::AsyncWriteExt;

const WIRE: &[u8] = include_bytes!("../../../../fixtures/skill-node-recovery-v1.bin");

fn fixture() -> (Header, usize, usize) {
    let header_end = 12 + u32::from_be_bytes(WIRE[8..12].try_into().unwrap()) as usize;
    let header = serde_json::from_slice(&WIRE[12..header_end]).unwrap();
    let entry_end = header_end
        + 4
        + u32::from_be_bytes(WIRE[header_end..header_end + 4].try_into().unwrap()) as usize;
    (header, header_end, entry_end)
}

#[tokio::test]
async fn recovery_fixture_matches_node_and_publishes_distinct_complete_bundle() {
    let (header, _, _) = fixture();
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("bundle");
    let mut reader = WIRE;
    let (bundle, result) = stream::receive(&mut reader, &header.binding, output.clone())
        .await
        .unwrap();
    assert!(!output.exists());
    assert_eq!(result.format, FORMAT);
    assert_eq!(result.tree_digest, header.recovery_digest);
    assert_eq!(result.file_objects, 3);
    assert_eq!(
        bundle.publish().unwrap(),
        directory.path().canonicalize().unwrap().join("bundle")
    );
    assert!(!output.join("manifest.json").exists());
    assert_eq!(
        std::fs::read_dir(output.join("entries")).unwrap().count(),
        3
    );
    assert_eq!(
        std::fs::read_dir(output.join("objects")).unwrap().count(),
        2
    );
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(output.join("checkpoint.json")).unwrap()).unwrap();
    assert_eq!(metadata["format"], FORMAT);
    assert_eq!(metadata["recovery_digest"], header.recovery_digest);
    assert_eq!(metadata["file_bytes"], 17);
}

#[tokio::test]
async fn recovery_rejects_corrupt_partial_and_trailing_streams_without_staging() {
    let (header, header_end, entry_end) = fixture();
    for kind in [
        "header",
        "entry",
        "body",
        "hash",
        "footer",
        "trailing",
        "duplicate_path",
        "unknown_entry_field",
    ] {
        let mut wire = WIRE.to_vec();
        match kind {
            "header" => wire.truncate(header_end - 1),
            "entry" => wire.truncate(entry_end - 1),
            "body" => wire[entry_end] ^= 1,
            "hash" => {
                let position = wire[entry_end..]
                    .windows(10)
                    .position(|b| b == b"\"sha256\":\"")
                    .unwrap()
                    + entry_end
                    + 10;
                wire[position] = b'g';
            }
            "footer" => {
                wire.pop();
            }
            "trailing" => wire.push(1),
            "duplicate_path" => {
                let position = wire
                    .windows(10)
                    .position(|b| b == b"\"path\":\"b\"")
                    .unwrap()
                    + 8;
                wire[position] = b'a';
            }
            "unknown_entry_field" => {
                let mut entry: Value =
                    serde_json::from_slice(&wire[header_end + 4..entry_end]).unwrap();
                entry["extra"] = json!(true);
                let data = serde_json::to_vec(&entry).unwrap();
                wire.splice(
                    header_end..entry_end,
                    (data.len() as u32).to_be_bytes().into_iter().chain(data),
                );
            }
            _ => unreachable!(),
        }
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("bundle");
        assert!(
            stream::receive(&mut wire.as_slice(), &header.binding, output.clone())
                .await
                .is_err(),
            "{kind}"
        );
        assert!(!output.exists());
        assert_eq!(
            std::fs::read_dir(directory.path()).unwrap().count(),
            0,
            "{kind}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn recovery_keeps_scan_waits_and_byte_progress_bounds() {
    let (header, _, entry_end) = fixture();
    let footer_start = WIRE
        .windows(11)
        .rposition(|b| b == b"{\"version\":")
        .unwrap()
        - 4;
    let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
    let producer = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(31)).await;
        source.write_all(&WIRE[..footer_start]).await.unwrap();
        tokio::time::sleep(Duration::from_secs(31)).await;
        source.write_all(&WIRE[footer_start..]).await.unwrap();
    });
    let directory = tempfile::tempdir().unwrap();
    let (bundle, _) = stream::receive(
        &mut reader,
        &header.binding,
        directory.path().join("bundle"),
    )
    .await
    .unwrap();
    drop(bundle);
    producer.await.unwrap();

    let (mut source, mut reader) = tokio::io::duplex(WIRE.len());
    source.write_all(&WIRE[..entry_end]).await.unwrap();
    let started = tokio::time::Instant::now();
    assert!(stream::receive(
        &mut reader,
        &header.binding,
        directory.path().join("bundle")
    )
    .await
    .is_err());
    assert!(started.elapsed() >= Duration::from_secs(30));
    assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 0);
}
