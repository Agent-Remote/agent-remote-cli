//! Actual HTTP streaming of binary state larger than a package file; no live source reads.

use agent_remote_cli::api::{
    skill_state::{ResolutionDomain, ResolutionTarget},
    ApiClient,
};
use agent_remote_cli::skills::state_snapshot::{CaptureCancellation, StateLimits, StateSnapshot};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::Arc,
};

const ID: &str = "11111111-1111-4111-8111-111111111111";
const UPLOAD: &str = "22222222-2222-4222-8222-222222222222";

#[tokio::test]
async fn streams_large_binary_from_private_snapshot_with_exact_length_digest_and_domain() {
    for kind in [ResolutionDomain::Publication, ResolutionDomain::Migration] {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("binary");
        let mut out = std::fs::File::create(&path).unwrap();
        let mut chunk = [b'x'; 65536];
        chunk[0] = 0;
        chunk[1] = 255;
        for _ in 0..193 {
            out.write_all(&chunk).unwrap();
        }
        drop(out);
        let snapshot = Arc::new(
            StateSnapshot::file(&path, StateLimits::ITEM, &CaptureCancellation::default()).unwrap(),
        );
        let entry = snapshot.manifest().entries[0].clone();
        std::fs::remove_file(path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let declared = entry.clone();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(10)))
                .unwrap();
            let mut headers = Vec::new();
            let mut byte = [0];
            while !headers.ends_with(b"\r\n\r\n") {
                assert!(headers.len() < 32768);
                stream.read_exact(&mut byte).unwrap();
                headers.push(byte[0]);
            }
            let headers = String::from_utf8(headers).unwrap();
            let prefix = if kind == ResolutionDomain::Migration {
                "migration/"
            } else {
                ""
            };
            assert!(headers.starts_with(&format!(
                "PUT /api/v1/skills/state/{prefix}conflicts/{ID}/uploads/{UPLOAD}/files/{} ",
                declared.sha256
            )));
            assert!(headers
                .to_ascii_lowercase()
                .contains(&format!("content-length: {}\r\n", declared.size)));
            assert!(headers
                .to_ascii_lowercase()
                .contains("authorization: bearer test-state-token\r\n"));
            let mut hash = Sha256::new();
            let mut left = declared.size;
            let mut buffer = [0; 16384];
            while left > 0 {
                let n = usize::try_from(left.min(buffer.len() as u64)).unwrap();
                stream.read_exact(&mut buffer[..n]).unwrap();
                hash.update(&buffer[..n]);
                left -= n as u64;
            }
            assert_eq!(format!("{:x}", hash.finalize()), declared.sha256);
            let body=json!({"schema_version":1,"status":"upload_pending","committed":false,"operation_id":null,"retryable":false,
                "data":{"upload_id":UPLOAD,"digest":declared.sha256,"created":true},"errors":[]}).to_string();
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let client = ApiClient::new(url).unwrap();
        let target = ResolutionTarget {
            kind,
            conflict_id: ID.into(),
        };
        let result = client
            .put_skill_resolution_file("test-state-token", &target, UPLOAD, snapshot, &entry.sha256)
            .await
            .unwrap();
        assert_eq!(result.status, "upload_pending");
        assert!(!result.committed);
        server.join().unwrap();
    }
}

#[tokio::test]
async fn invalid_scope_and_unknown_object_are_rejected_without_network() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("data"), b"x").unwrap();
    let snapshot = Arc::new(
        StateSnapshot::file(
            &root.path().join("data"),
            StateLimits::ITEM,
            &CaptureCancellation::default(),
        )
        .unwrap(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let client = ApiClient::new(format!("http://{}", listener.local_addr().unwrap())).unwrap();
    for conflict in [ID, "../uploads"] {
        let target = ResolutionTarget {
            kind: ResolutionDomain::Migration,
            conflict_id: conflict.into(),
        };
        let error = client
            .put_skill_resolution_file(
                "test",
                &target,
                UPLOAD,
                Arc::clone(&snapshot),
                &"f".repeat(64),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code(), Some("INVALID_SKILL_RESPONSE"));
    }
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}
