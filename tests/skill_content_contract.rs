#![cfg(unix)]

#[path = "support/skill_cli.rs"]
mod support;

use agent_remote_cli::api::ApiClient;
use agent_remote_cli::skills::manifest::{ContentKind, Entry, EntryKind, Manifest};
use serde_json::json;
use sha2::{Digest, Sha256};
use support::*;

#[tokio::test]
async fn content_envelopes_allow_complete_manifests_above_metadata_query_limit() {
    let manifest = Manifest {
        version: 1,
        entries: (0..5000)
            .map(|i| Entry {
                path: format!("{}-{i:04}", "x".repeat(230)),
                kind: EntryKind::File,
                mode: 0o644,
                size: 0,
                sha256: format!("{:x}", Sha256::digest(b"")),
                target: String::new(),
                content_kind: ContentKind::Text,
                dependency: String::new(),
            })
            .collect(),
    };
    let digest = manifest.digest().unwrap();
    let mut response = envelope(json!({"id":OP,"status":"staged","tree_digest":digest,
        "manifest":manifest,"reserved_bytes":0,"expires_at":"2099-01-01T00:00:00Z"}));
    response["status"] = json!("staged");
    assert!(response.to_string().len() > 1024 * 1024);
    let (url, server) = serve(vec![(200, response)]);
    let client = ApiClient::new(url).unwrap();
    let result = client
        .begin_skill_upload("skill-user-token", "manifest-key", &manifest)
        .await
        .unwrap();
    assert_eq!(result.data.unwrap().manifest, manifest);
    let requests = server.join().unwrap();
    assert!(requests[0]
        .to_ascii_lowercase()
        .contains("authorization: bearer skill-user-token"));
}

#[tokio::test]
async fn content_response_length_is_still_bounded_before_reading_body() {
    use std::io::Write;
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        request(&mut stream);
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            64 * 1024 * 1024 + 1
        )
        .unwrap();
    });
    let manifest = Manifest {
        version: 1,
        entries: vec![],
    };
    let client = ApiClient::new(url).unwrap();
    let error = client
        .begin_skill_upload("skill-user-token", "manifest-key", &manifest)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("safety limit"));
    server.join().unwrap();
}
