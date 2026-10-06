//! Opt-in transfer against a logged-in device; never submits text to Claude.
use agent_remote_cli::{
    api::{ApiClient, AttachSessionData},
    attachments::{AttachmentContext, ClipboardPayload},
    auth::load_device_token,
    config::AppPaths,
};
use anyhow::{ensure, Context, Result};
use tokio::io::AsyncWriteExt;

#[tokio::test]
#[ignore = "requires AGENT_REMOTE_ATTACHMENT_TEST_SESSION and an authenticated device"]
async fn real_attachment_upload_and_cleanup() -> Result<()> {
    let session_id = std::env::var("AGENT_REMOTE_ATTACHMENT_TEST_SESSION")?;
    let paths = AppPaths::new(None)?;
    let (server, _, token) = load_device_token(&paths).await?;
    let client = ApiClient::new(server)?;
    let session = client.get_tool_session(&token, &session_id).await?;
    let binding = client
        .get_tool_account_binding_status(&token, &session.tool_account_id)
        .await?;
    let account = binding
        .account_remote_path
        .context("missing account path")?;
    let attach = client.attach_session(&token, &session_id).await?;
    let context = AttachmentContext::new(&attach, account.clone(), &session.runtime_backend)?;
    let local = tempfile::tempdir()?;
    let directory = local.path().join("中文 folder");
    std::fs::create_dir(&directory)?;
    std::fs::write(
        directory.join("space file.txt"),
        b"attachment integration test",
    )?;
    let mut uploaded = Vec::new();
    let result: Result<()> = async {
        let started = std::time::Instant::now();
        let files = context
            .stage_payload(&paths, ClipboardPayload::Files(vec![directory]))
            .await?;
        assert_eq!(files.len(), 1);
        assert!(!files[0].contains("/workspace/"));
        println!(
            "first_upload_seconds={:.3}",
            started.elapsed().as_secs_f64()
        );
        let repeated = std::time::Instant::now();
        let images = context
            .stage_payload(
                &paths,
                ClipboardPayload::Image {
                    bytes: b"\x89PNG\r\nfixture".to_vec(),
                    extension: "png",
                },
            )
            .await?;
        assert_eq!(images.len(), 1);
        println!(
            "reused_channel_upload_seconds={:.3}",
            repeated.elapsed().as_secs_f64()
        );
        uploaded.extend(files);
        uploaded.extend(images);
        verify_remote(&paths, &attach, &account, &uploaded, true).await?;
        // The receiver verifies the archive checksum and every extracted entry's CRC
        // before acknowledging either batch. Paths are deliberately never printed.
        println!(
            "image_and_directory_upload_seconds={:.3}",
            started.elapsed().as_secs_f64()
        );
        Ok(())
    }
    .await;
    let started = std::time::Instant::now();
    let cleanup = context.cleanup(&paths).await;
    println!("cleanup_seconds={:.3}", started.elapsed().as_secs_f64());
    if let Err(error) = &result {
        eprintln!("upload: {error:#}");
    }
    cleanup?;
    if !uploaded.is_empty() {
        verify_remote(&paths, &attach, &account, &uploaded, false).await?;
    }
    result
}

async fn verify_remote(
    paths: &AppPaths,
    attach: &AttachSessionData,
    account: &str,
    uploaded: &[String],
    present: bool,
) -> Result<()> {
    let mapped: Vec<_> = uploaded
        .iter()
        .map(|path| {
            path.strip_prefix("/account/")
                .map(|suffix| format!("{account}/{suffix}"))
                .unwrap_or_else(|| path.clone())
        })
        .collect();
    let source = r#"import json,sys,pathlib
request=json.loads(sys.stdin.buffer.read())
paths=[pathlib.Path(p) for p in request["paths"]]
if request["present"]:
    assert (paths[0]/"space file.txt").read_bytes()==b"attachment integration test"
    assert paths[1].read_bytes()==b"\x89PNG\r\nfixture"
else:
    assert all(not p.parent.parent.exists() for p in paths)
print("verified")
"#;
    // Use the same fixed stdin bootstrap as production to keep multiline code
    // and every path out of shell interpretation.
    let mut child = tokio::process::Command::new(agent_remote_cli::platform::ssh_binary())
        .args(["-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o"])
        .arg(format!("UserKnownHostsFile={}", paths.ssh_dir().join("known_hosts").display()))
        .arg("-p").arg(attach.ssh_port.to_string())
        .arg(format!("{}@{}", attach.ssh_user, attach.ssh_host))
        .arg(r#"python3 -c 'import sys; exec(compile(sys.stdin.buffer.read(int(sys.stdin.buffer.readline())), "verify", "exec"))'"#)
        .stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null())
        .kill_on_drop(true).spawn()?;
    let mut input = child.stdin.take().context("missing input")?;
    input
        .write_all(format!("{}\n", source.len()).as_bytes())
        .await?;
    input.write_all(source.as_bytes()).await?;
    input
        .write_all(&serde_json::to_vec(
            &serde_json::json!({"paths":mapped,"present":present}),
        )?)
        .await?;
    drop(input);
    let output = tokio::time::timeout(std::time::Duration::from_secs(20), child.wait_with_output())
        .await??;
    ensure!(
        output.status.success() && output.stdout == b"verified\n",
        "remote content/cleanup verification failed"
    );
    Ok(())
}
