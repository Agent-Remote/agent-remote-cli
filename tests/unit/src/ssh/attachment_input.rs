// Tests for src/ssh/attachment_input.rs.

use super::*;
use crate::api::AttachSessionData;

fn context() -> AttachmentContext {
    let attach: AttachSessionData = serde_json::from_value(serde_json::json!({
        "session_id":"session", "node_id":"node", "node_wireguard_ip":"127.0.0.1",
        "ssh_host":"127.0.0.1", "ssh_port":22, "ssh_user":"test", "tmux_session_name":"tmux",
        "command_args":[], "ssh_command":"", "authorization_task_id":"task", "expires_in":30
    }))
    .unwrap();
    AttachmentContext::new(&attach, "/account".into(), "native").unwrap()
}

#[tokio::test]
async fn detach_cancels_pending_upload_without_enter_or_mouse_leakage() {
    let (send, mut receive) = tokio::sync::mpsc::channel(8);
    send.send(Ok(b"typed before detach".to_vec()))
        .await
        .unwrap();
    send.send(Ok(vec![2])).await.unwrap();
    send.send(Ok(b"d\x1b[<35;32;51M".to_vec())).await.unwrap();
    let attachment = context();
    let exit = exit::ExitState::default();
    let mut remote = Vec::new();
    let result = tokio::time::timeout(
        Duration::from_millis(200),
        InputQueue::default().upload(
            &mut remote,
            &mut receive,
            &exit,
            &attachment,
            std::future::pending(),
        ),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert_eq!(remote, b"\x02d");
    assert!(exit.started());
}

#[tokio::test]
async fn paste_completion_preserves_queued_typing_and_literal_paste_prefix() {
    let (send, mut receive) = tokio::sync::mpsc::channel(8);
    let typed = b"\x1b[200~\x02d\x1b[201~hello";
    send.send(Ok(typed.to_vec())).await.unwrap();
    let (complete, completed) = tokio::sync::oneshot::channel();
    let exit = exit::ExitState::default();
    let attachment = context();
    let mut remote = Vec::new();
    let mut queue = InputQueue::default();
    let operation = async {
        completed.await.unwrap();
        Ok(Some(vec!["/remote/image.png".into()]))
    };
    let upload = queue.upload(&mut remote, &mut receive, &exit, &attachment, operation);
    let result = tokio::time::timeout(Duration::from_secs(1), async {
        tokio::join!(upload, async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            complete.send(()).unwrap();
        })
        .0
    })
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, Some(vec!["/remote/image.png".into()]));
    assert_eq!(queue.deferred.pop_front().unwrap(), typed);
    assert!(remote.is_empty());
    assert!(!exit.started());
}
