use super::*;
use output_support as out;
use std::process::Stdio;

fn large(action: &str, preview: bool) -> Value {
    let mut v = receipt(false, action, preview);
    v["data"]["changes"] = json!((0..1200)
        .map(|index| {
            let path = format!("sample/memory-{index:04}");
            json!({"path":path,"base":file(&path,b"private learned content"),"current":null})
        })
        .collect::<Vec<_>>());
    v
}
fn args(action: &str) -> Vec<&str> {
    let mut args = vec![action, "sample", "--account-id", ACCOUNT];
    if action == "restore" {
        args.extend(["--checkpoint", SECOND]);
    }
    args
}

#[test]
fn reset_restore_review_can_stop_without_confirming_or_journaling() {
    for action in ["reset", "restore"] {
        for json in [true, false] {
            let (url, server) = serve(vec![
                user(),
                (200, envelope(current(false))),
                (200, large(action, true)),
            ]);
            let home = home(&url);
            let (_master, slave) = out::terminal();
            let child = out::spawn(home.path(), &args(action), json, Stdio::from(slave));
            let output = out::interrupt_output(child, true);
            if json {
                assert_eq!(
                    json_output(&output, 130)["errors"][0]["code"],
                    "SKILL_INTERRUPTED"
                );
            } else {
                assert!(output.stdout.is_empty());
            }
            assert_eq!(out::count(home.path()), 0);
            let calls = server.join().unwrap();
            assert_eq!(calls.len(), 3);
            assert_eq!(body(&calls[2])["dry_run"], true);
        }
    }
}

#[test]
fn reset_restore_dry_run_and_committed_output_remain_interruptible() {
    for action in ["reset", "restore"] {
        for preview in [true, false] {
            for json in [true, false] {
                let mut responses = vec![
                    user(),
                    (200, envelope(current(false))),
                    (200, large(action, true)),
                ];
                if !preview {
                    responses.push((200, large(action, false)));
                }
                let (url, server) = serve(responses);
                let home = home(&url);
                let mut args = args(action);
                args.push(if preview { "--dry-run" } else { "--yes" });
                let child = out::spawn(home.path(), &args, json, Stdio::null());
                // Human committed receipts render their large diff table on stdout.
                let output = out::interrupt_output(child, !json && preview);
                assert!(!String::from_utf8_lossy(&output.stdout).contains("SKILL_INTERRUPTED"));
                if preview {
                    assert_eq!(out::count(home.path()), 0);
                } else {
                    out::received(home.path(), OP);
                }
                assert_eq!(server.join().unwrap().len(), if preview { 3 } else { 4 });
            }
        }
    }
}

#[test]
fn late_reset_restore_interruption_preserves_the_verified_receipt() {
    for action in ["reset", "restore"] {
        for json in [true, false] {
            let replies = vec![
                user(),
                (200, envelope(current(false))),
                (200, receipt(false, action, true)),
                (200, receipt(false, action, false)),
            ];
            let mut args = args(action);
            args.push("--yes");
            out::interrupt_receipt_write(replies, &args, OP, json);
        }
    }
}
