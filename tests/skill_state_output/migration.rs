use super::*;
use output_support as out;
use std::process::Stdio;

fn large(preview: bool) -> Value {
    let mut v = view(preview, true);
    v["data"]["conflicts"] = json!((0..1600)
        .map(|i| json!({"path":format!("sample/memory-{i:04}"),"reason":"changed_both","unit":[]}))
        .collect::<Vec<_>>());
    v
}
fn args() -> Vec<&'static str> {
    vec![
        "migrate",
        "sample",
        "--account-id",
        ACCOUNT,
        "--from-revision",
        "r1",
        "--to-revision",
        "r2",
    ]
}
#[test]
fn migration_review_stops_without_confirmation_or_submission() {
    for json in [true, false] {
        let (url, server) = serve(vec![user(), (200, envelope(current())), (200, large(true))]);
        let home = home(&url);
        let (_master, slave) = out::terminal();
        let child = out::spawn(home.path(), &args(), json, Stdio::from(slave));
        let output = out::interrupt_output(child, true);
        if json {
            assert_eq!(json_output(&output, 130)["committed"], false);
        } else {
            assert!(output.stdout.is_empty());
        }
        assert_eq!(out::count(home.path()), 0);
        let calls = server.join().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(body(&calls[2])["dry_run"], true);
    }
}
#[test]
fn migration_dry_run_and_saved_conflict_output_remain_interruptible() {
    for preview in [true, false] {
        for json in [true, false] {
            let mut responses = vec![user(), (200, envelope(current())), (200, large(true))];
            if !preview {
                responses.push((200, large(false)));
            }
            let (url, server) = serve(responses);
            let home = home(&url);
            let mut args = args();
            args.push(if preview { "--dry-run" } else { "--yes" });
            let child = out::spawn(home.path(), &args, json, Stdio::null());
            let output = out::interrupt_output(child, !json);
            assert!(!String::from_utf8_lossy(&output.stdout).contains("SKILL_INTERRUPTED"));
            if preview {
                assert_eq!(out::count(home.path()), 0);
            } else {
                out::received(home.path(), SKILL);
            }
            assert_eq!(server.join().unwrap().len(), if preview { 3 } else { 4 });
        }
    }
}

#[test]
fn late_migration_interruption_preserves_the_verified_receipt() {
    for json in [true, false] {
        let mut replies = reads(false);
        replies.push((200, view(false, false)));
        let mut args = args();
        args.push("--yes");
        out::interrupt_receipt_write(replies, &args, SKILL, json);
    }
}
