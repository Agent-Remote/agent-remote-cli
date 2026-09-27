use super::*;
use output_support as out;
use std::process::Stdio;

fn large(migration: bool, preview: bool) -> Value {
    let mut v = resolution(migration, side(Some("sample/memory")), preview, false);
    v["data"]["remaining"] = json!((0..1600)
        .map(|i| json!({"path":format!("sample/other-{i:04}"),"reason":"changed_both","unit":[]}))
        .collect::<Vec<_>>());
    v
}
fn args() -> Vec<&'static str> {
    vec![
        "resolve",
        OP,
        "--path",
        "sample/memory",
        "--use",
        "incoming",
    ]
}
#[test]
fn resolution_review_stops_without_saving_a_choice() {
    for migration in [true, false] {
        for json in [true, false] {
            let mut replies = reads(migration);
            replies.push((200, large(migration, true)));
            let expected = replies.len();
            let (url, server) = serve(replies);
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
            assert_eq!(calls.len(), expected);
            assert_eq!(body(calls.last().unwrap())["dry_run"], true);
        }
    }
}
#[test]
fn resolution_dry_run_and_accepted_choice_output_remain_interruptible() {
    for migration in [true, false] {
        for preview in [true, false] {
            for json in [true, false] {
                let mut replies = reads(migration);
                replies.push((200, large(migration, true)));
                if !preview {
                    replies.push((200, large(migration, false)));
                }
                let expected = replies.len();
                let (url, server) = serve(replies);
                let home = home(&url);
                let mut args = args();
                args.push(if preview { "--dry-run" } else { "--yes" });
                let child = out::spawn(home.path(), &args, json, Stdio::null());
                let output = out::interrupt_output(child, !json);
                assert!(!String::from_utf8_lossy(&output.stdout).contains("SKILL_INTERRUPTED"));
                if preview {
                    assert_eq!(out::count(home.path()), 0);
                } else {
                    out::received(home.path(), REVISION);
                }
                assert_eq!(server.join().unwrap().len(), expected);
            }
        }
    }
}

#[test]
fn late_resolution_interruption_preserves_the_verified_receipt() {
    for migration in [true, false] {
        for json in [true, false] {
            let mut replies = reads(migration);
            replies.push((
                200,
                resolution(migration, side(Some("sample/memory")), true, true),
            ));
            replies.push((
                200,
                resolution(migration, side(Some("sample/memory")), false, true),
            ));
            let mut args = args();
            args.push("--yes");
            out::interrupt_receipt_write(replies, &args, REVISION, json);
        }
    }
}
