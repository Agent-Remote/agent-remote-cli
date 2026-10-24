use super::*;

fn digest(ch: u8) -> String {
    (0..64).map(|_| ch as char).collect()
}

#[test]
fn reserve_survives_restart_and_rejects_replay() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.jsonl");
    let request = digest(b'a');
    let mut journal = ReplayJournal::open(&path).unwrap();
    journal.reserve(&request).unwrap();
    assert_eq!(journal.len(), 1);
    assert_eq!(
        journal.reserve(&request).err().unwrap().0,
        "wireguard_broker_request_replayed"
    );
    drop(journal);
    let mut reopened = ReplayJournal::open(&path).unwrap();
    assert_eq!(reopened.len(), 1);
    assert_eq!(
        reopened.reserve(&request).err().unwrap().0,
        "wireguard_broker_request_replayed"
    );
}

#[test]
fn malformed_or_duplicate_journal_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.jsonl");
    std::fs::write(&path, b"not-json\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        ReplayJournal::open(&path).err().unwrap().0,
        "wireguard_replay_journal_invalid"
    );
    std::fs::write(
        &path,
        format!(
            "{{\"request_sha256\":\"{}\"}}\n{{\"request_sha256\":\"{}\"}}\n",
            digest(b'b'),
            digest(b'b')
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert_eq!(
        ReplayJournal::open(&path).err().unwrap().0,
        "wireguard_replay_journal_invalid"
    );
}

#[test]
fn unsafe_path_and_invalid_digest_are_rejected() {
    assert!(ReplayJournal::open("relative/journal").is_err());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("journal.jsonl");
    let mut journal = ReplayJournal::open(path).unwrap();
    assert_eq!(
        journal.reserve(&"A".repeat(64)).err().unwrap().0,
        "wireguard_replay_journal_invalid"
    );
}
