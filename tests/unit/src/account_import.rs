use super::*;
use std::path::Path;
const ACCOUNT: &str = "12345678-1234-1234-1234-123456789abc";
fn selection() -> Selection {
    Selection {
        tool: "claude".into(),
        include_resume_history: false,
        exclude_skills: false,
    }
}
fn home() -> (tempfile::TempDir, PathBuf) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    (temp, path)
}
fn write(home: &Path, path: &str, bytes: &[u8]) {
    let path = home.join(".claude").join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, bytes).unwrap();
}
fn context(home: &Path) -> Context {
    Context {
        home: home.into(),
        server_url: Some("https://server.test".into()),
        active_device_id: Some("device-test".into()),
    }
}
#[test]
fn absent_source_is_empty_and_no_state_created() {
    let (_t, h) = home();
    let d = source::discover_at(&h, &selection()).unwrap();
    assert!(d.include.is_empty());
    let c = source::capture(&h, &selection()).unwrap();
    assert!(c.files.is_empty());
    assert_eq!(std::fs::read_dir(h).unwrap().count(), 0);
}
#[test]
fn metadata_discovery_never_reads_oversized_content() {
    let (_t, h) = home();
    write(&h, "settings.json", b"");
    std::fs::File::options()
        .write(true)
        .open(h.join(".claude/settings.json"))
        .unwrap()
        .set_len(source::MAX_FILE_BYTES + 1)
        .unwrap();
    assert!(source::discover_at(&h, &selection()).is_ok());
    assert_eq!(
        source::capture(&h, &selection()).err().unwrap().code,
        "account_import_source_limit"
    );
}
#[test]
fn exact_limits_and_total_are_enforced() {
    let (_t, h) = home();
    for n in 0..8 {
        write(
            &h,
            &format!("agents/{n}"),
            &vec![b'x'; source::MAX_FILE_BYTES as usize],
        );
    }
    assert_eq!(
        source::capture(&h, &selection()).unwrap().total_bytes,
        source::MAX_TOTAL_BYTES
    );
    write(&h, "agents/extra", b"x");
    assert_eq!(
        source::capture(&h, &selection()).err().unwrap().code,
        "account_import_source_limit"
    );
}
#[test]
fn exclude_skills_before_read_preserves_plugins_and_history() {
    let (_t, h) = home();
    write(
        &h,
        "skills/huge",
        &vec![b'x'; source::MAX_FILE_BYTES as usize + 1],
    );
    write(&h, "plugins/p/skills/SKILL.md", b"plugin");
    write(&h, "projects/history", b"private");
    let mut s = selection();
    s.exclude_skills = true;
    let c = source::capture(&h, &s).unwrap();
    assert_eq!(c.files.len(), 1);
    s.include_resume_history = true;
    assert_eq!(source::capture(&h, &s).unwrap().files.len(), 2);
    assert!(source::capture(&h, &selection()).is_err());
}
#[cfg(unix)]
#[test]
fn entry_links_hardlinks_and_fifos_are_rejected_without_following() {
    use std::os::unix::fs::symlink;
    for kind in ["symlink", "hardlink", "fifo"] {
        let (_t, h) = home();
        std::fs::create_dir(h.join(".claude")).unwrap();
        let file = h.join(".claude/settings.json");
        match kind {
            "symlink" => {
                std::fs::write(h.join("outside"), "private").unwrap();
                symlink(h.join("outside"), &file).unwrap();
            }
            "hardlink" => {
                std::fs::write(h.join("outside"), "private").unwrap();
                std::fs::hard_link(h.join("outside"), &file).unwrap();
            }
            _ => {
                use std::os::unix::ffi::OsStrExt;
                let name = std::ffi::CString::new(file.as_os_str().as_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
            }
        }
        assert_eq!(
            source::capture(&h, &selection()).err().unwrap().code,
            "account_import_source_invalid"
        );
    }
}
#[cfg(unix)]
#[test]
fn source_root_ancestors_and_nested_links_are_rejected() {
    use std::os::unix::fs::symlink;
    let (_t, h) = home();
    std::fs::create_dir(h.join("actual")).unwrap();
    symlink(h.join("actual"), h.join(".claude")).unwrap();
    assert!(source::discover_at(&h, &selection()).is_err());
    std::fs::remove_file(h.join(".claude")).unwrap();
    write(&h, "agents/ok", b"ok");
    symlink(h.join("actual"), h.join(".claude/agents/link")).unwrap();
    assert!(source::capture(&h, &selection()).is_err());
    symlink(&h, h.join("alias")).unwrap();
    assert!(source::discover_at(&h.join("alias"), &selection()).is_err());
}
#[test]
fn capture_has_stable_hashes_sorted_manifest_and_private_bytes() {
    let (_t, h) = home();
    write(&h, "agents/a", b"private-body");
    write(&h, "agents.md", b"public-description");
    let a = plan(
        context(&h),
        ACCOUNT,
        source::capture(&h, &selection()).unwrap(),
    )
    .unwrap()
    .0;
    let b = plan(
        context(&h),
        ACCOUNT,
        source::capture(&h, &selection()).unwrap(),
    )
    .unwrap()
    .0;
    assert_eq!(a.digest, b.digest);
    assert_eq!(a.manifest[0].path, "~/.claude/agents.md");
    assert_eq!(a.manifest[1].path, "~/.claude/agents/a");
    let wire = serde_json::to_string(&a).unwrap();
    assert!(!wire.contains("private-body"));
    assert!(!wire.contains("cHJpdmF0ZS1ib2R5"));
    write(&h, "agents/a", b"replacement");
    let c = plan(
        context(&h),
        ACCOUNT,
        source::capture(&h, &selection()).unwrap(),
    )
    .unwrap()
    .0;
    assert_ne!(a.digest, c.digest);
}
#[test]
fn same_bytes_replacement_invalidates_local_snapshot_identity() {
    let (_t, h) = home();
    write(&h, "settings.json", b"same");
    let a = source::capture(&h, &selection()).unwrap();
    std::fs::rename(h.join(".claude/settings.json"), h.join("old")).unwrap();
    write(&h, "settings.json", b"same");
    let b = source::capture(&h, &selection()).unwrap();
    assert_eq!(a.manifest, b.manifest);
    assert_ne!(a.fingerprint, b.fingerprint);
}
#[test]
fn traversal_depth_entries_and_candidate_roots_are_bounded() {
    let (_t, h) = home();
    let deep = format!("agents/{}/end", vec!["a"; 33].join("/"));
    write(&h, &deep, b"x");
    assert_eq!(
        source::capture(&h, &selection()).err().unwrap().code,
        "account_import_source_limit"
    );
    let (_t, h) = home();
    for n in 0..65 {
        write(&h, &format!("{n}.md"), b"");
    }
    assert_eq!(
        source::discover_at(&h, &selection()).err().unwrap().code,
        "account_import_source_limit"
    );
    let (_t, h) = home();
    for n in 0..source::MAX_ENTRIES {
        write(&h, &format!("agents/{n}"), b"");
    }
    assert_eq!(
        source::capture(&h, &selection()).err().unwrap().code,
        "account_import_source_limit"
    );
}
#[test]
fn journal_reads_missing_state_without_creating_and_reserves_exact_scope() {
    let (_t, h) = home();
    let paths = AppPaths::new(Some(h.join("cli"))).unwrap();
    assert!(pending(&paths).unwrap().items.is_empty());
    assert!(!paths.home().exists());
    let state = LocalState::open(&paths).unwrap();
    state.init_schema().unwrap();
    let r = ImportRecord {
        context: context(paths.home()),
        account_id: ACCOUNT.into(),
        request_id: "12345678-1234-1234-1234-123456789abd".into(),
        digest: types::hash(b"plan"),
        intent_fingerprint: types::hash(b"intent"),
        task_id: None,
        phase: "pending".into(),
    };
    assert!(state.reserve_account_import(&r).unwrap());
    assert!(!state.reserve_account_import(&r).unwrap());
    let mut other = r.clone();
    other.request_id = "12345678-1234-1234-1234-123456789abe".into();
    assert!(!state.reserve_account_import(&other).unwrap());
    assert_eq!(pending(&paths).unwrap().items, vec![r.clone()]);
    let mut wrong = r.clone();
    wrong.digest = types::hash(b"different");
    assert!(!state.forget_account_import(&wrong).unwrap());
    assert!(state.forget_account_import(&r).unwrap());
    assert!(pending(&paths).unwrap().items.is_empty());
}
#[test]
fn canonical_server_intent_matches_cross_language_vector() {
    let manifest = vec![ManifestEntry {
        path: "~/.claude/猫.md".into(),
        size: 3,
        sha256: types::hash(b"abc"),
        mode: 384,
    }];
    let value = receipt::intent(
        ACCOUNT,
        "claude",
        &["~/.claude/猫.md".into()],
        &source::exclusions(false),
        false,
        &manifest,
    )
    .unwrap();
    assert_eq!(
        value,
        "sha256:f0327c23a6bde58f099b0305c5dd37637ebd3e1ea4c75035cca481e7ec21194f"
    );
}

#[test]
fn server_golden_intent_with_unicode_order_and_modes_matches() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../fixtures/account_import/intent_v1.json")).unwrap();
    let manifest: Vec<ManifestEntry> = serde_json::from_value(v["manifest"].clone()).unwrap();
    let include: Vec<String> = serde_json::from_value(v["request"]["include"].clone()).unwrap();
    let exclude: Vec<String> = serde_json::from_value(v["request"]["exclude"].clone()).unwrap();
    let hash = receipt::intent(
        v["tool_account_id"].as_str().unwrap(),
        "claude",
        &include,
        &exclude,
        false,
        &manifest,
    )
    .unwrap();
    assert_eq!(hash, v["intent_fingerprint"]);
}
#[test]
fn damaged_journal_key_and_phase_fail_closed() {
    for damage in ["key", "phase", "device"] {
        let (_temp, home) = home();
        let paths = AppPaths::new(Some(home)).unwrap();
        let state = LocalState::open(&paths).unwrap();
        state.init_schema().unwrap();
        let mut record = ImportRecord {
            context: context(paths.home()),
            account_id: ACCOUNT.into(),
            request_id: "12345678-1234-4234-9234-123456789abc".into(),
            digest: types::hash(b"plan"),
            intent_fingerprint: types::hash(b"intent"),
            task_id: None,
            phase: "pending".into(),
        };
        if damage == "phase" {
            record.phase = "accepted".into();
        }
        if damage == "device" {
            record.context.active_device_id = None;
        }
        let key = if damage == "key" {
            "account_import_request:other".into()
        } else {
            format!("account_import_request:{}", record.request_id)
        };
        state
            .set_kv(&key, &serde_json::to_string(&record).unwrap())
            .unwrap();
        assert_eq!(
            pending(&paths).err().unwrap().code,
            "account_import_journal_unavailable"
        );
    }
}
