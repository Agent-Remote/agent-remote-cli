//! Deterministic race injection, compiled only into source capture unit tests.
use std::cell::RefCell;
thread_local! {
    static BEFORE: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
    static AFTER: RefCell<Option<Box<dyn FnOnce()>>> = RefCell::new(None);
}
pub(super) fn before_open() {
    let hook = BEFORE.with(|v| v.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
pub(super) fn after_read() {
    let hook = AFTER.with(|v| v.borrow_mut().take());
    if let Some(hook) = hook {
        hook();
    }
}
fn source() -> (tempfile::TempDir, std::path::PathBuf, super::Selection) {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap();
    std::fs::create_dir(path.join(".claude")).unwrap();
    std::fs::write(path.join(".claude/settings.json"), b"original").unwrap();
    (
        temp,
        path,
        super::Selection {
            tool: "claude".into(),
            include_resume_history: false,
            exclude_skills: false,
        },
    )
}
#[test]
fn growth_between_stat_and_open_fails_closed() {
    let (_t, path, s) = source();
    let target = path.join(".claude/settings.json");
    BEFORE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move || {
            std::fs::OpenOptions::new()
                .write(true)
                .open(target)
                .unwrap()
                .set_len(super::MAX_FILE_BYTES + 1)
                .unwrap();
        }))
    });
    assert!(super::capture(&path, &s).is_err());
}
#[test]
fn replacement_after_read_is_not_silently_accepted() {
    let (_t, path, s) = source();
    let target = path.join(".claude/settings.json");
    let saved = path.join("old");
    AFTER.with(|v| {
        *v.borrow_mut() = Some(Box::new(move || {
            std::fs::rename(&target, saved).unwrap();
            std::fs::write(&target, b"original").unwrap();
        }))
    });
    assert_eq!(
        super::capture(&path, &s).err().unwrap().code,
        "account_import_source_changed"
    );
}
#[test]
fn new_file_after_read_invalidates_complete_selection() {
    let (_t, path, s) = source();
    let target = path.join(".claude/new.md");
    AFTER.with(|v| {
        *v.borrow_mut() = Some(Box::new(move || {
            std::fs::write(target, b"new").unwrap();
        }))
    });
    assert_eq!(
        super::capture(&path, &s).err().unwrap().code,
        "account_import_source_changed"
    );
}
#[cfg(unix)]
#[test]
fn fifo_replacement_between_stat_and_open_does_not_block() {
    use std::os::unix::ffi::OsStrExt;
    let (_t, path, s) = source();
    let target = path.join(".claude/settings.json");
    BEFORE.with(|v| {
        *v.borrow_mut() = Some(Box::new(move || {
            std::fs::remove_file(&target).unwrap();
            let name = std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
            assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        }))
    });
    assert_eq!(
        super::capture(&path, &s).err().unwrap().code,
        "account_import_source_invalid"
    );
}
