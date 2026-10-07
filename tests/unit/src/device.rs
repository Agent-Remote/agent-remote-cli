// Tests for src/device.rs.

use std::fs::{self, File, OpenOptions};
use std::io::{Seek, SeekFrom, Write};

#[cfg(unix)]
use std::os::unix::fs::symlink;
#[cfg(target_os = "macos")]
use std::process::Command;

use tempfile::tempdir;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[cfg(target_os = "macos")]
use super::prepare_install_source;
use super::{
    ensure_no_visibility_journal, ensure_not_downgrade, parse_team_identifier, remove_device_state,
    remove_fixed_state_path, remove_known_temporary_bundle, tccutil_reports_missing_bundle,
    validate_device_archive, validated_bundle_path, APP_NAME, GUI_EXECUTOR_BUNDLE_IDENTIFIER,
};

fn write_test_archive(path: &std::path::Path, entries: &[(&str, &[u8])]) {
    let mut archive = ZipWriter::new(File::create(path).unwrap());
    for (name, content) in entries {
        if name.ends_with('/') {
            archive
                .add_directory(*name, SimpleFileOptions::default())
                .unwrap();
        } else {
            archive
                .start_file(*name, SimpleFileOptions::default())
                .unwrap();
            archive.write_all(content).unwrap();
        }
    }
    archive.finish().unwrap();
}

#[test]
fn source_requires_the_fixed_non_symlink_app_name() {
    let directory = tempdir().unwrap();
    let wrong = directory.path().join("Other.app");
    fs::create_dir(&wrong).unwrap();
    assert!(validated_bundle_path(&wrong).is_err());

    let expected = directory.path().join(APP_NAME);
    fs::create_dir(&expected).unwrap();
    assert_eq!(
        validated_bundle_path(&expected).unwrap(),
        expected.canonicalize().unwrap()
    );
}

#[test]
fn archive_requires_every_entry_inside_the_fixed_app_bundle() {
    let directory = tempdir().unwrap();
    let valid = directory.path().join("device.zip");
    write_test_archive(
        &valid,
        &[
            ("Agent Remote Device.app/", b""),
            ("Agent Remote Device.app/Contents/Info.plist", b"plist"),
        ],
    );
    validate_device_archive(&valid).unwrap();

    let sibling = directory.path().join("sibling.zip");
    write_test_archive(
        &sibling,
        &[
            ("Agent Remote Device.app/Contents/Info.plist", b"plist"),
            ("unexpected.txt", b"unexpected"),
        ],
    );
    assert!(validate_device_archive(&sibling).is_err());

    let traversal = directory.path().join("traversal.zip");
    write_test_archive(
        &traversal,
        &[("Agent Remote Device.app/../outside", b"unsafe")],
    );
    assert!(validate_device_archive(&traversal).is_err());

    let symlink = directory.path().join("symlink.zip");
    let mut archive = ZipWriter::new(File::create(&symlink).unwrap());
    archive
        .add_symlink(
            "Agent Remote Device.app/Contents/link",
            "../../../outside",
            SimpleFileOptions::default(),
        )
        .unwrap();
    archive.finish().unwrap();
    assert!(validate_device_archive(&symlink).is_err());

    let inconsistent = directory.path().join("inconsistent.zip");
    write_test_archive(
        &inconsistent,
        &[("Agent Remote Device.app/Contents/Info.plist", b"plist")],
    );
    let mut archive = OpenOptions::new().write(true).open(&inconsistent).unwrap();
    archive.seek(SeekFrom::Start(30)).unwrap();
    archive.write_all(b"X").unwrap();
    drop(archive);
    assert!(validate_device_archive(&inconsistent).is_err());
}

#[cfg(target_os = "macos")]
#[test]
fn archive_source_is_extracted_to_a_temporary_app_bundle() {
    let directory = tempdir().unwrap();
    let archive = directory.path().join("device.ZIP");
    let bundle = directory.path().join(APP_NAME);
    fs::create_dir_all(bundle.join("Contents")).unwrap();
    fs::write(bundle.join("Contents/Info.plist"), b"plist").unwrap();
    assert!(Command::new("ditto")
        .args(["-c", "-k", "--keepParent"])
        .arg(&bundle)
        .arg(&archive)
        .status()
        .unwrap()
        .success());

    let prepared = prepare_install_source(&archive).unwrap();

    assert_eq!(prepared.bundle().file_name().unwrap(), APP_NAME);
    assert!(prepared.bundle().join("Contents/Info.plist").is_file());
}

#[test]
fn cleanup_refuses_paths_outside_the_fixed_staging_namespace() {
    let directory = tempdir().unwrap();
    let unrelated = directory.path().join("unrelated.app");
    fs::create_dir(&unrelated).unwrap();
    assert!(remove_known_temporary_bundle(&unrelated, directory.path()).is_err());
    assert!(unrelated.exists());

    let staging = directory.path().join(format!(".{APP_NAME}.install-1"));
    fs::create_dir(&staging).unwrap();
    remove_known_temporary_bundle(&staging, directory.path()).unwrap();
    assert!(!staging.exists());
}

#[test]
fn installation_rejects_downgrades_and_unparseable_versions() {
    ensure_not_downgrade(Some("1.2.3"), Some("1.2.3")).unwrap();
    ensure_not_downgrade(Some("1.2.3"), Some("1.3.0")).unwrap();
    assert!(ensure_not_downgrade(Some("1.2.3"), Some("1.2.2")).is_err());
    assert!(ensure_not_downgrade(Some("invalid"), Some("1.2.3")).is_err());
    assert!(ensure_not_downgrade(Some("1.2.3"), None).is_err());
}

#[test]
fn signing_team_identifier_parser_requires_one_canonical_identifier() {
    assert_eq!(
        parse_team_identifier("Executable=/tmp/App\nTeamIdentifier=ABC123DEF4\n"),
        Some("ABC123DEF4".to_string())
    );
    assert_eq!(parse_team_identifier("TeamIdentifier=not-valid\n"), None);
    assert_eq!(
        parse_team_identifier("TeamIdentifier=ABC123DEF4\nTeamIdentifier=ABC123DEF4\n"),
        None
    );
    assert_eq!(
        parse_team_identifier("Identifier=dev.agentremote.device\n"),
        None
    );
}

#[test]
fn missing_tcc_bundle_is_already_reset_but_other_failures_are_not_ignored() {
    assert!(tccutil_reports_missing_bundle(
        b"tccutil: No such bundle identifier \"dev.agentremote.device.network-broker\""
    ));
    assert!(tccutil_reports_missing_bundle(b"OSStatus error -10814"));
    assert!(!tccutil_reports_missing_bundle(
        b"tccutil: operation not permitted"
    ));
}

#[test]
fn uninstall_removes_only_fixed_device_state_paths() {
    let directory = tempdir().unwrap();
    let library = directory.path().join("Library");
    let container = library
        .join("Containers")
        .join(GUI_EXECUTOR_BUNDLE_IDENTIFIER);
    fs::create_dir_all(container.join("Data")).unwrap();
    let unrelated = library.join("Containers/com.example.unrelated");
    fs::create_dir_all(&unrelated).unwrap();

    remove_device_state(directory.path()).unwrap();

    assert!(!container.exists());
    assert!(unrelated.exists());
    assert!(remove_fixed_state_path(directory.path(), &library).is_err());
}

#[test]
fn uninstall_refuses_hidden_application_recovery_state() {
    let directory = tempdir().unwrap();
    let journal = directory
        .path()
        .join("Library/Containers")
        .join(GUI_EXECUTOR_BUNDLE_IDENTIFIER)
        .join("Data/Library/Application Support/Agent Remote Device/hidden-applications.json");
    fs::create_dir_all(journal.parent().unwrap()).unwrap();
    fs::write(&journal, b"[]").unwrap();

    assert!(ensure_no_visibility_journal(directory.path()).is_err());
    assert!(journal.exists());
}

#[cfg(unix)]
#[test]
fn uninstall_refuses_dangling_state_links() {
    let directory = tempdir().unwrap();
    let library = directory.path().join("Library");
    let state = library.join("Caches/dev.agentremote.device");
    fs::create_dir_all(state.parent().unwrap()).unwrap();
    symlink(directory.path().join("missing"), &state).unwrap();

    assert!(remove_fixed_state_path(&state, &library).is_err());
    assert!(fs::symlink_metadata(&state).is_ok());
}
