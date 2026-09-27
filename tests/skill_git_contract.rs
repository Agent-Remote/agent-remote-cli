#![cfg(unix)]
#[path = "support/skill_git.rs"]
mod git_support;
#[path = "support/skill_cli.rs"]
mod support;

use git_support::{git, GitFixture};
use serde_json::{json, Value};
use std::fs;
use support::*;

fn preview(fixture: &GitFixture, reference: Option<&str>) -> Value {
    let (server, requests) = serve(vec![
        (
            200,
            json!({"data":{"id":"88888888-8888-4888-8888-888888888888"}}),
        ),
        (
            200,
            envelope(json!({"generation":2,"items":[],"local_items":[]})),
        ),
    ]);
    let home = home(&server);
    let mut command = fixture.cli(home.path());
    command.args(["skill", "add", &fixture.url, "--dry-run", "--path", "one"]);
    if let Some(reference) = reference {
        command.args(["--ref", reference]);
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{} {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(requests.join().unwrap().len(), 2);
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn private_https_raw_tree_has_exact_provenance_and_portable_content() {
    let fixture = GitFixture::new();
    let result = preview(&fixture, None);
    let item = &result["data"]["request"]["items"][0];
    assert_eq!(
        item["source"],
        json!({"kind":"git","locator":fixture.url,"subpath":"one"})
    );
    assert_eq!(
        item["provenance"],
        json!({"ref_kind":"branch","ref":"main","commit":fixture.commit})
    );
    let snapshot = agent_remote_cli::skills::snapshot::PackageSnapshot::capture(
        &fixture.repo.join("one"),
        agent_remote_cli::skills::snapshot::PackageLimits::default(),
    )
    .unwrap();
    assert_eq!(item["tree_digest"], snapshot.tree_digest());
    assert!(
        !String::from_utf8_lossy(&serde_json::to_vec(&result).unwrap())
            .contains("synthetic-password")
    );
    assert_eq!(
        preview(&fixture, Some("v1"))["data"]["request"]["items"][0]["provenance"]["ref_kind"],
        "tag"
    );
    assert_eq!(
        preview(&fixture, Some(&fixture.commit))["data"]["request"]["items"][0]["provenance"]
            ["ref_kind"],
        "commit"
    );
}

#[test]
fn git_list_needs_no_server_login_and_ref_ambiguity_is_not_guessed() {
    let fixture = GitFixture::new();
    let empty = tempfile::tempdir().unwrap();
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &fixture.url, "--list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        result["data"]["candidates"][0]["metadata"]["name"],
        "sample"
    );
    git(&fixture.repo, &["branch", "v1"]);
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &fixture.url, "--list", "--ref", "v1"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stdout).contains("REF_AMBIGUOUS"));
    let output = fixture
        .cli(empty.path())
        .args([
            "skill",
            "add",
            &fixture.url,
            "--list",
            "--ref",
            "refs/tags/v1",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
}

#[test]
fn https_redirects_and_credentials_in_source_are_rejected() {
    let fixture = GitFixture::new();
    let empty = tempfile::tempdir().unwrap();
    let url = fixture.url.replace("repo.git", "redirect.git");
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &url, "--list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("GIT_FETCH_FAILED"));
    assert!(!fixture.root.path().join("redirect-followed").exists());
    let url = fixture.url.replace("https://", "https://secret@");
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &url, "--list"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("secret@"));
}

#[test]
fn selected_submodules_and_lfs_fail_before_any_upload() {
    for submodule in [true, false] {
        let fixture = GitFixture::new();
        if submodule {
            git(
                &fixture.repo,
                &[
                    "update-index",
                    "--add",
                    "--cacheinfo",
                    &format!("160000,{},one/module", fixture.commit),
                ],
            );
        } else {
            fs::write(
                fixture.repo.join("one/large.dat"),
                format!(
                    "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize 123456\n",
                    "a".repeat(64)
                ),
            )
            .unwrap();
            git(&fixture.repo, &["add", "one/large.dat"]);
        }
        git(&fixture.repo, &["commit", "-m", "incomplete"]);
        let (server, requests) = serve(vec![(
            200,
            json!({"data":{"id":"88888888-8888-4888-8888-888888888888"}}),
        )]);
        let home = home(&server);
        let output = fixture
            .cli(home.path())
            .args(["skill", "add", &fixture.url, "--yes"])
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("INCOMPLETE_SOURCE"),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert_eq!(requests.join().unwrap().len(), 1);
    }
}

#[test]
fn git_installation_recovery_uses_saved_commit_after_repository_disappears() {
    let mut fixture = GitFixture::new();
    for file in ["binary.dat", "link", "run.sh", ".gitattributes"] {
        fs::remove_file(fixture.repo.join("one").join(file)).unwrap();
    }
    git(&fixture.repo, &["add", "-A"]);
    git(&fixture.repo, &["commit", "-m", "single-file"]);
    let commit = git(&fixture.repo, &["rev-parse", "HEAD"]);
    let package = agent_remote_cli::skills::snapshot::PackageSnapshot::capture(
        &fixture.repo.join("one"),
        agent_remote_cli::skills::snapshot::PackageLimits::default(),
    )
    .unwrap();
    let upload_id = "66666666-6666-4666-8666-666666666666";
    let mut plan = envelope(
        json!({"id":upload_id,"status":"staged","tree_digest":package.tree_digest(),
        "manifest":package.manifest(),"reserved_bytes":100,"expires_at":"2099-01-01T00:00:00Z"}),
    );
    plan["status"] = json!("staged");
    let mut file = envelope(
        json!({"upload_id":upload_id,"digest":package.manifest().entries[0].sha256,"created":true}),
    );
    file["status"] = json!("persisted");
    let mut complete =
        envelope(json!({"tree_digest":package.tree_digest(),"manifest":package.manifest()}));
    complete["status"] = json!("stored");
    complete["committed"] = json!(true);
    let user = (
        200,
        json!({"data":{"id":"88888888-8888-4888-8888-888888888888"}}),
    );
    let unavailable = json!({"error":{"code":"UNAVAILABLE","message":"temporary"}});
    let receipt = operation("stored", "stored");
    let (server, requests) = serve(vec![
        user.clone(),
        (
            200,
            envelope(json!({"generation":2,"items":[],"local_items":[]})),
        ),
        (200, plan),
        (200, file),
        (200, complete),
        (0, Value::Null),
        (503, unavailable.clone()),
        (503, unavailable),
        user,
        (200, receipt.clone()),
    ]);
    let home = home(&server);
    let first = fixture
        .cli(home.path())
        .args(["skill", "add", &fixture.url, "--yes"])
        .output()
        .unwrap();
    assert_eq!(json_output(&first, 1)["status"], "unknown");
    fixture.server.kill().unwrap();
    fixture.server.wait().unwrap();
    fs::remove_dir_all(&fixture.repo).unwrap();
    fs::write(
        fixture.user_home.join(".gitconfig"),
        "[credential]\n\thelper = !exit 99\n",
    )
    .unwrap();
    let second = fixture
        .cli(home.path())
        .current_dir(fixture.root.path())
        .args(["skill", "add", &fixture.url, "--yes"])
        .output()
        .unwrap();
    assert_eq!(json_output(&second, 0), receipt);
    let requests = requests.join().unwrap();
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.starts_with("POST /api/v1/skills/content/uploads "))
            .count(),
        1
    );
    let install: Value =
        serde_json::from_str(requests[5].split_once("\r\n\r\n").unwrap().1).unwrap();
    assert_eq!(install["items"][0]["provenance"]["commit"], commit);
    assert!(!install.to_string().contains("synthetic-password"));
    assert!(requests[9].starts_with("GET /api/v1/skills/operations?key="));
}

#[test]
fn git_subpath_ignores_unselected_incomplete_assets_and_preserves_instruction_links() {
    let fixture = GitFixture::new();
    git(
        &fixture.repo,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{},outside", fixture.commit),
        ],
    );
    fs::write(fixture.repo.join("outside\\nonportable"), "unselected").unwrap();
    git(&fixture.repo, &["add", "outside\\nonportable"]);
    fs::rename(
        fixture.repo.join("one/SKILL.md"),
        fixture.repo.join("one/guide.md"),
    )
    .unwrap();
    std::os::unix::fs::symlink("guide.md", fixture.repo.join("one/SKILL.md")).unwrap();
    git(&fixture.repo, &["add", "one"]);
    git(&fixture.repo, &["commit", "-m", "instructions-link"]);
    let result = preview(&fixture, None);
    let expected = agent_remote_cli::skills::snapshot::PackageSnapshot::capture(
        &fixture.repo.join("one"),
        agent_remote_cli::skills::snapshot::PackageLimits::default(),
    )
    .unwrap();
    assert_eq!(
        result["data"]["request"]["items"][0]["tree_digest"],
        expected.tree_digest()
    );
}

#[test]
fn git_source_ignores_inherited_execution_config_and_never_disables_tls_checks() {
    let fixture = GitFixture::new();
    let empty = tempfile::tempdir().unwrap();
    let trace = fixture.root.path().join("trace");
    let output = fixture
        .cli(empty.path())
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "core.sshCommand")
        .env("GIT_CONFIG_VALUE_0", "false")
        .env("GIT_DIR", "/nonexistent/git")
        .env("GIT_TRACE", &trace)
        .args(["skill", "add", &fixture.url, "--list"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(!trace.exists());
    let output = fixture
        .cli(empty.path())
        .env_remove("GIT_SSL_CAINFO")
        .env("GIT_SSL_NO_VERIFY", "true")
        .args(["skill", "add", &fixture.url, "--list"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-password"));
}

#[test]
fn ctrl_c_during_credential_lookup_returns_one_interrupted_envelope() {
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let fixture = GitFixture::new();
    let empty = tempfile::tempdir().unwrap();
    let ready = fixture.root.path().join("helper-ready");
    fs::write(
        fixture.user_home.join(".gitconfig"),
        format!(
            "[credential]\n\thelper = \"!f() {{ touch '{}'; sleep 30; }}; f\"\n",
            ready.display()
        ),
    )
    .unwrap();
    let child = fixture
        .cli(empty.path())
        .args(["skill", "add", &fixture.url, "--list"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while !ready.exists() {
        assert!(Instant::now() < deadline, "credential helper did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
    unsafe {
        libc::kill(child.id() as i32, libc::SIGINT);
    }
    let output = child.wait_with_output().unwrap();
    let result = json_output(&output, 130);
    assert_eq!(result["errors"][0]["code"], "SOURCE_INTERRUPTED");
}

#[test]
fn pre_git_local_shorthand_journal_recovers_before_new_github_interpretation() {
    use agent_remote_cli::api::skill_mutations::{
        SkillAddCommand, SkillAddRequest, SkillInstallItem, SkillScope,
    };
    use agent_remote_cli::api::skills::{SkillProvenance, SkillSource};
    use agent_remote_cli::config::AppPaths;
    use agent_remote_cli::local_state::{LocalState, SkillCommandRecord};
    use sha2::{Digest, Sha256};
    let cwd = tempfile::tempdir().unwrap();
    let receipt = operation("stored", "stored");
    let user_id = "88888888-8888-4888-8888-888888888888";
    let (server, requests) = serve(vec![
        (200, json!({"data":{"id":user_id}})),
        (200, receipt.clone()),
    ]);
    let home = home(&server);
    let source = cwd.path().canonicalize().unwrap().join("owner/repo");
    let source_input = format!(
        "{:x}",
        Sha256::digest(source.as_os_str().as_encoded_bytes())
    );
    let legacy = format!("{{\"command\":\"add\",\"source_input\":\"{source_input}\",\"subpath\":null,\"all\":false,\"names\":[],\"scope\":{{\"tools\":[],\"account_id\":null}}}}");
    let request = SkillAddRequest {
        command: SkillAddCommand::Add,
        idempotency_key: "retained-local-key".into(),
        expected_generation: 2,
        items: vec![SkillInstallItem {
            name: "sample".into(),
            source: SkillSource {
                kind: "local".into(),
                locator: "a".repeat(64),
                subpath: "".into(),
            },
            provenance: SkillProvenance {
                ref_kind: "local".into(),
                r#ref: "".into(),
                commit: "".into(),
            },
            tree_digest: "b".repeat(64),
        }],
        scope: SkillScope {
            tools: vec![],
            account_id: None,
        },
        scope_explicit: false,
    };
    let state = LocalState::open(&AppPaths::new(Some(home.path().to_owned())).unwrap()).unwrap();
    state.init_schema().unwrap();
    state
        .begin_skill_command(&SkillCommandRecord {
            server_url: server,
            user_id: user_id.into(),
            intent_digest: format!("{:x}", Sha256::digest(legacy.as_bytes())),
            idempotency_key: request.idempotency_key.clone(),
            request_json: serde_json::to_string(&request).unwrap(),
        })
        .unwrap();
    let output = std::process::Command::new(BIN)
        .current_dir(cwd.path())
        .args(["--json", "--home"])
        .arg(home.path())
        .args(["skill", "add", "owner/repo", "--yes"])
        .env("AGENT_REMOTE_SECRET_BACKEND", "file")
        .env("HOME", home.path())
        .env("XDG_CONFIG_HOME", home.path())
        .env("HTTPS_PROXY", "http://127.0.0.1:1")
        .env("https_proxy", "http://127.0.0.1:1")
        .output()
        .unwrap();
    assert_eq!(json_output(&output, 0), receipt);
    assert_eq!(requests.join().unwrap().len(), 2);
}

#[test]
fn invalid_root_metadata_stops_nested_discovery_and_absolute_instruction_links_fail() {
    let fixture = GitFixture::new();
    fs::create_dir(fixture.repo.join(".assets")).unwrap();
    fs::write(
        fixture.repo.join(".assets/SKILL.md"),
        "---\nname: hidden\n---\nAsset",
    )
    .unwrap();
    fs::write(
        fixture.repo.join("SKILL.md"),
        "---\nname: Invalid Name\n---\nInvalid",
    )
    .unwrap();
    git(&fixture.repo, &["add", "."]);
    git(&fixture.repo, &["commit", "-m", "invalid-root"]);
    let empty = tempfile::tempdir().unwrap();
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &fixture.url, "--list"])
        .output()
        .unwrap();
    let result = json_output(&output, 0);
    assert_eq!(result["data"]["candidates"], json!([]));
    assert_eq!(result["data"]["issues"].as_array().unwrap().len(), 1);
    assert_eq!(result["data"]["issues"][0]["path"], "");
    fs::rename(
        fixture.repo.join("one/SKILL.md"),
        fixture.repo.join("one/guide.md"),
    )
    .unwrap();
    std::os::unix::fs::symlink("/guide.md", fixture.repo.join("one/SKILL.md")).unwrap();
    git(&fixture.repo, &["add", "one"]);
    git(&fixture.repo, &["commit", "-m", "absolute-link"]);
    let output = fixture
        .cli(empty.path())
        .args(["skill", "add", &fixture.url, "--list", "--path", "one"])
        .output()
        .unwrap();
    let result = json_output(&output, 0);
    assert_eq!(result["data"]["candidates"], json!([]));
    assert_eq!(result["data"]["issues"].as_array().unwrap().len(), 1);
}
