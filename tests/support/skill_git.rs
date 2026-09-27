#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub struct GitFixture {
    pub root: tempfile::TempDir,
    pub repo: PathBuf,
    pub user_home: PathBuf,
    pub url: String,
    pub commit: String,
    pub server: Child,
}
impl GitFixture {
    pub fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let repo = root.path().join("repo.git");
        let user_home = root.path().join("home");
        fs::create_dir(&user_home).unwrap();
        fs::create_dir(&repo).unwrap();
        git(&repo, &["init", "-b", "main"]);
        git(&repo, &["config", "user.name", "fixture"]);
        git(&repo, &["config", "user.email", "fixture@example.test"]);
        fs::create_dir(repo.join("one")).unwrap();
        fs::write(
            repo.join("one/SKILL.md"),
            "---\nname: sample\n---\nInstructions\n",
        )
        .unwrap();
        fs::write(repo.join("one/binary.dat"), b"\0\xff\n\rDATA").unwrap();
        fs::write(repo.join("one/run.sh"), "#!/bin/sh\nprintf untouched\\n\n").unwrap();
        use std::os::unix::fs::{symlink, PermissionsExt};
        fs::set_permissions(repo.join("one/run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        symlink("binary.dat", repo.join("one/link")).unwrap();
        fs::write(
            repo.join("one/.gitattributes"),
            "binary.dat export-ignore\nSKILL.md export-subst filter=poison\n",
        )
        .unwrap();
        git(&repo, &["add", "."]);
        git(&repo, &["commit", "-m", "fixture"]);
        let commit = git(&repo, &["rev-parse", "HEAD"]);
        git(&repo, &["tag", "-a", "v1", "-m", "version"]);
        let cert = root.path().join("cert.pem");
        let key = root.path().join("key.pem");
        let output = Command::new("openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=127.0.0.1",
                "-addext",
                "subjectAltName=IP:127.0.0.1",
                "-keyout",
            ])
            .arg(&key)
            .arg("-out")
            .arg(&cert)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "TLS fixture certificate creation failed"
        );
        let port_file = root.path().join("port");
        let server = Command::new("python3")
            .arg("tests/fixtures/skill_git_https.py")
            .arg(root.path())
            .arg(&cert)
            .arg(&key)
            .arg(&port_file)
            .env("HOME", &user_home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(10);
        let port = loop {
            if let Ok(port) = fs::read_to_string(&port_file) {
                if !port.is_empty() {
                    break port;
                }
            }
            assert!(Instant::now() < deadline, "TLS fixture did not start");
            thread::sleep(Duration::from_millis(20));
        };
        // The only secret here is synthetic test material; helpers and transport receive isolated HOME.
        fs::write(user_home.join(".gitconfig"), "[credential]\n\thelper = \"!f() { printf 'username=fixture\\npassword=synthetic-password\\n'; }; f\"\n[filter \"poison\"]\n\tsmudge = false\n\trequired = true\n[url \"https://127.0.0.1:1/\"]\n\tinsteadOf = https://127.0.0.1:9/\n").unwrap();
        let config_path = user_home.join(".gitconfig");
        let config = fs::read_to_string(&config_path).unwrap().replace(
            "https://127.0.0.1:9/",
            &format!("https://127.0.0.1:{port}/"),
        );
        fs::write(config_path, config).unwrap();
        Self {
            root,
            repo,
            user_home,
            url: format!("https://127.0.0.1:{port}/repo.git"),
            commit,
            server,
        }
    }
    pub fn cli(&self, home: &Path) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_agent-remote"));
        command
            .args(["--json", "--home"])
            .arg(home)
            .env("HOME", &self.user_home)
            .env("XDG_CONFIG_HOME", self.user_home.join(".config"))
            .env("GIT_SSL_CAINFO", self.root.path().join("cert.pem"))
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("AGENT_REMOTE_SECRET_BACKEND", "file")
            .env("NO_PROXY", "127.0.0.1")
            .env("no_proxy", "127.0.0.1")
            .env("NO_COLOR", "1");
        command
    }
}
impl Drop for GitFixture {
    fn drop(&mut self) {
        let _ = self.server.kill();
        let _ = self.server.wait();
    }
}
pub fn git(repo: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "fixture Git command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}
