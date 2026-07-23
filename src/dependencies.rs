use std::fs;
use std::process::Command;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::config::AppPaths;

#[derive(Clone)]
pub struct DependencyManager {
    paths: AppPaths,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct DependencyManifest {
    pub schema_version: u32,
    pub dependencies: Vec<ManagedDependency>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ManagedDependency {
    pub name: String,
    pub required_version: String,
    pub binary: String,
    pub source: String,
    pub license: String,
    pub license_notice: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DependencyStatus {
    pub name: String,
    pub required_version: String,
    pub binary_path: std::path::PathBuf,
    pub license: String,
    pub license_notice: String,
    pub installed: bool,
    pub version_output: Option<String>,
}

impl DependencyManager {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn ensure_manifest(&self) -> Result<()> {
        self.paths.ensure_base_dirs()?;
        let manifest_path = self.paths.dependency_manifest_path();
        if manifest_path.exists() {
            return Ok(());
        }
        let raw = serde_json::to_string_pretty(&DependencyManifest::default_managed())?;
        fs::write(
            manifest_path,
            format!(
                "{raw}
"
            ),
        )?;
        Ok(())
    }

    pub fn load_manifest(&self) -> Result<DependencyManifest> {
        self.ensure_manifest()?;
        let raw = fs::read_to_string(self.paths.dependency_manifest_path())?;
        Ok(serde_json::from_str(&raw)?)
    }

    pub fn check_all(&self) -> Result<Vec<DependencyStatus>> {
        let manifest = self.load_manifest()?;
        let statuses = manifest
            .dependencies
            .into_iter()
            .map(|dependency| self.check_dependency(dependency))
            .collect();
        Ok(statuses)
    }

    fn check_dependency(&self, dependency: ManagedDependency) -> DependencyStatus {
        let binary_path = self.paths.home().join(&dependency.binary);
        let installed = binary_path.exists();
        let version_output = if installed {
            Command::new(&binary_path)
                .arg("--version")
                .output()
                .ok()
                .map(|output| {
                    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
                    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
                    if stdout.is_empty() {
                        stderr
                    } else {
                        stdout
                    }
                })
                .filter(|value| !value.is_empty())
        } else {
            None
        };
        DependencyStatus {
            name: dependency.name,
            required_version: dependency.required_version,
            binary_path,
            license: dependency.license,
            license_notice: dependency.license_notice,
            installed,
            version_output,
        }
    }
}

impl DependencyManifest {
    pub fn default_managed() -> Self {
        let mut dependencies = vec![
            ManagedDependency {
                name: "mutagen".to_string(),
                required_version: "managed-by-agent-remote-release".to_string(),
                binary: "bin/mutagen".to_string(),
                source: "agent-remote-cli release artifact".to_string(),
                license: "MIT, with SSPL notice required for official v0.17+ builds".to_string(),
                license_notice:
                    "See THIRD_PARTY_NOTICES.md and the exact packaged Mutagen artifact notice"
                        .to_string(),
            },
            ManagedDependency {
                name: "wireguard-helper".to_string(),
                required_version: "managed-by-agent-remote-release".to_string(),
                binary: "bin/agent-remote-wireguard".to_string(),
                source: "agent-remote-cli release artifact".to_string(),
                license: "GPL-3.0-only".to_string(),
                license_notice:
                    "See THIRD_PARTY_NOTICES.md and the exact packaged WireGuard artifact notice"
                        .to_string(),
            },
            ManagedDependency {
                name: "tmux".to_string(),
                required_version: "managed-by-agent-remote-release".to_string(),
                binary: "bin/tmux".to_string(),
                source: "agent-remote-cli release artifact".to_string(),
                license: "ISC".to_string(),
                license_notice: "See the packaged dependencies/licenses/tmux-COPYING".to_string(),
            },
            ManagedDependency {
                name: "wireguard-tools".to_string(),
                required_version: "managed-by-agent-remote-release".to_string(),
                binary: "bin/wg".to_string(),
                source: "agent-remote-cli release artifact".to_string(),
                license: "GPL-2.0-only".to_string(),
                license_notice: "See the packaged dependencies/licenses/wireguard-tools-COPYING"
                    .to_string(),
            },
        ];
        #[cfg(target_os = "macos")]
        dependencies.push(ManagedDependency {
            name: "wireguard-go".to_string(),
            required_version: "managed-by-agent-remote-release".to_string(),
            binary: "bin/wireguard-go".to_string(),
            source: "agent-remote-cli release artifact".to_string(),
            license: "MIT".to_string(),
            license_notice: "See the packaged dependencies/licenses/wireguard-go-LICENSE"
                .to_string(),
        });
        Self {
            schema_version: 1,
            dependencies,
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use crate::config::AppPaths;

    use super::DependencyManager;

    #[test]
    fn creates_default_manifest_and_reports_missing_binaries() {
        let dir = tempdir().unwrap();
        let paths = AppPaths::from_home(dir.path().join("agent-remote"));
        let manager = DependencyManager::new(paths.clone());
        manager.ensure_manifest().unwrap();
        assert!(paths.dependency_manifest_path().exists());

        let statuses = manager.check_all().unwrap();
        assert_eq!(
            statuses.len(),
            if cfg!(target_os = "macos") { 5 } else { 4 }
        );
        assert!(statuses.iter().all(|status| !status.installed));
        assert!(statuses.iter().any(|status| status.name == "mutagen"));
    }
}
