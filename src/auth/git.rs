//! Read native Git helper credentials without storing or exposing them to the control plane.

use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::path::Path;
use std::time::Duration;
use tokio::process::Command;

use crate::skills::{git_process, git_source::GitSource};

/// Deliberately has no Debug/Serialize implementation. The value only enters a Git child environment.
pub struct GitCredential(String);
impl GitCredential {
    pub fn apply(&self, command: &mut Command, source: &GitSource) {
        command
            .env("GIT_CONFIG_COUNT", "1")
            .env(
                "GIT_CONFIG_KEY_0",
                format!("http.{}.extraHeader", source.url),
            )
            .env("GIT_CONFIG_VALUE_0", &self.0);
    }
}

pub async fn load(source: &GitSource, directory: &Path) -> Result<Option<GitCredential>> {
    let mut command = git_process::command(directory, true);
    command.args(["credential", "fill"]);
    let input = format!("url={}\n\n", source.url);
    let Some(output) = git_process::run(
        command,
        input.as_bytes(),
        64 * 1024,
        Duration::from_secs(30),
        None,
    )
    .await?
    else {
        // Missing credentials is normal for public repositories. Authentication errors from the
        // transport remain failures; no login UI or credential-store write is initiated here.
        return Ok(None);
    };
    parse(&output)
}

fn parse(output: &[u8]) -> Result<Option<GitCredential>> {
    let output = std::str::from_utf8(output)
        .map_err(|_| anyhow::anyhow!("GIT_AUTH_FAILED: invalid helper response"))?;
    let mut username = None;
    let mut password = None;
    for line in output.lines() {
        if line.is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once('=') else {
            bail!("GIT_AUTH_FAILED: invalid helper response");
        };
        if value.chars().any(char::is_control) {
            bail!("GIT_AUTH_FAILED: invalid helper response");
        }
        let field = match key {
            "username" => &mut username,
            "password" => &mut password,
            _ => continue,
        };
        if field.replace(value).is_some() {
            bail!("GIT_AUTH_FAILED: repeated helper field");
        }
    }
    match (username, password) {
        (Some(user), Some(pass)) if !user.contains(':') => Ok(Some(GitCredential(format!(
            "Authorization: Basic {}",
            STANDARD.encode(format!("{user}:{pass}"))
        )))),
        (None, None) => Ok(None),
        _ => bail!("GIT_AUTH_FAILED: helper did not supply a complete credential"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn helper_material_is_validated_without_echoing_secrets() {
        assert!(parse(b"username=test\npassword=secret\n\n")
            .unwrap()
            .is_some());
        assert!(parse(b"username=test\npassword=secret\npassword=secret\n")
            .err()
            .unwrap()
            .to_string()
            .contains("repeated"));
        assert!(parse(b"username=bad:user\npassword=secret\n").is_err());
    }
}
