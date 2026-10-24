//! Bounded content-free snapshots; no secret environment values leave this module.
use super::{Binding, Error, Result, Tool};
use crate::config::AppPaths;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};

pub(super) const MARKER: &str = "agent-remote-environment.json";

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Marker {
    pub version: u32,
    pub binding: Binding,
    pub namespace_fingerprint: String,
    pub running_fingerprint: String,
}

pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

pub(super) fn text(path: &Path) -> Result<String> {
    let text = path.to_str().ok_or_else(invalid)?;
    if !path.is_absolute() || text.len() > 32768 || text.chars().any(char::is_control) {
        return Err(invalid());
    }
    Ok(text.into())
}

fn invalid() -> Error {
    Error::new("sync_mutagen_environment_invalid")
}

/// Missing is distinct from unreadable, linked, special or changing objects.
pub(super) fn read(path: &Path, limit: u64) -> Result<Option<(Vec<u8>, String)>> {
    let parent = path.parent().ok_or_else(invalid)?;
    let Some(directory) = super::inventory::open_path(parent, false)? else {
        return Ok(None);
    };
    let name = path.file_name().ok_or_else(invalid)?;
    match directory.symlink_metadata(name) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(invalid()),
    }
    let file = super::inventory::open_regular(&directory, name, false, false)?;
    let metadata = file.metadata().map_err(|_| invalid())?;
    if !metadata.is_file() || metadata.len() > limit {
        return Err(invalid());
    }
    let identity = crate::platform::file_identity(&file).map_err(|_| invalid())?;
    let modified = metadata.modified().map_err(|_| invalid())?;
    let mut bytes = Vec::new();
    (&file)
        .take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid())?;
    let after = file.metadata().map_err(|_| invalid())?;
    if bytes.len() as u64 > limit
        || after.len() != metadata.len()
        || after.modified().map_err(|_| invalid())? != modified
    {
        return Err(invalid());
    }
    let current_directory = super::inventory::open_path(parent, false)?.ok_or_else(invalid)?;
    if super::inventory::directory_identity(&directory)?
        != super::inventory::directory_identity(&current_directory)?
    {
        return Err(invalid());
    }
    let current = super::inventory::open_regular(&current_directory, name, false, false)?;
    if crate::platform::file_identity(&current).map_err(|_| invalid())? != identity {
        return Err(invalid());
    }
    let fingerprint = digest(
        json!([
            identity,
            metadata.len(),
            format!("{modified:?}"),
            digest(&bytes)
        ])
        .to_string()
        .as_bytes(),
    );
    Ok(Some((bytes, fingerprint)))
}

pub(super) fn tools(paths: &AppPaths) -> (Vec<Tool>, Option<String>) {
    let binary = crate::mutagen::binary_path(paths);
    let Some(directory) = binary.parent() else {
        return (vec![], Some("sync_mutagen_missing".into()));
    };
    let mut tools = Vec::new();
    for name in ["mutagen", "ssh", "scp"] {
        let path = if name == "mutagen" {
            binary.clone()
        } else {
            crate::platform::managed_binary(directory, name)
        };
        let observed = (|| {
            let resolved = fs::canonicalize(&path).map_err(|_| invalid())?;
            let (_, fingerprint) = read(&resolved, 128 * 1024 * 1024)?.ok_or_else(invalid)?;
            Ok::<_, Error>(Tool {
                name: name.into(),
                path: text(&path)?,
                fingerprint: digest(
                    json!([text(&resolved)?, fingerprint])
                        .to_string()
                        .as_bytes(),
                ),
            })
        })();
        match observed {
            Ok(tool) => tools.push(tool),
            Err(_) => {
                return (
                    tools,
                    Some(
                        if name == "mutagen" {
                            "sync_mutagen_missing"
                        } else {
                            "sync_mutagen_proxy_missing"
                        }
                        .into(),
                    ),
                )
            }
        }
    }
    (tools, None)
}

pub(super) fn desired(paths: &AppPaths, tools: &[Tool]) -> Result<Binding> {
    let binary = crate::mutagen::binary_path(paths);
    let home = text(paths.home())?;
    let opened_home = super::inventory::open_path(paths.home(), false)?.ok_or_else(invalid)?;
    let home_identity = super::inventory::directory_identity(&opened_home)?;
    let ssh_directory = text(binary.parent().ok_or_else(invalid)?)?;
    // Values only feed a digest. Volatile shell bookkeeping is deliberately not
    // included; these variables affect transport and credential-store behavior.
    let environment: Vec<_> = [
        "PATH",
        "HOME",
        "USERPROFILE",
        "AGENT_REMOTE_SECRET_BACKEND",
        "SSH_AUTH_SOCK",
        "SSH_AGENT_PID",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_RUNTIME_DIR",
        "XDG_CONFIG_HOME",
        "MUTAGEN_LOG_LEVEL",
    ]
    .into_iter()
    .map(|name| {
        (
            name,
            std::env::var_os(name).map(|s| s.as_encoded_bytes().to_vec()),
        )
    })
    .collect();
    let fingerprint = digest(
        json!([home, home_identity, ssh_directory, tools, environment])
            .to_string()
            .as_bytes(),
    );
    Ok(Binding {
        home,
        ssh_directory,
        fingerprint,
    })
}

pub(super) fn marker(data: &Path) -> Result<(Option<Marker>, Option<String>)> {
    let Some((bytes, fingerprint)) = read(&data.join(MARKER), 16384)? else {
        return Ok((None, None));
    };
    let marker: Marker = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    if marker.version != 2
        || text(Path::new(&marker.binding.home))? != marker.binding.home
        || text(Path::new(&marker.binding.ssh_directory))? != marker.binding.ssh_directory
        || [
            &marker.binding.fingerprint,
            &marker.namespace_fingerprint,
            &marker.running_fingerprint,
        ]
        .iter()
        .any(|value| !valid_digest(value))
    {
        return Err(invalid());
    }
    Ok((Some(marker), Some(fingerprint)))
}

fn valid_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value.len() == 64
            && value
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
    })
}

pub(super) fn registration() -> (&'static str, Option<String>) {
    #[cfg(target_os = "macos")]
    {
        let Some(home) = crate::platform::user_home_dir() else {
            return ("unknown", Some("sync_mutagen_registration_unknown".into()));
        };
        match fs::symlink_metadata(home.join("Library/LaunchAgents/io.mutagen.mutagen.plist")) {
            Ok(_) => {
                return (
                    "external",
                    Some("sync_mutagen_registration_external".into()),
                )
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return ("unknown", Some("sync_mutagen_registration_unknown".into())),
        }
    }
    ("unmanaged", None)
}

pub(super) fn endpoint(data: &Path) -> Result<Option<String>> {
    let path = data.join("daemon/daemon.sock");
    #[cfg(unix)]
    {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_) => return Err(invalid()),
        };
        if !metadata.file_type().is_socket() {
            return Err(invalid());
        }
        Ok(Some(digest(
            json!([
                metadata.dev(),
                metadata.ino(),
                metadata.ctime(),
                metadata.ctime_nsec()
            ])
            .to_string()
            .as_bytes(),
        )))
    }
    #[cfg(windows)]
    {
        Ok(read(&path, 1024)?.map(|(_, identity)| identity))
    }
}

pub(super) fn publish(data: &Path, marker: &Marker) -> Result<()> {
    use std::io::Write;
    let failed = || Error::new("sync_mutagen_environment_write_failed").changed();
    let bytes = serde_json::to_vec(marker).map_err(|_| failed())?;
    let directory = super::inventory::open_path(data, false)?.ok_or_else(failed)?;
    if super::inventory::namespace(data, &directory)? != marker.namespace_fingerprint {
        return Err(failed());
    }
    use rand_core::RngCore;
    let mut nonce = [0u8; 16];
    rand_core::OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| failed())?;
    let name = format!(
        ".agent-remote-environment-{}.tmp",
        uuid::Uuid::from_bytes(nonce)
    );
    let result = (|| {
        let mut file =
            super::inventory::open_regular(&directory, std::ffi::OsStr::new(&name), true, true)?;
        file.write_all(&bytes).map_err(|_| failed())?;
        file.sync_all().map_err(|_| failed())?;
        directory
            .rename(&name, &directory, MARKER)
            .map_err(|_| failed())?;
        #[cfg(unix)]
        crate::platform::sync_directory(&directory).map_err(|_| failed())?;
        let current = super::inventory::open_path(data, false)?.ok_or_else(failed)?;
        if super::inventory::directory_identity(&current)?
            != super::inventory::directory_identity(&directory)?
        {
            return Err(failed());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = directory.remove_file(&name);
    }
    result.map_err(Error::changed)
}
