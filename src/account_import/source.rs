//! Descriptor-relative, bounded source capture. No file bytes are persisted.
use super::{
    types::{hash, source_error},
    Discovery, Error, ManifestEntry, Result, Selection,
};
use crate::api::ToolAccountConfigImportFile;
use base64::{engine::general_purpose::STANDARD, Engine};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, Metadata, OpenOptions};
use std::{
    collections::BTreeMap,
    io::Read,
    path::{Component, Path, PathBuf},
};

pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const MAX_TOTAL_BYTES: u64 = 8 * 1024 * 1024;
pub const MAX_ENTRIES: usize = 2048;
const MAX_DEPTH: usize = 32;
const MAX_PATH: usize = 1024;

pub(crate) struct Capture {
    pub discovery: Discovery,
    pub manifest: Vec<ManifestEntry>,
    pub files: Vec<ToolAccountConfigImportFile>,
    pub total_bytes: u64,
    pub fingerprint: String,
}

pub fn exclusions(exclude_skills: bool) -> Vec<String> {
    let mut paths = vec![
        "~/.claude.json".into(),
        "~/.claude/cache".into(),
        "~/.claude/logs".into(),
        "~/.claude/transcripts".into(),
    ];
    if exclude_skills {
        paths.push("~/.claude/skills".into());
    }
    paths.sort();
    paths
}
fn invalid() -> Error {
    Error::new("account_import_source_invalid")
}
fn changed() -> Error {
    Error::new("account_import_source_changed")
}
fn limit() -> Error {
    Error::new("account_import_source_limit")
}
fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && name.trim() == name
        && !name
            .chars()
            .any(|c| c.is_control() || c == '/' || c == '\\')
}
fn safe_metadata(meta: &Metadata) -> Result<()> {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        if meta.file_attributes() & 0x400 != 0 {
            return Err(invalid());
        }
    }
    if meta.is_symlink()
        || (!meta.is_file() && !meta.is_dir())
        || (meta.is_file() && meta.nlink() != 1)
    {
        return Err(invalid());
    }
    Ok(())
}
fn metadata_key(meta: &Metadata) -> Result<String> {
    safe_metadata(meta)?;
    let mut key = format!(
        "{}:{}:{}:{}:{:?}",
        meta.dev(),
        meta.ino(),
        meta.len(),
        meta.nlink(),
        meta.modified().map_err(source_error)?
    );
    #[cfg(unix)]
    {
        use cap_std::fs::MetadataExt;
        key.push_str(&format!(
            ":{}:{}:{}",
            meta.mode(),
            meta.ctime(),
            meta.ctime_nsec()
        ));
    }
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        key.push_str(&format!(
            ":{}:{}",
            meta.creation_time(),
            meta.file_attributes()
        ));
    }
    Ok(key)
}
fn same(a: &Metadata, b: &Metadata) -> Result<()> {
    if metadata_key(a)? != metadata_key(b)? {
        return Err(changed());
    }
    Ok(())
}
fn open_dir(parent: &Dir, name: &str) -> Result<Dir> {
    let before = parent.symlink_metadata(name).map_err(source_error)?;
    safe_metadata(&before)?;
    if !before.is_dir() {
        return Err(invalid());
    }
    let dir = parent.open_dir_nofollow(name).map_err(source_error)?;
    let after = dir.dir_metadata().map_err(source_error)?;
    safe_metadata(&after)?;
    // Ancestor directories may gain unrelated siblings while opening the source.
    // Bind their object identity, not their mutable directory timestamps/length.
    if before.dev() != after.dev() || before.ino() != after.ino() || !after.is_dir() {
        return Err(changed());
    }
    let reopened = parent.open_dir_nofollow(name).map_err(source_error)?;
    let identity =
        crate::platform::file_identity(&dir.try_clone().map_err(source_error)?.into_std_file())
            .map_err(source_error)?;
    if crate::platform::file_identity(&reopened.into_std_file()).map_err(source_error)? != identity
    {
        return Err(changed());
    }
    Ok(dir)
}
fn directory_key(dir: &Dir) -> Result<String> {
    let file = dir.try_clone().map_err(source_error)?.into_std_file();
    Ok(format!(
        "{}:{}",
        crate::platform::file_identity(&file).map_err(source_error)?,
        metadata_key(&dir.dir_metadata().map_err(source_error)?)?
    ))
}
fn open_home(path: &Path) -> Result<Dir> {
    if !path.is_absolute()
        || path
            .to_str()
            .is_none_or(|s| s.len() > 32768 || s.chars().any(char::is_control))
    {
        return Err(invalid());
    }
    let mut anchor = PathBuf::new();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir if names.is_empty() => {
                anchor.push(component.as_os_str())
            }
            Component::Normal(name) => names.push(name.to_str().ok_or_else(invalid)?.to_owned()),
            _ => return Err(invalid()),
        }
    }
    let mut dir =
        Dir::open_ambient_dir(anchor, cap_std::ambient_authority()).map_err(source_error)?;
    for name in names {
        dir = open_dir(&dir, &name)?;
    }
    Ok(dir)
}
fn source_root(home: &Dir) -> Result<Option<Dir>> {
    match home.symlink_metadata(".claude") {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(source_error(e)),
        Ok(_) => open_dir(home, ".claude").map(Some),
    }
}
fn names(dir: &Dir, remaining: usize) -> Result<Vec<String>> {
    let mut result = Vec::new();
    for entry in dir.entries().map_err(source_error)? {
        if result.len() >= remaining {
            return Err(limit());
        }
        let name = entry
            .map_err(source_error)?
            .file_name()
            .into_string()
            .map_err(|_| invalid())?;
        if !valid_name(&name) {
            return Err(invalid());
        }
        result.push(name);
    }
    result.sort();
    Ok(result)
}
fn selected(dir: &Dir, selection: &Selection) -> Result<Vec<String>> {
    let mut paths = Vec::new();
    for name in names(dir, MAX_ENTRIES)? {
        if name == "skills" && selection.exclude_skills {
            continue;
        }
        let normal = [
            "settings.json",
            "CLAUDE.md",
            "agents",
            "skills",
            "plugins",
            "hooks",
            "rules",
        ]
        .contains(&name.as_str());
        let history = selection.include_resume_history
            && [
                "projects",
                "sessions",
                "history.jsonl",
                "file-history",
                "plans",
                "tasks",
                "session-env",
            ]
            .contains(&name.as_str());
        if normal || history || name.ends_with(".md") {
            let metadata = dir.symlink_metadata(&name).map_err(source_error)?;
            safe_metadata(&metadata)?;
            if normal || history || metadata.is_file() {
                paths.push(format!("~/.claude/{name}"));
            }
        }
    }
    if paths.len() > 64 {
        return Err(limit());
    }
    Ok(paths)
}
pub fn discover_at(home: &Path, selection: &Selection) -> Result<Discovery> {
    if !selection.valid() {
        return Err(Error::new("invalid_params"));
    }
    let home_dir = open_home(home)?;
    let include = match source_root(&home_dir)? {
        Some(dir) => selected(&dir, selection)?,
        None => Vec::new(),
    };
    Ok(Discovery {
        source_home: home.to_owned(),
        selection: selection.clone(),
        include,
        exclude: exclusions(selection.exclude_skills),
    })
}

struct Walker {
    entries: usize,
    path_bytes: usize,
    bytes: u64,
    records: BTreeMap<String, String>,
    manifest: Vec<ManifestEntry>,
    files: Vec<ToolAccountConfigImportFile>,
    read: bool,
}
impl Walker {
    fn entry(&mut self, parent: &Dir, name: &str, path: &str, depth: usize) -> Result<()> {
        self.entries += 1;
        self.path_bytes += path.len();
        if self.path_bytes > 256 * 1024 {
            return Err(limit());
        }
        if self.entries > MAX_ENTRIES || depth > MAX_DEPTH || path.len() > MAX_PATH {
            return Err(limit());
        }
        let before = parent.symlink_metadata(name).map_err(source_error)?;
        safe_metadata(&before)?;
        if before.is_dir() {
            let dir = open_dir(parent, name)?;
            self.records.insert(path.to_owned(), directory_key(&dir)?);
            for child in names(&dir, MAX_ENTRIES - self.entries)? {
                self.entry(&dir, &child, &format!("{path}/{child}"), depth + 1)?;
            }
            same(&before, &dir.dir_metadata().map_err(source_error)?)?;
        } else {
            if before.len() > MAX_FILE_BYTES || before.len() > MAX_TOTAL_BYTES - self.bytes {
                return Err(limit());
            }
            #[cfg(test)]
            hooks::before_open();
            let mut options = OpenOptions::new();
            options.read(true).follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NONBLOCK);
            }
            let mut file = parent.open_with(name, &options).map_err(source_error)?;
            same(&before, &file.metadata().map_err(source_error)?)?;
            let identity =
                crate::platform::file_identity(&file.try_clone().map_err(source_error)?.into_std())
                    .map_err(source_error)?;
            self.records.insert(
                path.to_owned(),
                format!("{identity}:{}", metadata_key(&before)?),
            );
            if self.read {
                let mut bytes = Vec::new();
                file.by_ref()
                    .take(MAX_FILE_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map_err(source_error)?;
                if bytes.len() as u64 > MAX_FILE_BYTES
                    || bytes.len() as u64 > MAX_TOTAL_BYTES - self.bytes
                {
                    return Err(limit());
                }
                if bytes.len() as u64 != before.len() {
                    return Err(changed());
                }
                self.manifest.push(ManifestEntry {
                    path: path.into(),
                    size: bytes.len() as u64,
                    sha256: hash(&bytes),
                    mode: 0o600,
                });
                self.files.push(ToolAccountConfigImportFile {
                    path: path.into(),
                    content_base64: STANDARD.encode(bytes),
                    mode: 0o600,
                });
            }
            self.bytes += before.len();
            same(&before, &file.metadata().map_err(source_error)?)?;
            // Reopening validates the full native identity, including Windows 128-bit IDs.
            let current = parent.open_with(name, &options).map_err(source_error)?;
            same(&before, &current.metadata().map_err(source_error)?)?;
            if crate::platform::file_identity(&current.into_std()).map_err(source_error)?
                != identity
            {
                return Err(changed());
            }
        }
        same(
            &before,
            &parent.symlink_metadata(name).map_err(source_error)?,
        )
    }
}
fn walk(home: &Path, selection: &Selection, read: bool) -> Result<(Discovery, Walker)> {
    let root = open_home(home)?;
    let mut walker = Walker {
        entries: 0,
        path_bytes: 0,
        bytes: 0,
        records: BTreeMap::new(),
        manifest: Vec::new(),
        files: Vec::new(),
        read,
    };
    // Bind home identity, but not its mutable unrelated directory contents.
    let home_id =
        crate::platform::file_identity(&root.try_clone().map_err(source_error)?.into_std_file())
            .map_err(source_error)?;
    walker.records.insert("$HOME".into(), home_id);
    let include = if let Some(claude) = source_root(&root)? {
        walker
            .records
            .insert("~/.claude".into(), directory_key(&claude)?);
        let include = selected(&claude, selection)?;
        for path in &include {
            let name = path.strip_prefix("~/.claude/").ok_or_else(invalid)?;
            walker.entry(&claude, name, path, 1)?;
        }
        if walker.records.get("~/.claude") != Some(&directory_key(&claude)?) {
            return Err(changed());
        }
        include
    } else {
        Vec::new()
    };
    Ok((
        Discovery {
            source_home: home.into(),
            selection: selection.clone(),
            include,
            exclude: exclusions(selection.exclude_skills),
        },
        walker,
    ))
}
pub(crate) fn capture(home: &Path, selection: &Selection) -> Result<Capture> {
    if !selection.valid() {
        return Err(Error::new("invalid_params"));
    }
    let (discovery, mut first) = walk(home, selection, true)?;
    #[cfg(test)]
    hooks::after_read();
    let (second_discovery, second) = walk(home, selection, false)?;
    if first.records != second.records || discovery.include != second_discovery.include {
        return Err(changed());
    }
    first.manifest.sort_by(|a, b| a.path.cmp(&b.path));
    first.files.sort_by(|a, b| a.path.cmp(&b.path));
    let fingerprint = hash(&serde_json::to_vec(&first.records).map_err(source_error)?);
    Ok(Capture {
        discovery,
        manifest: first.manifest,
        files: first.files,
        total_bytes: first.bytes,
        fingerprint,
    })
}

#[cfg(test)]
#[path = "../../tests/unit/src/account_import_source.rs"]
mod hooks;
