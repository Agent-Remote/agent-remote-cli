//! Bounded read-only inspection of the pinned Mutagen 0.18.1 disk protobufs.
use super::super::{Error, Result};
use super::{Endpoint, Session};
use cap_fs_ext::{DirExt, FollowSymlinks, MetadataExt, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Read,
    path::{Component, Path, PathBuf},
};

const FILE_LIMIT: u64 = 1024 * 1024;
const TOTAL_LIMIT: usize = 32 * 1024 * 1024;
const SESSION_LIMIT: usize = 4096;

pub(super) struct Inventory {
    pub namespace_fingerprint: Option<String>,
    pub fingerprint: String,
    pub sessions: Vec<Session>,
}

pub(super) fn invalid() -> Error {
    Error::new("sync_mutagen_inventory_invalid")
}
fn changed() -> Error {
    Error::new("sync_mutagen_inventory_changed")
}
fn limit() -> Error {
    Error::new("sync_mutagen_inventory_limit")
}
pub(super) fn digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

/// Traverse only directories; the fixed macOS filesystem aliases are the sole exception.
pub(super) fn open_path(path: &Path, create: bool) -> Result<Option<Dir>> {
    if !path.is_absolute() || path.as_os_str().len() > 4096 {
        return Err(invalid());
    }
    let mut root = PathBuf::new();
    let mut names = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => root.push(component.as_os_str()),
            Component::Normal(name) => names.push(name.to_owned()),
            _ => return Err(invalid()),
        }
    }
    let mut directory =
        Dir::open_ambient_dir(&root, cap_std::ambient_authority()).map_err(|_| invalid())?;
    for name in names {
        let metadata = match directory.symlink_metadata(&name) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && !create => return Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = cap_std::fs::DirBuilder::new();
                #[cfg(unix)]
                {
                    use cap_std::fs::DirBuilderExt;
                    builder.mode(0o700);
                }
                directory
                    .create_dir_with(&name, &builder)
                    .map_err(|_| invalid())?;
                directory.symlink_metadata(&name).map_err(|_| invalid())?
            }
            Err(_) => return Err(invalid()),
        };
        #[cfg(target_os = "macos")]
        if root == Path::new("/")
            && matches!(name.to_str(), Some("tmp" | "var" | "etc"))
            && metadata.file_type().is_symlink()
        {
            root = std::fs::canonicalize(root.join(&name)).map_err(|_| invalid())?;
            directory = Dir::open_ambient_dir(&root, cap_std::ambient_authority())
                .map_err(|_| invalid())?;
            continue;
        }
        if !metadata.is_dir() || metadata.file_type().is_symlink() || reparse(&metadata) {
            return Err(invalid());
        }
        let next = directory.open_dir_nofollow(&name).map_err(|_| invalid())?;
        let actual = next.dir_metadata().map_err(|_| invalid())?;
        if metadata.dev() != actual.dev() || metadata.ino() != actual.ino() {
            return Err(changed());
        }
        directory = next;
        root.push(name);
    }
    Ok(Some(directory))
}

fn reparse(metadata: &cap_std::fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use cap_std::fs::MetadataExt;
        metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        let _ = metadata;
        false
    }
}

pub(super) fn directory_identity(directory: &Dir) -> Result<String> {
    crate::platform::file_identity(
        &directory
            .try_clone()
            .map_err(|_| invalid())?
            .into_std_file(),
    )
    .map_err(|_| invalid())
}

pub(super) fn namespace(path: &Path, directory: &Dir) -> Result<String> {
    let physical = std::fs::canonicalize(path).map_err(|_| invalid())?;
    Ok(digest(
        format!(
            "mutagen-environment-namespace-v1\0{}\0{}",
            physical.to_str().ok_or_else(invalid)?,
            directory_identity(directory)?
        )
        .as_bytes(),
    ))
}

pub(super) fn open_regular(
    directory: &Dir,
    name: &std::ffi::OsStr,
    write: bool,
    create: bool,
) -> Result<std::fs::File> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .write(write)
        .create_new(create)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NONBLOCK);
    }
    let file = directory
        .open_with(name, &options)
        .map_err(|_| invalid())?
        .into_std();
    crate::platform::validate_single_regular_file(&file).map_err(|_| invalid())?;
    Ok(file)
}

pub(super) fn read(data: &Path) -> Result<Inventory> {
    let Some(directory) = open_path(data, false)? else {
        return Ok(Inventory {
            namespace_fingerprint: None,
            fingerprint: digest(b"mutagen-environment-empty-v1"),
            sessions: vec![],
        });
    };
    let namespace_fingerprint = namespace(data, &directory)?;
    let first = scan(data)?;
    // Reopen every path and re-read bounded contents: catches ancestor replacement,
    // late edits to an earlier file, and concurrent additions/removals.
    let second = scan(data)?;
    let after = open_path(data, false)?.ok_or_else(changed)?;
    if namespace(data, &after)? != namespace_fingerprint || first.0 != second.0 {
        return Err(changed());
    }
    Ok(Inventory {
        fingerprint: digest(format!("{}\0{}", namespace_fingerprint, first.0).as_bytes()),
        namespace_fingerprint: Some(namespace_fingerprint),
        sessions: first.1,
    })
}

fn scan(data: &Path) -> Result<(String, Vec<Session>)> {
    let mut fingerprint = String::new();
    let mut sessions = Vec::new();
    let mut total = 0usize;
    let mut entries_count = 0usize;
    for (kind, subpath) in [("sync", "sessions"), ("forward", "forwarding/sessions")] {
        let Some(directory) = open_path(&data.join(subpath), false)? else {
            fingerprint.push_str(&format!("{kind}:absent\n"));
            continue;
        };
        fingerprint.push_str(&format!("{kind}:{}\n", directory_identity(&directory)?));
        let mut names = Vec::new();
        for entry in directory.entries().map_err(|_| invalid())? {
            entries_count += 1;
            if entries_count > SESSION_LIMIT {
                return Err(limit());
            }
            names.push(entry.map_err(|_| invalid())?.file_name());
        }
        names.sort();
        for name in names {
            let text = name.to_str().ok_or_else(invalid)?;
            // Upstream ignores atomic temporary files and other non-identifiers.
            fingerprint.push_str(&format!("entry:{}\n", digest(text.as_bytes())));
            if !identifier(text) {
                continue;
            }
            let mut file = open_regular(&directory, &name, false, false)?;
            let before = file.metadata().map_err(|_| invalid())?;
            if before.len() > FILE_LIMIT {
                return Err(limit());
            }
            let identity = crate::platform::file_identity(&file).map_err(|_| invalid())?;
            let mut bytes = Vec::new();
            (&mut file)
                .take(FILE_LIMIT + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| invalid())?;
            total = total.checked_add(bytes.len()).ok_or_else(limit)?;
            if bytes.len() as u64 > FILE_LIMIT || total > TOTAL_LIMIT {
                return Err(limit());
            }
            let after = file.metadata().map_err(|_| invalid())?;
            if before.len() != after.len()
                || before.modified().map_err(|_| invalid())?
                    != after.modified().map_err(|_| invalid())?
            {
                return Err(changed());
            }
            let session = decode(&bytes, kind)?;
            if session.identifier != text {
                return Err(invalid());
            }
            fingerprint.push_str(&format!(
                "{}:{}:{}\n",
                kind, identity, session.configuration_fingerprint
            ));
            sessions.push(session);
        }
        let reopened = open_path(&data.join(subpath), false)?.ok_or_else(changed)?;
        if directory_identity(&reopened)? != directory_identity(&directory)? {
            return Err(changed());
        }
    }
    Ok((digest(fingerprint.as_bytes()), sessions))
}

fn identifier(value: &str) -> bool {
    let b = value.as_bytes();
    (b.len() == 48
        && b[..4].iter().all(u8::is_ascii_lowercase)
        && b[4] == b'_'
        && b[5..].iter().all(u8::is_ascii_alphanumeric))
        || (b.len() == 36
            && b.iter().enumerate().all(|(i, c)| {
                if [8, 13, 18, 23].contains(&i) {
                    *c == b'-'
                } else {
                    c.is_ascii_digit() || (b'a'..=b'f').contains(c)
                }
            }))
}

// Only varints and length-delimited fields occur in the pinned schemas. Duplicate
// singular fields are rejected, rather than silently misinterpreting proto merge.
#[derive(Clone, Copy)]
enum Value<'a> {
    Number(u64),
    Bytes(&'a [u8]),
}
struct Fields<'a>(Vec<(u32, Value<'a>)>);
impl<'a> Fields<'a> {
    fn parse(mut bytes: &'a [u8], allowed: &[u32], repeated: &[u32]) -> Result<Self> {
        let mut fields = Vec::new();
        let mut seen = BTreeSet::new();
        while !bytes.is_empty() {
            if fields.len() >= 65536 {
                return Err(limit());
            }
            let key = varint(&mut bytes)?;
            let tag = u32::try_from(key >> 3).map_err(|_| invalid())?;
            if !allowed.contains(&tag) || (!repeated.contains(&tag) && !seen.insert(tag)) {
                return Err(invalid());
            }
            let value = match key & 7 {
                0 => Value::Number(varint(&mut bytes)?),
                2 => {
                    let count = usize::try_from(varint(&mut bytes)?).map_err(|_| invalid())?;
                    let value = bytes.get(..count).ok_or_else(invalid)?;
                    bytes = &bytes[count..];
                    Value::Bytes(value)
                }
                _ => return Err(invalid()),
            };
            fields.push((tag, value));
        }
        Ok(Self(fields))
    }
    fn number(&self, tag: u32) -> Result<u64> {
        match self.0.iter().find(|(t, _)| *t == tag).map(|(_, v)| v) {
            None => Ok(0),
            Some(Value::Number(n)) => Ok(*n),
            _ => Err(invalid()),
        }
    }
    fn bytes(&self, tag: u32) -> Result<Option<&'a [u8]>> {
        match self.0.iter().find(|(t, _)| *t == tag).map(|(_, v)| v) {
            None => Ok(None),
            Some(Value::Bytes(b)) => Ok(Some(b)),
            _ => Err(invalid()),
        }
    }
    fn text(&self, tag: u32) -> Result<String> {
        text(self.bytes(tag)?.unwrap_or_default())
    }
    fn required(&self, tag: u32) -> Result<&'a [u8]> {
        self.bytes(tag)?.ok_or_else(invalid)
    }
    fn maps(&self, tag: u32) -> Result<usize> {
        let mut keys = BTreeSet::new();
        for (_, value) in self.0.iter().filter(|(t, _)| *t == tag) {
            let Value::Bytes(bytes) = value else {
                return Err(invalid());
            };
            let entry = Self::parse(bytes, &[1, 2], &[])?;
            if !keys.insert(entry.text(1)?) {
                return Err(invalid());
            }
            entry.text(2)?;
        }
        Ok(keys.len())
    }
}
fn varint(bytes: &mut &[u8]) -> Result<u64> {
    let mut value = 0u64;
    for index in 0..10 {
        let byte = *bytes.first().ok_or_else(invalid)?;
        *bytes = &bytes[1..];
        if index == 9 && byte > 1 {
            return Err(invalid());
        }
        value |= u64::from(byte & 127) << (index * 7);
        if byte & 128 == 0 {
            return Ok(value);
        }
    }
    Err(invalid())
}
fn text(bytes: &[u8]) -> Result<String> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid())?;
    if value.len() > 65536 || value.contains('\0') {
        return Err(invalid());
    }
    Ok(value.to_owned())
}

fn decode(bytes: &[u8], kind: &str) -> Result<Session> {
    let fields = Fields::parse(
        bytes,
        &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14],
        &[13],
    )?;
    let identifier = fields.text(1)?;
    if !self::identifier(&identifier) || fields.number(2)? != 1 {
        return Err(invalid());
    }
    let timestamp = Fields::parse(fields.required(3)?, &[1, 2], &[])?;
    timestamp.number(1)?;
    if timestamp.number(2)? > 999_999_999
        || fields.number(4)? > 0
        || fields.number(5)? > 18
        || (fields.number(5)? == 18 && fields.number(6)? > 1)
    {
        return Err(invalid());
    }
    fields.maps(13)?;
    let sync = kind == "sync";
    let paused = fields.number(if sync { 10 } else { 14 })?;
    if paused > 1 {
        return Err(invalid());
    }
    let name = fields.text(if sync { 14 } else { 12 })?;
    if name == "defaults"
        || name.chars().enumerate().any(|(i, c)| {
            if i == 0 {
                !c.is_alphabetic()
            } else {
                !c.is_alphanumeric() && c != '-'
            }
        })
        || (!name.is_empty() && uuid::Uuid::parse_str(&name).is_ok())
    {
        return Err(invalid());
    }
    for tag in if sync { [9, 11, 12] } else { [9, 10, 11] } {
        let configuration = fields.bytes(tag)?;
        if configuration.is_none() && (tag == 9 || !sync) {
            return Err(invalid());
        }
        validate_configuration(configuration.unwrap_or_default(), sync, tag != 9)?;
    }
    Ok(Session {
        kind: kind.into(),
        identifier,
        name,
        paused: paused != 0,
        source: endpoint(fields.required(7)?, sync)?,
        destination: endpoint(fields.required(8)?, sync)?,
        configuration_fingerprint: digest(bytes),
    })
}

fn endpoint(bytes: &[u8], sync: bool) -> Result<Endpoint> {
    let fields = Fields::parse(bytes, &[1, 2, 3, 4, 5, 6, 7, 8], &[6, 8])?;
    let protocol = fields.number(1)?;
    if fields.number(7)? != u64::from(!sync) {
        return Err(invalid());
    }
    let result = Endpoint {
        protocol: match protocol {
            0 => "local",
            1 => "ssh",
            11 => "docker",
            _ => return Err(invalid()),
        }
        .into(),
        user: fields.text(2)?,
        host: fields.text(3)?,
        port: u32::try_from(fields.number(4)?).map_err(|_| invalid())?,
        path: fields.text(5)?,
    };
    let environment = fields.maps(6)?;
    let parameters = fields.maps(8)?;
    if result.path.is_empty()
        || [&result.user, &result.host, &result.path]
            .iter()
            .any(|v| v.chars().any(char::is_control))
        || (protocol == 0
            && (!result.user.is_empty()
                || !result.host.is_empty()
                || result.port != 0
                || environment != 0
                || parameters != 0))
        || (protocol == 1 && (result.host.is_empty() || result.port > 65535 || environment != 0))
        || (protocol == 11 && (result.host.is_empty() || result.port != 0))
        || (sync && protocol == 0 && !Path::new(&result.path).is_absolute())
    {
        return Err(invalid());
    }
    if !sync {
        let (transport, address) = result.path.split_once(':').ok_or_else(invalid)?;
        if !matches!(transport, "tcp" | "tcp4" | "tcp6" | "unix" | "npipe")
            || address.is_empty()
            || (protocol == 0 && transport == "unix" && !Path::new(address).is_absolute())
        {
            return Err(invalid());
        }
    }
    Ok(result)
}

fn validate_configuration(bytes: &[u8], sync: bool, endpoint_specific: bool) -> Result<()> {
    let allowed: &[u32] = if sync {
        &[
            1, 11, 12, 13, 14, 15, 16, 17, 21, 22, 31, 32, 33, 34, 61, 63, 64, 65, 66, 81,
        ]
    } else {
        &[41, 42, 43, 44]
    };
    let fields = Fields::parse(bytes, allowed, if sync { &[31, 32] } else { &[] })?;
    for (tag, value) in &fields.0 {
        if sync
            && endpoint_specific
            && (matches!(*tag, 31 | 32)
                || (matches!(*tag, 1 | 11 | 17 | 33 | 34 | 61) && fields.number(*tag)? != 0))
        {
            return Err(invalid());
        }
        if matches!(*tag, 31 | 32 | 65 | 66 | 42 | 43) {
            let Value::Bytes(bytes) = value else {
                return Err(invalid());
            };
            text(bytes)?;
        } else {
            let Value::Number(number) = value else {
                return Err(invalid());
            };
            let max = match *tag {
                1 | 16 | 17 | 21 | 81 => 3,
                11 => 4,
                14 | 15 | 33 | 34 | 61 | 41 => 2,
                63 | 64 | 44 => 0o777,
                22 => u32::MAX as u64,
                12 | 13 => u64::MAX,
                _ => return Err(invalid()),
            };
            if *number > max {
                return Err(invalid());
            }
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../../../tests/unit/src/mutagen_environment_inventory.rs"]
mod tests;
