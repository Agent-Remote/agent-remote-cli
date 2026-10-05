//! Cross-platform local attachment capture and workspace staging.
//!
//! Claude's terminal UI accepts image/file paths as attachments.  A remote
//! session cannot read the local desktop clipboard or local drag paths, so the
//! launcher stages those bytes inside the synchronized workspace and returns
//! the corresponding remote path.

use crate::mutagen;
use crate::{api::SyncSessionData, config::AppPaths};
use anyhow::{bail, Context, Result};
#[cfg(any(target_os = "linux", target_os = "windows"))]
use base64::Engine;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

const MAX_IMAGE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILES_PER_PASTE: usize = 32;
const ATTACHMENT_DIR: &str = ".agent-remote/attachments";
const BRACKETED_PASTE_START: &[u8] = b"\x1b[200~";
const BRACKETED_PASTE_END: &[u8] = b"\x1b[201~";
static ATTACHMENT_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct AttachmentContext {
    pub local_workspace: PathBuf,
    pub remote_workspace: String,
    pub session_id: String,
    pub sync: SyncSessionData,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ClipboardPayload {
    Image {
        bytes: Vec<u8>,
        extension: &'static str,
    },
    Files(Vec<PathBuf>),
}

/// Events emitted by a terminal input stream.  Keeping bracketed paste
/// framing intact lets normal text paste retain Claude's native behavior while
/// allowing file drops to be replaced with synchronized remote paths.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum InputEvent {
    Bytes(Vec<u8>),
    ClipboardPaste,
    BracketedPaste(Vec<u8>),
}

#[derive(Default)]
pub(crate) struct InputDecoder {
    pending: Vec<u8>,
    in_paste: bool,
    paste: Vec<u8>,
}

impl InputDecoder {
    pub(crate) fn feed(&mut self, input: &[u8]) -> Vec<InputEvent> {
        let mut events = Vec::new();
        for &byte in input {
            if self.in_paste {
                self.paste.push(byte);
                if self.paste.ends_with(BRACKETED_PASTE_END) {
                    let length = self.paste.len() - BRACKETED_PASTE_END.len();
                    self.paste.truncate(length);
                    self.in_paste = false;
                    events.push(InputEvent::BracketedPaste(std::mem::take(&mut self.paste)));
                } else if self.paste.len() > 1024 * 1024 {
                    // A malformed or very large paste is forwarded as text so
                    // the input path cannot consume unbounded memory.
                    let mut bytes = BRACKETED_PASTE_START.to_vec();
                    bytes.extend(std::mem::take(&mut self.paste));
                    self.in_paste = false;
                    events.push(InputEvent::Bytes(bytes));
                }
                continue;
            }
            if self.pending.is_empty() && byte == 0x16 {
                events.push(InputEvent::ClipboardPaste);
                continue;
            }
            self.pending.push(byte);
            while !BRACKETED_PASTE_START.starts_with(&self.pending) {
                let first = self.pending.remove(0);
                events.push(InputEvent::Bytes(vec![first]));
                if self.pending.is_empty() {
                    break;
                }
            }
            if self.pending == BRACKETED_PASTE_START {
                self.pending.clear();
                self.in_paste = true;
            }
        }
        events
    }

    pub(crate) fn finish(&mut self) -> Vec<InputEvent> {
        let mut events = Vec::new();
        if self.in_paste {
            let mut bytes = BRACKETED_PASTE_START.to_vec();
            bytes.extend(std::mem::take(&mut self.paste));
            events.push(InputEvent::Bytes(bytes));
            self.in_paste = false;
        }
        if !self.pending.is_empty() {
            events.push(InputEvent::Bytes(std::mem::take(&mut self.pending)));
        }
        events
    }
}

impl AttachmentContext {
    #[allow(dead_code)]
    pub fn new(
        local_workspace: impl Into<PathBuf>,
        remote_workspace: impl Into<String>,
        session_id: impl Into<String>,
        sync: SyncSessionData,
    ) -> Self {
        Self {
            local_workspace: local_workspace.into(),
            remote_workspace: remote_workspace.into(),
            session_id: session_id.into(),
            sync,
        }
    }

    /// Stage an image or one or more files and flush the existing sync session.
    /// The returned paths are safe to paste into the remote Claude prompt.
    pub fn stage_payload(
        &self,
        paths: &AppPaths,
        payload: ClipboardPayload,
    ) -> Result<Vec<String>> {
        let root = self.attachment_root()?;
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create attachment directory {}", root.display()))?;
        let mut remote = Vec::new();
        match payload {
            ClipboardPayload::Image { bytes, extension } => {
                if bytes.is_empty() || bytes.len() as u64 > MAX_IMAGE_BYTES {
                    bail!("clipboard image exceeds the 64 MiB attachment limit");
                }
                let destination = root.join(format!("{}.{extension}", unique_id()));
                write_private(&destination, &bytes)?;
                remote.push(self.remote_path(&destination)?);
            }
            ClipboardPayload::Files(files) => {
                if files.is_empty() || files.len() > MAX_FILES_PER_PASTE {
                    bail!("file drop contains too many files");
                }
                let mut seen = BTreeSet::new();
                for source in files {
                    if fs::symlink_metadata(&source)
                        .map(|metadata| metadata.file_type().is_symlink())
                        .unwrap_or(false)
                    {
                        bail!("symbolic links are not allowed in dropped attachments");
                    }
                    let path = source.canonicalize().with_context(|| {
                        format!("dropped path does not exist: {}", source.display())
                    })?;
                    let key = path.to_string_lossy().to_string();
                    if !seen.insert(key) {
                        continue;
                    }
                    remote.push(self.stage_file(&path, &root)?);
                }
            }
        }
        if remote.is_empty() {
            bail!("no usable attachment was found");
        }
        mutagen::resolve(paths, &self.sync, false)?;
        Ok(remote)
    }

    fn stage_file(&self, source: &Path, root: &Path) -> Result<String> {
        if source.strip_prefix(&self.local_workspace).is_ok() {
            return self.remote_path(source);
        }
        let metadata = fs::metadata(source)
            .with_context(|| format!("failed to inspect dropped path {}", source.display()))?;
        if metadata.is_file() {
            if metadata.len() > MAX_FILE_BYTES {
                bail!(
                    "dropped file exceeds the 256 MiB attachment limit: {}",
                    source.display()
                );
            }
        } else if !metadata.is_dir() {
            bail!("unsupported dropped path: {}", source.display());
        }
        let name = source
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty() && *value != "." && *value != "..")
            .unwrap_or("attachment");
        let destination = root.join(format!("{}-{name}", unique_id()));
        if metadata.is_dir() {
            if let Err(error) = copy_dir_bounded(source, &destination, MAX_FILE_BYTES) {
                let _ = fs::remove_dir_all(&destination);
                return Err(error);
            }
        } else {
            fs::copy(source, &destination)
                .with_context(|| format!("failed to stage dropped file {}", source.display()))?;
            set_private(&destination)?;
        }
        self.remote_path(&destination)
    }

    fn attachment_root(&self) -> Result<PathBuf> {
        if self.session_id.is_empty()
            || self.session_id.len() > 128
            || !self
                .session_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(&byte))
        {
            bail!("invalid session id for attachment staging");
        }
        Ok(self
            .local_workspace
            .join(ATTACHMENT_DIR)
            .join(&self.session_id))
    }

    fn remote_path(&self, local: &Path) -> Result<String> {
        let relative = local
            .strip_prefix(&self.local_workspace)
            .context("attachment is outside the synchronized workspace")?;
        let relative = relative
            .to_str()
            .context("attachment path is not valid UTF-8")?
            .replace('\\', "/");
        let root = self.remote_workspace.trim_end_matches('/');
        Ok(format!("{root}/{relative}"))
    }
}

/// Read the richest available local clipboard payload. Text is intentionally
/// omitted so ordinary Ctrl+V keeps Claude's native text behavior.
pub fn read_clipboard_payload() -> Option<ClipboardPayload> {
    if let Some(bytes) = read_image() {
        return Some(ClipboardPayload::Image {
            extension: image_extension(&bytes),
            bytes,
        });
    }
    let files = read_clipboard_files();
    (!files.is_empty()).then_some(ClipboardPayload::Files(files))
}

/// Parse a terminal bracketed paste commonly produced by Finder/Explorer file
/// drops. Returns paths only when every non-empty item resolves locally.
pub fn parse_dropped_paths(input: &str) -> Option<Vec<PathBuf>> {
    let mut paths = Vec::new();
    for raw in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if raw.starts_with('#') {
            continue;
        }
        let value = decode_uri_or_shell_path(raw)?;
        let path = PathBuf::from(value);
        if !path.exists() {
            return None;
        }
        paths.push(path);
    }
    if paths.is_empty() || paths.len() > MAX_FILES_PER_PASTE {
        None
    } else {
        Some(paths)
    }
}

fn decode_uri_or_shell_path(value: &str) -> Option<String> {
    if let Some(uri) = value.strip_prefix("file://") {
        let uri = uri.strip_prefix("localhost").unwrap_or(uri);
        let decoded = percent_decode(uri)?;
        #[cfg(windows)]
        if decoded.starts_with('/')
            && decoded.as_bytes().get(2) == Some(&b':')
            && decoded
                .as_bytes()
                .get(1)
                .is_some_and(u8::is_ascii_alphabetic)
        {
            return Some(decoded[1..].to_string());
        }
        return Some(decoded);
    }
    #[cfg(windows)]
    if value.starts_with(r"\\")
        || (value.len() >= 3
            && value.as_bytes()[1] == b':'
            && matches!(value.as_bytes()[2], b'\\' | b'/'))
    {
        let value = value.trim_matches(['\'', '"']);
        let mut output = String::with_capacity(value.len());
        let mut chars = value.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '\\'
                && chars
                    .peek()
                    .is_some_and(|next| matches!(next, ' ' | '\t' | '\'' | '"'))
            {
                output.push(chars.next().expect("peeked character exists"));
            } else {
                output.push(ch);
            }
        }
        return Some(output);
    }
    let mut output = String::with_capacity(value.len());
    let mut escaped = false;
    let mut quote = None;
    for ch in value.chars() {
        if escaped {
            output.push(ch);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if (ch == '\'' || ch == '"') && quote.is_none() {
            quote = Some(ch);
        } else if quote == Some(ch) {
            quote = None;
        } else {
            output.push(ch);
        }
    }
    (!escaped && quote.is_none()).then_some(output)
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            if index + 2 >= bytes.len() {
                return None;
            }
            let high = (bytes[index + 1] as char).to_digit(16)? as u8;
            let low = (bytes[index + 2] as char).to_digit(16)? as u8;
            output.push((high << 4) | low);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn unique_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let counter = ATTACHMENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{}-{counter:x}", std::process::id())
}

fn read_image() -> Option<Vec<u8>> {
    read_image_platform().filter(|bytes| !bytes.is_empty())
}

fn image_extension(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(b"BM") {
        "bmp"
    } else if bytes.starts_with(b"II*\0") || bytes.starts_with(b"MM\0*") {
        "tiff"
    } else {
        "png"
    }
}

#[cfg(target_os = "macos")]
fn read_image_platform() -> Option<Vec<u8>> {
    let script = r#"ObjC.import('AppKit'); var p=$.NSPasteboard.generalPasteboard; var d=p.dataForType($.NSPasteboardTypePNG); if (!d || d.isNil()) d=p.dataForType($.NSPasteboardTypeTIFF); if (d && !d.isNil()) $.NSFileHandle.fileHandleWithStandardOutput.writeData(d);"#;
    run_bytes("/usr/bin/osascript", &["-l", "JavaScript", "-e", script])
}

#[cfg(target_os = "windows")]
fn read_image_platform() -> Option<Vec<u8>> {
    read_image_windows()
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn read_image_windows() -> Option<Vec<u8>> {
    let script = r#"Add-Type -AssemblyName System.Windows.Forms; Add-Type -AssemblyName System.Drawing; $i=[Windows.Forms.Clipboard]::GetImage(); if ($null -ne $i) { $m=New-Object IO.MemoryStream; $i.Save($m,[Drawing.Imaging.ImageFormat]::Png); [Console]::Write([Convert]::ToBase64String($m.ToArray())) }"#;
    let encoded = run_text(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-Command",
            script,
        ],
    )?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()
}

#[cfg(target_os = "linux")]
fn read_image_platform() -> Option<Vec<u8>> {
    for (program, args) in [
        ("wl-paste", vec!["--no-newline", "--type", "image/png"]),
        (
            "xclip",
            vec!["-selection", "clipboard", "-t", "image/png", "-o"],
        ),
        (
            "xclip",
            vec!["-selection", "clipboard", "-t", "image/bmp", "-o"],
        ),
        (
            "xsel",
            vec!["--clipboard", "--output", "--mime-type", "image/png"],
        ),
    ] {
        if let Some(bytes) = run_bytes(program, &args) {
            if !bytes.is_empty() {
                return Some(bytes);
            }
        }
    }
    if std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return read_image_windows();
    }
    None
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn read_image_platform() -> Option<Vec<u8>> {
    None
}

fn read_clipboard_files() -> Vec<PathBuf> {
    read_clipboard_files_platform()
}

#[cfg(target_os = "macos")]
fn read_clipboard_files_platform() -> Vec<PathBuf> {
    let script = r#"ObjC.import('AppKit'); var p=$.NSPasteboard.generalPasteboard; var a=p.propertyListForType($.NSFilenamesPboardType); if (a && !a.isNil()) { var n=ObjC.deepUnwrap(a); n.forEach(function(v){ console.log(v); }); }"#;
    run_text("/usr/bin/osascript", &["-l", "JavaScript", "-e", script])
        .map(|value| {
            value
                .lines()
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn read_clipboard_files_platform() -> Vec<PathBuf> {
    read_clipboard_files_windows()
}

#[cfg(any(target_os = "linux", target_os = "windows"))]
fn read_clipboard_files_windows() -> Vec<PathBuf> {
    let script = r#"Add-Type -AssemblyName System.Windows.Forms; [Windows.Forms.Clipboard]::GetFileDropList() | ForEach-Object { $_ }"#;
    run_text(
        "powershell.exe",
        &[
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-STA",
            "-Command",
            script,
        ],
    )
    .map(|value| {
        value
            .lines()
            .map(PathBuf::from)
            .filter(|p| p.exists())
            .collect()
    })
    .unwrap_or_default()
}

#[cfg(target_os = "linux")]
fn read_clipboard_files_platform() -> Vec<PathBuf> {
    for (program, args) in [
        ("wl-paste", vec!["--no-newline", "--type", "text/uri-list"]),
        (
            "xclip",
            vec!["-selection", "clipboard", "-t", "text/uri-list", "-o"],
        ),
        (
            "xsel",
            vec!["--clipboard", "--output", "--mime-type", "text/uri-list"],
        ),
    ] {
        if let Some(value) = run_text(program, &args) {
            let paths: Vec<_> = value
                .lines()
                .filter_map(decode_uri_or_shell_path)
                .map(PathBuf::from)
                .filter(|p| p.exists())
                .collect();
            if !paths.is_empty() {
                return paths;
            }
        }
    }
    if std::env::var_os("WSL_INTEROP").is_some() || std::env::var_os("WSL_DISTRO_NAME").is_some() {
        return read_clipboard_files_windows();
    }
    Vec::new()
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn read_clipboard_files_platform() -> Vec<PathBuf> {
    Vec::new()
}

fn run_bytes(program: &str, args: &[&str]) -> Option<Vec<u8>> {
    let output = Command::new(program).args(args).output().ok()?;
    output.status.success().then_some(output.stdout)
}

fn run_text(program: &str, args: &[&str]) -> Option<String> {
    String::from_utf8(run_bytes(program, args)?).ok()
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))?;
    set_private(path)
}

fn set_private(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn set_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn copy_dir_bounded(source: &Path, destination: &Path, limit: u64) -> Result<u64> {
    fs::create_dir_all(destination)?;
    set_private_directory(destination)?;
    let mut total = 0;
    for entry in fs::read_dir(source)? {
        let entry = entry?;
        let source_path = entry.path();
        let target_path = destination.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)?;
        if metadata.file_type().is_symlink() {
            bail!("symbolic links are not allowed in dropped directories");
        }
        if metadata.is_dir() {
            fs::create_dir_all(&target_path)?;
            total += copy_dir_bounded(&source_path, &target_path, limit.saturating_sub(total))?;
        } else if metadata.is_file() {
            if metadata.len() > limit.saturating_sub(total) {
                bail!("dropped directory exceeds the 256 MiB attachment limit");
            }
            fs::copy(&source_path, &target_path)?;
            set_private(&target_path)?;
            total += metadata.len();
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::{
        copy_dir_bounded, decode_uri_or_shell_path, image_extension, parse_dropped_paths,
        InputDecoder, InputEvent,
    };
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn parses_shell_escaped_paths() {
        let root = tempdir().unwrap();
        let path = root.path().join("a file.txt");
        fs::write(&path, "ok").unwrap();
        let input = path.to_string_lossy().replace(' ', "\\ ");
        assert_eq!(parse_dropped_paths(&input), Some(vec![path]));
    }

    #[test]
    fn parses_file_uri_and_percent_encoding() {
        assert_eq!(
            decode_uri_or_shell_path("file:///tmp/a%20b.png"),
            Some("/tmp/a b.png".into())
        );
    }

    #[test]
    fn rejects_mixed_or_missing_paths() {
        assert!(parse_dropped_paths("/tmp/does-not-exist\nplain text").is_none());
    }

    #[test]
    fn decodes_ctrl_v_and_bracketed_file_drop_across_chunks() {
        let mut decoder = InputDecoder::default();
        assert_eq!(
            decoder.feed(b"abc"),
            vec![
                InputEvent::Bytes(vec![b'a']),
                InputEvent::Bytes(vec![b'b']),
                InputEvent::Bytes(vec![b'c']),
            ]
        );
        assert_eq!(decoder.feed(&[0x16]), vec![InputEvent::ClipboardPaste]);
        assert!(decoder.feed(b"\x1b[200~/tmp/a").is_empty());
        assert_eq!(
            decoder.feed(b" file\x1b[201~"),
            vec![InputEvent::BracketedPaste(b"/tmp/a file".to_vec())]
        );
        let mut partial = InputDecoder::default();
        assert!(partial.feed(b"\x1b[").is_empty());
        assert_eq!(partial.finish(), vec![InputEvent::Bytes(b"\x1b[".to_vec())]);
    }

    #[test]
    fn copies_directories_with_their_contents_and_limit() {
        let source = tempdir().unwrap();
        let output_root = tempdir().unwrap();
        fs::create_dir(source.path().join("nested")).unwrap();
        fs::write(source.path().join("nested/file.txt"), b"hello").unwrap();
        let destination = output_root.path().join("out");
        assert_eq!(copy_dir_bounded(source.path(), &destination, 5).unwrap(), 5);
        assert_eq!(
            fs::read(destination.join("nested/file.txt")).unwrap(),
            b"hello"
        );
        let too_small = output_root.path().join("too-small");
        assert!(copy_dir_bounded(source.path(), &too_small, 4).is_err());
    }

    #[test]
    fn detects_common_image_formats() {
        assert_eq!(image_extension(b"\x89PNG\r\n"), "png");
        assert_eq!(image_extension(b"BM..."), "bmp");
        assert_eq!(image_extension(b"II*\0..."), "tiff");
    }
}
