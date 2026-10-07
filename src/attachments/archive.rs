//! Bounded, link-free attachment snapshots outside the workspace.
use super::{ClipboardPayload, MAX_FILES_PER_PASTE, MAX_FILE_BYTES, MAX_IMAGE_BYTES};
use anyhow::{bail, Context, Result};
use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, OpenOptions};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use zip::{write::SimpleFileOptions, CompressionMethod, ZipWriter};

pub(super) struct Archive {
    pub file: std::fs::File,
    pub names: Vec<String>,
    pub size: u64,
    pub sha256: String,
}

struct Builder {
    zip: ZipWriter<std::fs::File>,
    bytes: u64,
    entries: usize,
    cancelled: Arc<AtomicBool>,
}

impl Builder {
    fn check(&mut self, name: &str, size: u64) -> Result<()> {
        if self.cancelled.load(Ordering::Acquire) {
            bail!("attachment transfer cancelled");
        }
        self.entries += 1;
        self.bytes = self
            .bytes
            .checked_add(size)
            .context("attachment size overflow")?;
        if self.entries > 10000 || self.bytes > MAX_FILE_BYTES {
            bail!("attachment batch exceeds 256 MiB or 10000 entries");
        }
        if name.len() > 4096 || name.contains('\\') || name.chars().any(char::is_control) {
            bail!("attachment name cannot be represented safely");
        }
        Ok(())
    }

    fn entry(
        &mut self,
        parent: &Dir,
        name: &std::ffi::OsStr,
        archive_name: &str,
        depth: usize,
    ) -> Result<()> {
        if depth > 64 {
            bail!("attachment directory is too deeply nested");
        }
        let before = parent.symlink_metadata(name)?;
        self.check(
            archive_name,
            if before.is_file() { before.len() } else { 0 },
        )?;
        if before.is_dir() {
            let directory = parent.open_dir_nofollow(name)?;
            self.zip.add_directory(archive_name, options(0o770))?;
            for child in directory.entries()? {
                let child = child?;
                let name = child.file_name();
                let text = name.to_str().context("attachment names must be UTF-8")?;
                self.entry(
                    &directory,
                    &name,
                    &format!("{archive_name}/{text}"),
                    depth + 1,
                )?;
            }
        } else if before.is_file() {
            let mut open = OpenOptions::new();
            open.read(true).follow(FollowSymlinks::No);
            #[cfg(unix)]
            {
                use cap_std::fs::OpenOptionsExt;
                open.custom_flags(libc::O_NONBLOCK);
            }
            let file = parent.open_with(name, &open)?;
            let actual = file.metadata()?;
            if !actual.is_file() || actual.len() != before.len() {
                bail!("attachment changed while opening");
            }
            #[cfg(unix)]
            let mode = {
                use cap_std::fs::MetadataExt;
                0o660 | (actual.mode() & 0o110)
            };
            #[cfg(not(unix))]
            let mode = 0o660;
            self.zip.start_file(archive_name, options(mode))?;
            let mut source = file.into_std();
            let mut remaining = actual.len();
            let mut buffer = vec![0; 65536];
            while remaining > 0 {
                if self.cancelled.load(Ordering::Acquire) {
                    bail!("attachment transfer cancelled");
                }
                let size = remaining.min(buffer.len() as u64) as usize;
                source
                    .read_exact(&mut buffer[..size])
                    .context("attachment changed during read")?;
                self.zip.write_all(&buffer[..size])?;
                remaining -= size as u64;
            }
            let after = source.metadata()?;
            if after.len() != actual.len() || after.modified()? != actual.modified()?.into_std() {
                bail!("attachment changed during read; retry when its writer has finished");
            }
        } else {
            bail!("attachment links and special files are not supported");
        }
        Ok(())
    }
}

fn options(mode: u32) -> SimpleFileOptions {
    SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(mode)
}

pub(super) fn pack(payload: ClipboardPayload, cancelled: Arc<AtomicBool>) -> Result<Archive> {
    // Anonymous/delete-on-close storage also disappears after a process crash.
    let file = tempfile::tempfile()?;
    let mut builder = Builder {
        zip: ZipWriter::new(file.try_clone()?),
        bytes: 0,
        entries: 0,
        cancelled,
    };
    let mut names = Vec::new();
    match payload {
        ClipboardPayload::Image { bytes, extension } => {
            if bytes.is_empty() || bytes.len() as u64 > MAX_IMAGE_BYTES {
                bail!("clipboard image exceeds the 64 MiB attachment limit");
            }
            if !matches!(
                extension,
                "png" | "jpg" | "jpeg" | "gif" | "bmp" | "tiff" | "webp"
            ) {
                bail!("unsupported clipboard image extension");
            }
            let name = format!("image.{extension}");
            builder.check(&name, bytes.len() as u64)?;
            builder.zip.start_file(&name, options(0o660))?;
            builder.zip.write_all(&bytes)?;
            names.push(name);
        }
        ClipboardPayload::Files(files) => {
            if files.is_empty() || files.len() > MAX_FILES_PER_PASTE {
                bail!("file drop must contain 1 to 32 paths");
            }
            for (index, path) in files.iter().enumerate() {
                let parent = path.parent().context("cannot attach a filesystem root")?;
                let name = path.file_name().context("attachment has no filename")?;
                let text = name.to_str().context("attachment names must be UTF-8")?;
                let archive_name = format!("{index}-{text}");
                let parent = Dir::open_ambient_dir(parent, cap_std::ambient_authority())?;
                builder.entry(&parent, name, &archive_name, 0)?;
                names.push(archive_name);
            }
        }
    }
    let mut stream = builder.zip.finish()?;
    let size = stream.seek(SeekFrom::End(0))?;
    stream.rewind()?;
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 65536];
    loop {
        if builder.cancelled.load(Ordering::Acquire) {
            bail!("attachment transfer cancelled");
        }
        let count = stream.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    stream.rewind()?;
    Ok(Archive {
        file,
        names,
        size,
        sha256: format!("{:x}", digest.finalize()),
    })
}

#[cfg(test)]
#[path = "../../tests/unit/src/attachments/archive.rs"]
mod tests;
