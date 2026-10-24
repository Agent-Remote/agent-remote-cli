use std::fs::File;
use std::io::{Read, Write};
use std::path::{Component, PathBuf};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt};
use cap_std::fs::{Dir, DirBuilder, OpenOptions};
use rand_core::{OsRng, RngCore};

use super::{SecretStore, SecretValue, StrictSecretError as Error, MAX_SECRET_BYTES};
use crate::platform;

fn home_directory(paths: &crate::config::AppPaths, create: bool) -> Result<Option<Dir>, Error> {
    let home: PathBuf = std::path::absolute(paths.home())?.components().collect();
    if home
        .components()
        .any(|item| matches!(item, Component::ParentDir))
    {
        return Err(Error::Invalid);
    }
    let name = home.file_name().ok_or(Error::Invalid)?;
    let parent = home.parent().ok_or(Error::Invalid)?;
    let parent = match Dir::open_ambient_dir(parent, cap_std::ambient_authority()) {
        Ok(value) => value,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let home = match parent.open_dir_nofollow(name) {
        Ok(value) => value,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_directory(&home)?;
    Ok(Some(home))
}

fn directory(store: &SecretStore, create: bool) -> Result<Option<Dir>, Error> {
    let Some(home) = home_directory(&store.paths, create)? else {
        return Ok(None);
    };
    if create {
        let builder = DirBuilder::new();
        #[cfg(unix)]
        let mut builder = builder;
        #[cfg(unix)]
        {
            use cap_std::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match home.create_dir_with("secrets", &builder) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    let directory = match home.open_dir_nofollow("secrets") {
        Ok(value) => value,
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_directory(&directory)?;
    Ok(Some(directory))
}

fn validate_directory(dir: &Dir) -> Result<(), Error> {
    platform::validate_private_directory(&dir.try_clone()?.into_std_file())
        .map_err(|_| Error::Invalid)
}

fn open(dir: &Dir, name: &std::ffi::OsStr) -> Result<Option<File>, Error> {
    let mut options = OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK);
    }
    let file = match dir.open_with(name, &options) {
        Ok(file) => file.into_std(),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    platform::validate_private_file(&file).map_err(|_| Error::Invalid)?;
    Ok(Some(file))
}

pub(super) fn read(store: &SecretStore, key: &str) -> Result<Option<SecretValue>, Error> {
    let Some(dir) = directory(store, false)? else {
        return Ok(None);
    };
    let path = store.secret_path(key);
    read_at(&dir, path.file_name().ok_or(Error::Invalid)?)
}

#[cfg(target_os = "macos")]
pub(crate) fn read_private_home_file(
    paths: &crate::config::AppPaths,
    name: &str,
) -> Result<Option<SecretValue>, Error> {
    let Some(dir) = home_directory(paths, false)? else {
        return Ok(None);
    };
    read_at(&dir, std::ffi::OsStr::new(name))
}

fn read_at(dir: &Dir, name: &std::ffi::OsStr) -> Result<Option<SecretValue>, Error> {
    let Some(file) = open(dir, name)? else {
        return Ok(None);
    };
    if file.metadata()?.len() > MAX_SECRET_BYTES as u64 {
        return Err(Error::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(MAX_SECRET_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let text = String::from_utf8(bytes).map_err(|_| Error::Invalid)?;
    SecretValue::new(text).map(Some)
}

pub(super) fn write(store: &SecretStore, key: &str, value: &SecretValue) -> Result<(), Error> {
    let dir = directory(store, true)?.ok_or(Error::Unavailable)?;
    let path = store.secret_path(key);
    let name = path.file_name().ok_or(Error::Invalid)?;
    let previous = open(&dir, name)?;
    let identity = previous
        .as_ref()
        .map(platform::file_identity)
        .transpose()
        .map_err(|_| Error::Unavailable)?;
    let mut nonce = [0; 16];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|_| Error::Unavailable)?;
    let suffix: String = nonce.iter().map(|byte| format!("{byte:02x}")).collect();
    let temporary = format!(".credential-{suffix}.tmp");
    let mut options = OpenOptions::new();
    options
        .write(true)
        .create_new(true)
        .follow(FollowSymlinks::No);
    #[cfg(unix)]
    {
        use cap_std::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = dir.open_with(&temporary, &options)?.into_std();
    let result = (|| {
        platform::set_private_file_permissions(&file).map_err(|_| Error::Denied)?;
        file.write_all(value.as_str().as_bytes())?;
        file.sync_all()?;
        let current = open(&dir, name)?;
        let current_id = current
            .as_ref()
            .map(platform::file_identity)
            .transpose()
            .map_err(|_| Error::Unavailable)?;
        if current_id != identity {
            return Err(Error::Invalid);
        }
        drop(current);
        drop(previous);
        if identity.is_some() {
            dir.rename(&temporary, &dir, name)?;
        } else {
            dir.hard_link(&temporary, &dir, name)?;
            dir.remove_file(&temporary)?;
        }
        #[cfg(unix)]
        platform::sync_directory(&dir)?;
        Ok(())
    })();
    drop(file);
    let _ = dir.remove_file(&temporary);
    result
}
