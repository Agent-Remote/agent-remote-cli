//! Existing-only refresh metadata; this path never initializes a home or schema.
use anyhow::{ensure, Context, Result};
#[cfg(windows)]
use cap_fs_ext::{FollowSymlinks, OpenOptionsFollowExt};
use rusqlite::{params, Connection, OpenFlags, Transaction, TransactionBehavior};

use super::initialization;
use crate::config::AppPaths;

pub(crate) struct RefreshRecord {
    key: String,
    value: String,
    database_identity: String,
    pub at: u64,
}

#[cfg(windows)]
fn database_identity(path: &std::path::Path) -> Result<String> {
    let directory = cap_std::fs::Dir::open_ambient_dir(
        path.parent().context("metadata parent")?,
        cap_std::ambient_authority(),
    )?;
    let mut options = cap_std::fs::OpenOptions::new();
    options.read(true).follow(FollowSymlinks::No);
    let file = directory
        .open_with(path.file_name().context("metadata filename")?, &options)?
        .into_std();
    crate::platform::validate_single_regular_file(&file)?;
    crate::platform::file_identity(&file)
}

#[cfg(unix)]
fn database_identity(path: &std::path::Path) -> Result<String> {
    use std::os::unix::fs::MetadataExt;
    // POSIX locks belong to the process: closing ANY raw descriptor for this
    // inode could release another SQLite connection's locks. lstat uses no FD.
    let metadata = std::fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_file()
            && metadata.nlink() == 1
            && metadata.uid() == unsafe { libc::geteuid() }
            && metadata.mode() & 0o022 == 0,
        "unsafe metadata file"
    );
    Ok(format!("{}:{}", metadata.dev(), metadata.ino()))
}

fn open(paths: &AppPaths, write: bool) -> Result<(Connection, String)> {
    let home = initialization::checked_home(paths, false)?;
    let database = paths.state_db_path();
    let path =
        std::fs::canonicalize(home)?.join(database.file_name().context("metadata filename")?);
    for suffix in ["", "-journal", "-wal", "-shm"] {
        let mut name = path.as_os_str().to_os_string();
        name.push(suffix);
        initialization::validate_file(std::path::Path::new(&name))?;
    }
    let identity = database_identity(&path)?;
    let mode = if write {
        OpenFlags::SQLITE_OPEN_READ_WRITE
    } else {
        OpenFlags::SQLITE_OPEN_READ_ONLY
    };
    let connection = Connection::open_with_flags(
        &path,
        mode | OpenFlags::SQLITE_OPEN_NOFOLLOW | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_secs(3))?;
    ensure!(database_identity(&path)? == identity, "metadata changed");
    Ok((connection, identity))
}

impl RefreshRecord {
    pub(crate) fn read(paths: &AppPaths, key: String) -> Result<Self> {
        let (connection, database_identity) = open(paths, false)?;
        let value: String = connection.query_row(
            "SELECT substr(value, 1, 129) FROM kv WHERE key=?1",
            [&key],
            |row| row.get(0),
        )?;
        let at = value.parse::<u64>().context("invalid refresh metadata")?;
        Ok(Self {
            key,
            value,
            database_identity,
            at,
        })
    }

    pub(crate) fn update(&self, paths: &AppPaths, next: u64) -> Result<()> {
        let (connection, identity) = open(paths, true)?;
        ensure!(identity == self.database_identity, "metadata changed");
        let transaction = Transaction::new_unchecked(&connection, TransactionBehavior::Immediate)?;
        let changed = transaction.execute(
            "UPDATE kv SET value=?1,updated_at=CURRENT_TIMESTAMP WHERE key=?2 AND value=?3",
            params![next.to_string(), self.key, self.value],
        )?;
        ensure!(changed == 1, "refresh metadata changed");
        transaction.commit()?;
        let (_, identity) = open(paths, false)?;
        ensure!(identity == self.database_identity, "metadata changed");
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../tests/unit/src/credential_refresh.rs"]
mod tests;
