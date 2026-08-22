use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{Flock, FlockArg};
use nix::unistd::Uid;

use crate::installer::{conflict, create_private_directory};

pub(crate) const AUTHORITY_DIRECTORY: &str = "/run/remap-lifecycle-authority";
const LIFECYCLE_LOCK: &str = "lifecycle.lock";

pub(crate) fn acquire_lifecycle() -> io::Result<Flock<File>> {
    ensure_directory()?;
    acquire_lock(
        &Path::new(AUTHORITY_DIRECTORY).join(LIFECYCLE_LOCK),
        Uid::effective().as_raw(),
    )
}

pub(crate) fn resolver_lock_directory() -> io::Result<PathBuf> {
    ensure_directory()?;
    Ok(PathBuf::from(AUTHORITY_DIRECTORY))
}

fn ensure_directory() -> io::Result<()> {
    create_private_directory(Path::new(AUTHORITY_DIRECTORY), 0o700)
}

fn acquire_lock(path: &Path, owner_uid: u32) -> io::Result<Flock<File>> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != owner_uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || metadata.len() != 0
    {
        return Err(conflict("the Linux lifecycle authority lock is unsafe"));
    }
    Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_file, _error)| conflict("another Linux lifecycle transaction is active"))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    use nix::unistd::Uid;

    use super::acquire_lock;

    #[test]
    fn lock_inode_is_stable_across_three_contenders() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))?;
        let path = root.path().join("lifecycle.lock");
        let first = acquire_lock(&path, Uid::effective().as_raw())?;
        let inode = std::fs::metadata(&path)?.ino();
        assert!(acquire_lock(&path, Uid::effective().as_raw()).is_err());
        drop(first);

        let third = acquire_lock(&path, Uid::effective().as_raw())?;
        assert_eq!(std::fs::metadata(&path)?.ino(), inode);
        assert!(acquire_lock(&path, Uid::effective().as_raw()).is_err());
        drop(third);
        assert_eq!(std::fs::metadata(path)?.ino(), inode);
        Ok(())
    }
}
