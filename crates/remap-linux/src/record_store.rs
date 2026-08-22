use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::OwnedFd;
use std::path::{Component, Path};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg, OFlag, open, openat, renameat};
use nix::sys::stat::{Mode, SFlag, fstat};
use nix::unistd::{Uid, UnlinkatFlags, fsync, unlinkat};
use xattr::FileExt;

use crate::{
    ActivationPhase, ActivationRecord, ActivationStore, LinuxError, LinuxErrorKind, LinuxResult,
    MAX_RECORD_BYTES, RecordCodec, RecordMetadata,
};

const RECORD_NAME: &str = "resolver-activation.json";
const TEMPORARY_NAME: &str = ".resolver-activation.new";
const LOCK_NAME: &str = ".resolver-activation.lock";
const MAX_PLATFORM_XATTR_BYTES: usize = 4096;
const PLATFORM_XATTRS: [&str; 3] = ["security.evm", "security.ima", "security.selinux"];

/// Locked, descriptor-rooted activation-record store for a privileged helper.
#[derive(Debug)]
pub struct RootRecordStore {
    directory: OwnedFd,
    _lock: Flock<File>,
}

impl RootRecordStore {
    /// Reads an existing activation record without creating or locking state.
    ///
    /// This is intended only for privileged lifecycle preview/status. A
    /// mutating transaction must still acquire [`Self::open`] and recompute
    /// any state-bound authorization after doing so.
    ///
    /// # Errors
    ///
    /// Returns an error unless the caller is root and any existing directory
    /// and record satisfy the descriptor-rooted ownership contract.
    pub fn inspect(directory: &Path) -> LinuxResult<Option<ActivationRecord>> {
        if !Uid::effective().is_root() || !directory.is_absolute() {
            return Err(store_error(
                "resolver record inspection requires a root caller and absolute directory",
            ));
        }
        match std::fs::symlink_metadata(directory) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(_error) => {
                return Err(store_error(
                    "the resolver record directory could not be inspected",
                ));
            }
            Ok(_metadata) => {}
        }
        let directory = open_directory_no_follow(directory)?;
        validate_directory(&directory)?;
        read_record_from(&directory)
    }

    /// Opens a fixed root-owned private directory and acquires its transaction lock.
    ///
    /// The final directory component is never followed through a symlink. All
    /// subsequent operations are relative to the verified open descriptor.
    ///
    /// # Errors
    ///
    /// Returns an error unless the caller is root and the directory and lock
    /// satisfy the ownership, type, mode, and no-follow contract.
    pub fn open(directory: &Path) -> LinuxResult<Self> {
        Self::open_with_lock_directory(directory, directory)
    }

    /// Opens a record directory while keeping its lock in a stable authority directory.
    ///
    /// The lock directory must remain present for the lifetime of every process
    /// that can mutate the record. Keeping it separate allows product state to
    /// be removed without ever unlinking the serialization inode.
    ///
    /// # Errors
    ///
    /// Returns an error unless both directories and the lock are root-owned,
    /// private, descriptor-rooted, and free of symlink substitution.
    pub fn open_with_lock_directory(directory: &Path, lock_directory: &Path) -> LinuxResult<Self> {
        if !Uid::effective().is_root() || !directory.is_absolute() || !lock_directory.is_absolute()
        {
            return Err(store_error(
                "the resolver record store requires a root caller and absolute directory",
            ));
        }
        let directory = open_directory_no_follow(directory)?;
        validate_directory(&directory)?;
        let lock_directory = open_directory_no_follow(lock_directory)?;
        validate_directory(&lock_directory)?;
        let lock = openat(
            &lock_directory,
            LOCK_NAME,
            OFlag::O_RDWR | OFlag::O_CREAT | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_error| store_error("the resolver record lock could not be opened"))?;
        validate_private_file(&lock, None)?;
        let lock = Flock::lock(File::from(lock), FlockArg::LockExclusiveNonblock).map_err(
            |(_file, _error)| store_error("another resolver transaction holds the lock"),
        )?;
        Ok(Self {
            directory,
            _lock: lock,
        })
    }

    fn read_record(&self) -> LinuxResult<Option<ActivationRecord>> {
        read_record_from(&self.directory)
    }

    fn publish(&self, record: &ActivationRecord) -> LinuxResult<()> {
        match self.read_record()? {
            Some(existing)
                if existing.metadata() != record.metadata()
                    || existing.before() != record.before()
                    || existing.owned() != record.owned()
                    || existing.manager() != record.manager()
                    || !valid_phase_transition(existing.phase(), record.phase()) =>
            {
                return Err(ownership_error());
            }
            None if record.phase() != (ActivationPhase::Applying { completed_steps: 0 }) => {
                return Err(ownership_error());
            }
            Some(_) | None => {}
        }
        remove_if_present(&self.directory, TEMPORARY_NAME)?;
        let descriptor = openat(
            &self.directory,
            TEMPORARY_NAME,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_error| store_error("the resolver activation record staging file failed"))?;
        validate_private_file(&descriptor, None)?;
        let result = write_and_publish(&self.directory, descriptor, record);
        if result.is_err() {
            let _removed = unlinkat(&self.directory, TEMPORARY_NAME, UnlinkatFlags::NoRemoveDir);
        }
        result
    }
}

fn read_record_from(directory: &OwnedFd) -> LinuxResult<Option<ActivationRecord>> {
    let descriptor = match openat(
        directory,
        RECORD_NAME,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    ) {
        Ok(descriptor) => descriptor,
        Err(Errno::ENOENT) => return Ok(None),
        Err(_error) => {
            return Err(store_error(
                "the resolver activation record could not be opened safely",
            ));
        }
    };
    let length = validate_private_file(&descriptor, Some(MAX_RECORD_BYTES as u64))?;
    let capacity = usize::try_from(length)
        .map_err(|_error| store_error("the resolver activation record size is invalid"))?;
    let mut encoded = Vec::with_capacity(capacity);
    File::from(descriptor)
        .take((MAX_RECORD_BYTES + 1) as u64)
        .read_to_end(&mut encoded)
        .map_err(|_error| store_error("the resolver activation record could not be read"))?;
    RecordCodec::decode(&encoded).map(Some)
}

const fn valid_phase_transition(before: ActivationPhase, after: ActivationPhase) -> bool {
    match (before, after) {
        (
            ActivationPhase::Applying {
                completed_steps: old,
            },
            ActivationPhase::Applying {
                completed_steps: new,
            },
        )
        | (
            ActivationPhase::Restoring {
                completed_steps: old,
            },
            ActivationPhase::Restoring {
                completed_steps: new,
            },
        ) => new == old || new == old.saturating_add(1),
        (
            ActivationPhase::Aborting {
                applied_steps: old_applied,
                completed_steps: old_completed,
            },
            ActivationPhase::Aborting {
                applied_steps: new_applied,
                completed_steps: new_completed,
            },
        ) => {
            new_applied == old_applied
                && (new_completed == old_completed
                    || new_completed == old_completed.saturating_add(1))
        }
        (
            ActivationPhase::Applying {
                completed_steps: applied_steps,
            },
            ActivationPhase::Aborting {
                applied_steps: recorded_applied,
                completed_steps: 0,
            },
        ) => recorded_applied == applied_steps,
        (ActivationPhase::Applying { completed_steps: 3 }, ActivationPhase::Active)
        | (
            ActivationPhase::Active,
            ActivationPhase::Active | ActivationPhase::Restoring { completed_steps: 0 },
        ) => true,
        _ => false,
    }
}

fn open_directory_no_follow(path: &Path) -> LinuxResult<OwnedFd> {
    let mut current = open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_error| store_error("the filesystem root could not be opened safely"))?;
    for component in path.components() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) => {
                current = openat(
                    &current,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_error| {
                    store_error("the resolver record directory path could not be opened safely")
                })?;
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(store_error(
                    "the resolver record directory path contains an unsafe component",
                ));
            }
        }
    }
    Ok(current)
}

impl ActivationStore for RootRecordStore {
    fn load(&mut self) -> LinuxResult<Option<ActivationRecord>> {
        self.read_record()
    }

    fn save(&mut self, record: &ActivationRecord) -> LinuxResult<()> {
        self.publish(record)
    }

    fn replace(
        &mut self,
        expected: &ActivationRecord,
        successor: &ActivationRecord,
    ) -> LinuxResult<()> {
        let current = self.read_record()?.ok_or_else(ownership_error)?;
        if current != *expected
            || expected.phase() != ActivationPhase::Active
            || !matches!(
                successor.phase(),
                ActivationPhase::Applying { completed_steps: 0 } | ActivationPhase::Active
            )
            || successor.metadata().activation_id() != expected.metadata().activation_id()
            || successor.metadata().owner_uid() != expected.metadata().owner_uid()
            || successor.metadata().generation() <= expected.metadata().generation()
            || successor.owned() != expected.owned()
            || (successor.phase() == ActivationPhase::Active
                && !active_manager_rebase_compatible(expected, successor))
        {
            return Err(ownership_error());
        }
        remove_if_present(&self.directory, TEMPORARY_NAME)?;
        let descriptor = openat(
            &self.directory,
            TEMPORARY_NAME,
            OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_error| store_error("the resolver rebase staging file failed"))?;
        validate_private_file(&descriptor, None)?;
        let result = write_and_publish(&self.directory, descriptor, successor);
        if result.is_err() {
            let _removed = unlinkat(&self.directory, TEMPORARY_NAME, UnlinkatFlags::NoRemoveDir);
        }
        result
    }

    fn remove(&mut self, metadata: &RecordMetadata) -> LinuxResult<()> {
        let existing = self
            .read_record()?
            .ok_or_else(|| store_error("the resolver activation record is already absent"))?;
        if existing.metadata() != metadata {
            return Err(LinuxError::new(
                LinuxErrorKind::OwnershipConflict,
                "the resolver activation identity changed before durable removal",
            ));
        }
        unlinkat(&self.directory, RECORD_NAME, UnlinkatFlags::NoRemoveDir)
            .map_err(|_error| store_error("the resolver activation record could not be removed"))?;
        fsync(&self.directory).map_err(|_error| {
            store_error("the resolver record directory could not be synchronized")
        })
    }
}

fn active_manager_rebase_compatible(
    expected: &ActivationRecord,
    successor: &ActivationRecord,
) -> bool {
    matches!(
        (expected.manager(), successor.manager()),
        (
            crate::ResolverManagerRecord::Systemd,
            crate::ResolverManagerRecord::Systemd
                | crate::ResolverManagerRecord::SystemdResolved(_)
                | crate::ResolverManagerRecord::SystemdNetworkd(_)
        )
    ) || match (expected.manager(), successor.manager()) {
        (
            crate::ResolverManagerRecord::SystemdResolved(expected),
            crate::ResolverManagerRecord::SystemdResolved(successor),
        )
        | (
            crate::ResolverManagerRecord::SystemdNetworkd(expected),
            crate::ResolverManagerRecord::SystemdNetworkd(successor),
        ) => expected == successor,
        (
            crate::ResolverManagerRecord::NetworkManager(expected),
            crate::ResolverManagerRecord::NetworkManager(successor),
        ) => expected.interface_name() == successor.interface_name(),
        _ => false,
    }
}

fn write_and_publish(
    directory: &OwnedFd,
    descriptor: OwnedFd,
    record: &ActivationRecord,
) -> LinuxResult<()> {
    let encoded = RecordCodec::encode(record)?;
    let mut file = File::from(descriptor);
    file.write_all(&encoded)
        .map_err(|_error| store_error("the resolver activation record could not be written"))?;
    file.sync_all().map_err(|_error| {
        store_error("the resolver activation record could not be synchronized")
    })?;
    drop(file);
    renameat(directory, TEMPORARY_NAME, directory, RECORD_NAME)
        .map_err(|_error| store_error("the resolver activation record could not be published"))?;
    fsync(directory)
        .map_err(|_error| store_error("the resolver record directory could not be synchronized"))
}

fn validate_directory(descriptor: &OwnedFd) -> LinuxResult<()> {
    let status = fstat(descriptor)
        .map_err(|_error| store_error("the resolver record directory could not be inspected"))?;
    let kind = SFlag::from_bits_truncate(status.st_mode);
    if status.st_uid != 0 || !kind.contains(SFlag::S_IFDIR) || status.st_mode & 0o777 != 0o700 {
        return Err(store_error(
            "the resolver record directory is not root-owned mode 0700",
        ));
    }
    validate_xattrs(descriptor)?;
    Ok(())
}

fn validate_private_file(descriptor: &OwnedFd, maximum: Option<u64>) -> LinuxResult<u64> {
    let status = fstat(descriptor)
        .map_err(|_error| store_error("the resolver record file could not be inspected"))?;
    let kind = SFlag::from_bits_truncate(status.st_mode);
    let length = u64::try_from(status.st_size)
        .map_err(|_error| store_error("the resolver record file size is invalid"))?;
    if status.st_nlink != 1 {
        return Err(store_error(
            "the resolver record file has an unsafe hard-link count",
        ));
    }
    RecordCodec::validate_root_file(
        status.st_uid,
        status.st_mode,
        kind.contains(SFlag::S_IFREG),
        false,
        maximum.map_or(1, |_| length),
    )?;
    if maximum.is_some_and(|bound| length == 0 || length > bound) {
        return Err(store_error(
            "the resolver activation record size is invalid",
        ));
    }
    validate_xattrs(descriptor)?;
    Ok(length)
}

fn validate_xattrs(descriptor: &OwnedFd) -> LinuxResult<()> {
    let duplicate = descriptor
        .try_clone()
        .map_err(|_error| store_error("resolver state xattrs could not be inspected"))?;
    let file = File::from(duplicate);
    for name in file
        .list_xattr()
        .map_err(|_error| store_error("resolver state xattrs could not be inspected"))?
    {
        let Some(name_text) = name.to_str() else {
            return Err(store_error(
                "resolver state has an unsafe extended attribute",
            ));
        };
        let value = file
            .get_xattr(&name)
            .map_err(|_error| store_error("resolver state xattrs could not be inspected"))?
            .ok_or_else(|| store_error("resolver state xattrs changed during inspection"))?;
        if !PLATFORM_XATTRS.contains(&name_text) || value.len() > MAX_PLATFORM_XATTR_BYTES {
            return Err(store_error(
                "resolver state has an unsafe extended attribute",
            ));
        }
    }
    Ok(())
}

fn remove_if_present(directory: &OwnedFd, name: &str) -> LinuxResult<()> {
    match unlinkat(directory, name, UnlinkatFlags::NoRemoveDir) {
        Ok(()) | Err(Errno::ENOENT) => Ok(()),
        Err(_error) => Err(store_error(
            "a stale resolver activation staging file could not be removed",
        )),
    }
}

const fn store_error(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::Persistence, message)
}

const fn ownership_error() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::OwnershipConflict,
        "the resolver activation record replacement violates ownership",
    )
}
