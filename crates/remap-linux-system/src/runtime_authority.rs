use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use nix::unistd::Uid;
use uuid::Uuid;

use crate::authority;
use crate::install_model::InstallPhase;
use crate::installer::{conflict, inspect_install_record};
use crate::source_io::installed_xattrs_safe;
use crate::system_publication::verify_current_link;

const RUNTIME_LEASE: &str = "runtime-start.lease";
const LEASE_LENGTH: u64 = 37;
const LEASE_CAPACITY: usize = 37;

pub(crate) fn acquire(generation_id: Uuid) -> io::Result<Flock<File>> {
    let directory = authority::resolver_lock_directory()?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(directory.join(RUNTIME_LEASE))?;
    validate(&file, true)?;
    let mut lease = Flock::lock(file, FlockArg::LockExclusiveNonblock)
        .map_err(|(_file, _error)| conflict("another runtime-start lease is active"))?;
    lease.set_len(0)?;
    lease.write_all(format!("{generation_id}\n").as_bytes())?;
    lease.sync_all()?;
    validate(&lease, false)?;
    Ok(lease)
}

pub(crate) fn authorize() -> io::Result<()> {
    if !Uid::effective().is_root() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "runtime authorization requires root",
        ));
    }
    let record = inspect_install_record()?
        .ok_or_else(|| conflict("the Remap runtime has no installation authority"))?;
    let leased = if matches!(record.phase, InstallPhase::Active | InstallPhase::Pruning) {
        None
    } else {
        Some(require_lease()?)
    };
    let expected = selected_generation(&record, leased)?;
    if requires_existing_activation(record.phase)
        && remap_linux::RootRecordStore::inspect(std::path::Path::new(
            crate::installer::STATE_DIRECTORY,
        ))
        .map_err(crate::installer::platform_error)?
        .is_none()
    {
        return Err(conflict(
            "the active runtime has no durable resolver authority",
        ));
    }
    verify_current_link(expected)
}

const fn requires_existing_activation(phase: InstallPhase) -> bool {
    matches!(phase, InstallPhase::Active | InstallPhase::Pruning)
}

pub(crate) fn activation_creation_allowed() -> io::Result<bool> {
    let Some(record) = inspect_install_record()? else {
        return Ok(false);
    };
    let leased = if record.phase == InstallPhase::Published {
        Some(require_lease()?)
    } else {
        None
    };
    let Some(expected) = activation_creation_generation(&record, leased)? else {
        return Ok(false);
    };
    verify_current_link(expected)?;
    Ok(true)
}

fn activation_creation_generation(
    record: &crate::install_model::InstallRecord,
    leased: Option<Uuid>,
) -> io::Result<Option<Uuid>> {
    if record.phase != InstallPhase::Published {
        return Ok(None);
    }
    selected_generation(record, leased).map(Some)
}

fn selected_generation(
    record: &crate::install_model::InstallRecord,
    leased: Option<Uuid>,
) -> io::Result<Uuid> {
    match record.phase {
        InstallPhase::Active | InstallPhase::Pruning => Ok(record.current.id),
        InstallPhase::Published | InstallPhase::Uninstalling(_) => {
            let leased =
                leased.ok_or_else(|| conflict("the runtime-start transaction lease is absent"))?;
            if leased != record.current.id {
                return Err(conflict(
                    "the runtime-start lease is for another generation",
                ));
            }
            Ok(leased)
        }
        InstallPhase::RollingBack(_) => {
            let leased =
                leased.ok_or_else(|| conflict("the rollback runtime-start lease is absent"))?;
            if leased != record.current.id
                && record.previous.as_ref().map(|value| value.id) != Some(leased)
            {
                return Err(conflict("the rollback runtime-start lease is not owned"));
            }
            Ok(leased)
        }
        _ => Err(conflict(
            "the installation journal does not authorize runtime startup",
        )),
    }
}

fn require_lease() -> io::Result<Uuid> {
    let directory = authority::resolver_lock_directory()?;
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(directory.join(RUNTIME_LEASE))?;
    validate(&file, false)?;
    let first = read_identity(&mut file)?;
    match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
        Ok(_unexpected_lease) => Err(conflict("the runtime-start lease is not held")),
        Err((mut file, Errno::EAGAIN)) => {
            validate(&file, false)?;
            let second = read_identity(&mut file)?;
            if first != second {
                return Err(conflict("the runtime-start lease changed identity"));
            }
            Ok(first)
        }
        Err((_file, _error)) => Err(conflict("the runtime-start lease could not be verified")),
    }
}

fn read_identity(file: &mut File) -> io::Result<Uuid> {
    file.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(LEASE_CAPACITY);
    file.take(LEASE_LENGTH + 1).read_to_end(&mut bytes)?;
    if bytes.len() != LEASE_CAPACITY || bytes.last() != Some(&b'\n') {
        return Err(conflict("the runtime-start lease payload is invalid"));
    }
    let text = std::str::from_utf8(&bytes[..bytes.len() - 1])
        .map_err(|_error| conflict("the runtime-start lease payload is invalid"))?;
    Uuid::parse_str(text).map_err(|_error| conflict("the runtime-start lease identity is invalid"))
}

fn validate(file: &File, allow_empty: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || (!allow_empty && metadata.len() != LEASE_LENGTH)
        || (allow_empty && !matches!(metadata.len(), 0 | LEASE_LENGTH))
        || !installed_xattrs_safe(file)?
    {
        return Err(conflict("the runtime-start lease metadata is unsafe"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    use nix::fcntl::{Flock, FlockArg};
    use uuid::Uuid;

    use crate::install_model::{InstallPhase, InstallRecord, RollbackStep};

    use super::{
        activation_creation_generation, read_identity, requires_existing_activation,
        selected_generation, validate,
    };

    #[test]
    fn lease_payload_is_exact_and_bounded() -> std::io::Result<()> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("lease");
        let mut file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let identity = Uuid::new_v4();
        writeln!(file, "{identity}")?;
        file.sync_all()?;
        // A lease is root's file, and validate says so: run by anyone else,
        // as on a hosted runner, the exact-metadata check is what is being
        // tested, and it must refuse the file that everything else here
        // accepts. Same shape as cleanup's ownership tests.
        if nix::unistd::Uid::effective().is_root() {
            validate(&file, false)?;
        } else {
            assert!(validate(&file, false).is_err());
        }
        assert_eq!(read_identity(&mut file)?, identity);
        let held = Flock::lock(file, FlockArg::LockExclusiveNonblock)
            .map_err(|(_file, error)| std::io::Error::other(error))?;
        let contender = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.path().join("lease"))?;
        assert!(Flock::lock(contender, FlockArg::LockExclusiveNonblock).is_err());
        drop(held);
        Ok(())
    }

    #[test]
    fn durable_and_transactional_phases_have_distinct_boot_authority() -> std::io::Result<()> {
        let current = crate::install_model::tests::generation(1);
        let previous = crate::install_model::tests::generation(2);
        let current_id = current.id;
        let previous_id = previous.id;
        let mut record = InstallRecord {
            phase: InstallPhase::Active,
            current,
            previous: Some(previous),
            previous_previous: None,
            pending_resolver_plan: None,
        };
        assert_eq!(selected_generation(&record, None)?, current_id);
        assert!(requires_existing_activation(record.phase));
        assert_eq!(activation_creation_generation(&record, None)?, None);
        record.phase = InstallPhase::Published;
        assert!(!requires_existing_activation(record.phase));
        assert!(selected_generation(&record, None).is_err());
        assert_eq!(selected_generation(&record, Some(current_id))?, current_id);
        assert_eq!(
            activation_creation_generation(&record, Some(current_id))?,
            Some(current_id)
        );
        record.phase = InstallPhase::RollingBack(RollbackStep::StartPrevious);
        assert_eq!(
            selected_generation(&record, Some(previous_id))?,
            previous_id
        );
        record.phase = InstallPhase::Staged;
        assert!(selected_generation(&record, Some(current_id)).is_err());
        Ok(())
    }
}
