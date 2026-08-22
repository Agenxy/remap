use std::io;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};
use uuid::Uuid;

use crate::generation_storage::{GENERATION_ROOT, PRODUCT_ROOT};
use crate::install_model::InstallRecord;
use crate::installer::{conflict, sync_directory, unit_names, validate_directory};

const CURRENT_LINK: &str = "/usr/libexec/remap/current";
const CURRENT_TEMPORARY: &str = "/usr/libexec/remap/.current.new";
const UNIT_DIRECTORY: &str = "/etc/systemd/system";
const MULTI_USER_WANTS: &str = "/etc/systemd/system/multi-user.target.wants";
const SOCKETS_WANTS: &str = "/etc/systemd/system/sockets.target.wants";

pub(crate) fn install_unit_links() -> io::Result<()> {
    validate_unit_publication_directories()?;
    let specifications = unit_link_specs();
    for (destination, _target) in &specifications {
        ensure_path_absent(destination)?;
    }
    for (destination, target) in specifications {
        publish_new_symlink(&target, &destination)?;
    }
    sync_unit_directories()
}

pub(crate) fn validate_unit_publication_directories() -> io::Result<()> {
    validate_directory(Path::new(UNIT_DIRECTORY), 0o755)?;
    validate_directory(Path::new(MULTI_USER_WANTS), 0o755)?;
    validate_directory(Path::new(SOCKETS_WANTS), 0o755)
}

pub(crate) fn remove_owned_unit_links() -> io::Result<()> {
    validate_unit_publication_directories()?;
    for (destination, expected) in unit_link_specs().into_iter().rev() {
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && std::fs::read_link(&destination)? == expected =>
            {
                std::fs::remove_file(destination)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(conflict("a systemd unit path changed ownership")),
            Err(error) => return Err(error),
        }
    }
    sync_unit_directories()
}

pub(crate) fn verify_unit_links() -> io::Result<()> {
    validate_unit_publication_directories()?;
    for (destination, expected) in unit_link_specs() {
        verify_symlink(&destination, &expected)?;
    }
    Ok(())
}

pub(crate) fn unit_publication_paths() -> Vec<PathBuf> {
    unit_link_specs()
        .into_iter()
        .map(|(destination, _target)| destination)
        .collect()
}

pub(crate) fn publish_current(new: Uuid, expected: Option<Uuid>) -> io::Result<()> {
    if let Some(expected) = expected {
        verify_current_link(expected)?;
        replace_current_link(new, expected)?;
    } else {
        ensure_path_absent(Path::new(CURRENT_LINK))?;
        publish_new_symlink(&generation_directory(new), Path::new(CURRENT_LINK))?;
    }
    sync_directory(Path::new(PRODUCT_ROOT))
}

pub(crate) fn verify_current_link(expected: Uuid) -> io::Result<()> {
    verify_symlink(Path::new(CURRENT_LINK), &generation_directory(expected))
}

pub(crate) fn restore_current_for_rollback(record: &InstallRecord) -> io::Result<()> {
    let Some(previous) = &record.previous else {
        remove_owned_current_link(record.current.id)?;
        remove_optional_current_temporary(record.current.id)?;
        return Ok(());
    };
    if current_is(previous.id) {
        remove_optional_current_temporary(record.current.id)?;
        return sync_directory(Path::new(PRODUCT_ROOT));
    }
    if !current_is(record.current.id) {
        return Err(conflict(
            "the current generation changed during rollback recovery",
        ));
    }
    match std::fs::read_link(CURRENT_TEMPORARY) {
        Ok(target) if target == generation_directory(previous.id) => {
            exchange_current()?;
            verify_current_link(previous.id)?;
            remove_exact_temporary_link(record.current.id)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            replace_current_link(previous.id, record.current.id)
        }
        Ok(_) => Err(conflict(
            "the rollback publication temporary changed ownership",
        )),
        Err(error) => Err(error),
    }
}

pub(crate) fn remove_owned_current_link(expected: Uuid) -> io::Result<()> {
    match std::fs::symlink_metadata(CURRENT_LINK) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => sync_product_publication_parent(),
        Err(error) => Err(error),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                && std::fs::read_link(CURRENT_LINK)? == generation_directory(expected) =>
        {
            std::fs::remove_file(CURRENT_LINK)?;
            sync_directory(Path::new(PRODUCT_ROOT))
        }
        Ok(_) => Err(conflict("the Remap publication path changed ownership")),
    }
}

pub(crate) fn publish_new_symlink(target: &Path, destination: &Path) -> io::Result<()> {
    symlink(target, destination).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            conflict("an installation publication path became occupied")
        } else {
            error
        }
    })
}

pub(crate) fn verify_symlink(path: &Path, expected: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_symlink() || std::fs::read_link(path)? != expected {
        return Err(conflict("an installed publication link changed ownership"));
    }
    Ok(())
}

fn replace_current_link(new: Uuid, expected: Uuid) -> io::Result<()> {
    ensure_path_absent(Path::new(CURRENT_TEMPORARY))?;
    symlink(generation_directory(new), CURRENT_TEMPORARY)?;
    sync_directory(Path::new(PRODUCT_ROOT))?;
    if let Err(error) = exchange_current() {
        remove_exact_temporary_link(new)?;
        return Err(error);
    }
    if verify_symlink(
        Path::new(CURRENT_TEMPORARY),
        &generation_directory(expected),
    )
    .is_err()
    {
        exchange_current()?;
        sync_directory(Path::new(PRODUCT_ROOT))?;
        remove_exact_temporary_link(new)?;
        return Err(conflict(
            "the current generation changed during atomic replacement",
        ));
    }
    verify_current_link(new)?;
    std::fs::remove_file(CURRENT_TEMPORARY)?;
    sync_directory(Path::new(PRODUCT_ROOT))
}

fn exchange_current() -> io::Result<()> {
    renameat2(
        AT_FDCWD,
        CURRENT_TEMPORARY,
        AT_FDCWD,
        CURRENT_LINK,
        RenameFlags::RENAME_EXCHANGE,
    )
    .map_err(io::Error::from)
}

fn remove_exact_temporary_link(expected: Uuid) -> io::Result<()> {
    verify_symlink(
        Path::new(CURRENT_TEMPORARY),
        &generation_directory(expected),
    )?;
    std::fs::remove_file(CURRENT_TEMPORARY)?;
    sync_directory(Path::new(PRODUCT_ROOT))
}

fn remove_optional_current_temporary(expected: Uuid) -> io::Result<()> {
    match std::fs::read_link(CURRENT_TEMPORARY) {
        Ok(target) if target == generation_directory(expected) => {
            std::fs::remove_file(CURRENT_TEMPORARY)?;
            sync_directory(Path::new(PRODUCT_ROOT))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => sync_product_publication_parent(),
        Ok(_) => Err(conflict(
            "the rollback publication temporary changed ownership",
        )),
        Err(error) => Err(error),
    }
}

fn ensure_path_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(conflict(
            "a transaction publication path is already occupied",
        )),
    }
}

fn current_is(expected: Uuid) -> bool {
    std::fs::read_link(CURRENT_LINK).is_ok_and(|target| target == generation_directory(expected))
}

fn generation_directory(id: Uuid) -> PathBuf {
    Path::new(GENERATION_ROOT).join(id.to_string())
}

fn sync_product_publication_parent() -> io::Result<()> {
    match std::fs::symlink_metadata(PRODUCT_ROOT) {
        Ok(_) => sync_directory(Path::new(PRODUCT_ROOT)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            sync_directory(Path::new(PRODUCT_ROOT).parent().ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "product root has no parent")
            })?)
        }
        Err(error) => Err(error),
    }
}

fn unit_link_specs() -> Vec<(PathBuf, PathBuf)> {
    let mut specifications = unit_names()
        .into_iter()
        .map(|unit| {
            (
                Path::new(UNIT_DIRECTORY).join(&unit),
                Path::new(CURRENT_LINK).join("units").join(unit),
            )
        })
        .collect::<Vec<_>>();
    specifications.extend(unit_names().into_iter().map(|unit| {
        let directory = if unit.ends_with(".socket") {
            SOCKETS_WANTS
        } else {
            MULTI_USER_WANTS
        };
        (
            Path::new(directory).join(&unit),
            Path::new(UNIT_DIRECTORY).join(unit),
        )
    }));
    specifications
}

fn sync_unit_directories() -> io::Result<()> {
    sync_directory(Path::new(UNIT_DIRECTORY))?;
    sync_directory(Path::new(MULTI_USER_WANTS))?;
    sync_directory(Path::new(SOCKETS_WANTS))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{publish_new_symlink, unit_link_specs};

    #[test]
    fn create_only_publication_never_replaces_an_existing_owner() -> std::io::Result<()> {
        let root = tempfile::tempdir()?;
        let destination = root.path().join("publication");
        std::os::unix::fs::symlink("foreign-target", &destination)?;
        assert!(publish_new_symlink(std::path::Path::new("remap-target"), &destination).is_err());
        assert_eq!(
            std::fs::read_link(destination)?,
            std::path::Path::new("foreign-target")
        );
        Ok(())
    }

    #[test]
    fn unit_and_enablement_links_are_one_exact_publication_set() {
        let specifications = unit_link_specs();
        assert_eq!(specifications.len(), 10);
        let destinations = specifications
            .iter()
            .map(|(destination, _target)| destination)
            .collect::<BTreeSet<_>>();
        assert_eq!(destinations.len(), specifications.len());
        assert_eq!(
            specifications
                .iter()
                .filter(|(destination, _target)| destination
                    .parent()
                    .is_some_and(|parent| parent.ends_with("multi-user.target.wants")))
                .count(),
            2
        );
        assert_eq!(
            specifications
                .iter()
                .filter(|(destination, _target)| destination
                    .parent()
                    .is_some_and(|parent| parent.ends_with("sockets.target.wants")))
                .count(),
            3
        );
    }
}
