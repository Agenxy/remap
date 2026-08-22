use std::fs::{File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::source_io::installed_xattrs_safe;

const INSTALL_LOCK: &str = ".installation.lock";
const INSTALL_RECORD: &str = "installation.json";
const RESOLVER_LOCK: &str = ".resolver-activation.lock";
const RESOLVER_RECORD: &str = "resolver-activation.json";
const INSTALL_TEMPORARY: &str = ".installation.new";
const RESOLVER_TEMPORARY: &str = ".resolver-activation.new";
const MAX_STATE_FILE_BYTES: u64 = 64 * 1024;
const ALLOWED_STATE_FILES: [&str; 6] = [
    INSTALL_LOCK,
    INSTALL_RECORD,
    INSTALL_TEMPORARY,
    RESOLVER_LOCK,
    RESOLVER_RECORD,
    RESOLVER_TEMPORARY,
];

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateResidueEntry {
    path: String,
    byte_length: u64,
    digest: [u8; 32],
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct StateResidue {
    directory: String,
    remove_directory: bool,
    entries: Vec<StateResidueEntry>,
}

impl StateResidue {
    pub(crate) fn directory(&self) -> &str {
        &self.directory
    }

    pub(crate) fn is_empty_directory(&self) -> bool {
        self.remove_directory && self.entries.is_empty()
    }

    pub(crate) fn requires_resolver_quiescence(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.path.ends_with(RESOLVER_TEMPORARY))
    }
}

pub(crate) fn preflight_state_directory(directory: &Path) -> io::Result<()> {
    validate_directory(directory, 0o700)?;
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_name| conflict("the Linux state directory contains an invalid name"))?;
        if !ALLOWED_STATE_FILES.contains(&name.as_str()) {
            return Err(conflict(
                "the Linux state directory contains an unowned entry",
            ));
        }
        let file = open_owned_file(&entry.path())?;
        validate_root_file(&file, matches!(name.as_str(), INSTALL_LOCK | RESOLVER_LOCK))?;
    }
    Ok(())
}

pub(crate) fn remove_empty_generation_roots(generation_root: &Path) -> io::Result<()> {
    let product_root = generation_root
        .parent()
        .ok_or_else(|| invalid_data("the Linux generation root has no parent"))?;
    remove_exact_empty_directory(
        generation_root,
        "the Linux generation directory contains data Remap does not own",
    )?;
    remove_exact_empty_directory(
        product_root,
        "the Linux product directory contains data Remap does not own",
    )
}

fn remove_exact_empty_directory(path: &Path, message: &'static str) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => sync_existing_parent(path),
        Err(error) => Err(error),
        Ok(_metadata) => {
            validate_directory(path, 0o755)?;
            std::fs::remove_dir(path).map_err(|error| cleanup_error(error, message))?;
            sync_parent(path)
        }
    }
}

fn sync_existing_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("a Linux product path has no parent"))?;
    match File::open(parent) {
        Ok(directory) => directory.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

pub(crate) fn inspect_state_residue(state_directory: &Path) -> io::Result<Option<StateResidue>> {
    match std::fs::symlink_metadata(state_directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
        Ok(_metadata) => validate_directory(state_directory, 0o700)?,
    }
    let install_present = state_directory.join(INSTALL_RECORD).try_exists()?;
    let resolver_present = state_directory.join(RESOLVER_RECORD).try_exists()?;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(state_directory)? {
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_name| conflict("the Linux state directory contains an invalid name"))?;
        if !ALLOWED_STATE_FILES.contains(&name.as_str()) {
            return Err(conflict(
                "the Linux state directory contains an unowned entry",
            ));
        }
        let is_record = matches!(name.as_str(), INSTALL_RECORD | RESOLVER_RECORD);
        let is_temporary = matches!(name.as_str(), INSTALL_TEMPORARY | RESOLVER_TEMPORARY);
        let is_orphan = !install_present && !resolver_present && !is_record;
        if is_temporary || is_orphan {
            entries.push(inspect_residue_entry(&entry.path(), !is_temporary)?);
        }
    }
    entries.sort_by(|left, right| left.path.cmp(&right.path));
    let remove_directory = !install_present && !resolver_present;
    if remove_directory || !entries.is_empty() {
        Ok(Some(StateResidue {
            directory: state_directory.to_string_lossy().into_owned(),
            remove_directory,
            entries,
        }))
    } else {
        Ok(None)
    }
}

pub(crate) fn cleanup_state_residue(expected: &StateResidue) -> io::Result<()> {
    let state_directory = Path::new(&expected.directory);
    let observed = inspect_state_residue(state_directory)?
        .ok_or_else(|| conflict("the Linux state residue changed before recovery"))?;
    if observed != *expected {
        return Err(conflict("the Linux state residue changed before recovery"));
    }
    for entry in &expected.entries {
        std::fs::remove_file(&entry.path)?;
    }
    sync_parent_entries(state_directory)?;
    if !expected.remove_directory {
        return Ok(());
    }
    validate_directory(state_directory, 0o700)?;
    ensure_absent(&state_directory.join(INSTALL_RECORD))?;
    ensure_absent(&state_directory.join(RESOLVER_RECORD))?;
    std::fs::remove_dir(state_directory).map_err(|error| {
        cleanup_error(
            error,
            "the Linux state directory contains data Remap does not own",
        )
    })?;
    sync_parent(state_directory)
}

fn inspect_residue_entry(path: &Path, empty: bool) -> io::Result<StateResidueEntry> {
    let file = open_owned_file(path)?;
    validate_root_file(&file, empty)?;
    let length = file.metadata()?.len();
    if length > MAX_STATE_FILE_BYTES {
        return Err(conflict("a Linux state residue exceeds its bound"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(length)
            .map_err(|_error| invalid_data("a Linux state residue length is invalid"))?,
    );
    file.take(MAX_STATE_FILE_BYTES + 1)
        .read_to_end(&mut bytes)?;
    Ok(StateResidueEntry {
        path: path.to_string_lossy().into_owned(),
        byte_length: length,
        digest: crate::digest::sha256(&bytes),
    })
}

fn open_owned_file(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
}

fn validate_root_file(file: &File, empty: bool) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != 0o600
        || (empty && metadata.len() != 0)
    {
        return Err(conflict("a Linux state file changed ownership or metadata"));
    }
    if !installed_xattrs_safe(file)? {
        return Err(conflict(
            "a Linux state file has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn validate_directory(path: &Path, mode: u32) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o777 != mode
    {
        return Err(conflict(
            "a Linux product directory changed ownership or metadata",
        ));
    }
    let directory = File::open(path)?;
    if !installed_xattrs_safe(&directory)? {
        return Err(conflict(
            "a Linux product directory has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(conflict("a Linux state record remains active")),
        Err(error) => Err(error),
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| invalid_data("a Linux product path has no parent"))?,
    )?
    .sync_all()
}

fn sync_parent_entries(directory: &Path) -> io::Result<()> {
    File::open(directory)?.sync_all()
}

fn cleanup_error(error: io::Error, message: &'static str) -> io::Error {
    if error.kind() == io::ErrorKind::DirectoryNotEmpty {
        conflict(message)
    } else {
        error
    }
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

    use super::{ALLOWED_STATE_FILES, cleanup_state_residue, inspect_state_residue};

    #[test]
    fn cleanup_allowlist_is_exact_and_duplicate_free() {
        assert_eq!(ALLOWED_STATE_FILES.len(), 6);
        for (index, name) in ALLOWED_STATE_FILES.iter().enumerate() {
            assert!(name.is_ascii());
            assert!(!name.contains('/'));
            assert!(!ALLOWED_STATE_FILES[..index].contains(name));
        }
    }

    #[test]
    fn empty_or_partial_state_is_exactly_recoverable() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let parent = tempfile::tempdir()?;
        let state = parent.path().join("remap-system");
        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        let Some(residue) = inspect_state_residue(&state)? else {
            return Err(std::io::Error::other(
                "empty state residue was not detected",
            ));
        };
        cleanup_state_residue(&residue)?;
        assert!(!state.exists());

        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        let mut temporary = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(state.join(".installation.new"))?;
        std::io::Write::write_all(&mut temporary, b"partial")?;
        let Some(residue) = inspect_state_residue(&state)? else {
            return Err(std::io::Error::other(
                "partial state residue was not detected",
            ));
        };
        cleanup_state_residue(&residue)?;
        assert!(!state.exists());
        Ok(())
    }

    #[test]
    fn state_recovery_refuses_content_or_namespace_substitution() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let parent = tempfile::tempdir()?;
        let state = parent.path().join("remap-system");
        std::fs::create_dir(&state)?;
        std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
        let path = state.join(".installation.new");
        std::fs::write(&path, b"first")?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        let Some(residue) = inspect_state_residue(&state)? else {
            return Err(std::io::Error::other(
                "temporary state residue was not detected",
            ));
        };
        std::fs::write(&path, b"other")?;
        assert!(cleanup_state_residue(&residue).is_err());
        assert!(path.exists());

        std::fs::write(state.join("foreign"), b"foreign")?;
        assert!(inspect_state_residue(&state).is_err());
        Ok(())
    }
}
