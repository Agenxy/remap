use std::collections::BTreeSet;
use std::fs::File;
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};
use uuid::Uuid;
use xattr::FileExt;

use crate::install_model::{
    DirectoryIdentity, DirectoryProvenance, Generation, InstallRecord, PublicDirectory,
};
use crate::installer::{InstallStore, conflict, invalid_data, sync_directory, validate_directory};
use crate::source_io::created_directory_xattrs_safe;
use crate::system_publication::{publish_new_symlink, unit_publication_paths, verify_symlink};

const CURRENT_LINK: &str = "/usr/libexec/remap/current";
const CLI_LINK: &str = "/usr/bin/remap";
const MAN_DIRECTORY: &str = "/usr/share/man/man1";
const BASH_COMPLETION_DIRECTORY: &str = "/usr/share/bash-completion/completions";
const FISH_COMPLETION_DIRECTORY: &str = "/usr/share/fish/vendor_completions.d";
const ZSH_COMPLETION_DIRECTORY: &str = "/usr/share/zsh/site-functions";
const DOCUMENT_DIRECTORY: &str = "/usr/share/doc/remap";
const OWNERSHIP_XATTR: &str = "user.remap.owner";
const MANPAGES: [&str; 22] = [
    "remap-apply.1",
    "remap-completions.1",
    "remap-daemon.1",
    "remap-disable.1",
    "remap-doctor.1",
    "remap-enable.1",
    "remap-get.1",
    "remap-list.1",
    "remap-manpage.1",
    "remap-manpages.1",
    "remap-mcp.1",
    "remap-preview.1",
    "remap-remove.1",
    "remap-resolve.1",
    "remap-set.1",
    "remap-status.1",
    "remap-system-recover.1",
    "remap-system-status.1",
    "remap-system-uninstall.1",
    "remap-system.1",
    "remap-validate.1",
    "remap.1",
];

pub(crate) fn install_public_links(generation: &Generation) -> io::Result<()> {
    validate_fixed_publication_parents()?;
    ensure_public_directories(generation)?;
    let links = public_link_specs_for_generation(generation);
    for (destination, _target) in &links {
        match std::fs::symlink_metadata(destination) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
            Ok(_) => return Err(conflict("a public Remap installation path is occupied")),
        }
    }
    for (destination, target) in links {
        publish_new_symlink(&target, &destination)?;
    }
    sync_public_directories()
}

pub(crate) fn install_public_link_changes(
    previous: &Generation,
    current: &Generation,
) -> io::Result<()> {
    validate_fixed_publication_parents()?;
    ensure_public_directories(current)?;
    for (destination, target) in public_link_additions(previous, current) {
        publish_expected_symlink(&destination, &target)?;
    }
    for (destination, target) in public_link_removals(previous, current) {
        remove_expected_symlink(&destination, &target)?;
    }
    sync_public_directories()
}

pub(crate) fn revert_public_link_changes(
    previous: &Generation,
    failed: &Generation,
) -> io::Result<()> {
    validate_fixed_publication_parents()?;
    ensure_public_directories(previous)?;
    for (destination, target) in public_link_removals(previous, failed) {
        publish_expected_symlink(&destination, &target)?;
    }
    for (destination, target) in public_link_additions(previous, failed) {
        remove_expected_symlink(&destination, &target)?;
    }
    sync_public_directories()
}

pub(crate) fn missing_public_links(generation: &Generation) -> io::Result<Vec<(PathBuf, PathBuf)>> {
    validate_fixed_publication_parents()?;
    ensure_public_directories(generation)?;
    let mut missing = Vec::new();
    for (destination, target) in public_link_specs_for_generation(generation) {
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && std::fs::read_link(&destination)? == target => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                missing.push((destination, target));
            }
            Ok(_) => return Err(conflict("a public Remap path changed ownership")),
            Err(error) => return Err(error),
        }
    }
    Ok(missing)
}

pub(crate) fn install_missing_public_links(
    generation: &Generation,
    expected: &[(PathBuf, PathBuf)],
) -> io::Result<()> {
    let observed = missing_public_links(generation)?;
    if observed != expected {
        return Err(conflict(
            "the missing public Remap paths changed after recovery approval",
        ));
    }
    for (destination, target) in expected {
        publish_expected_symlink(destination, target)?;
    }
    sync_public_directories()
}

pub(crate) fn publish_created_directories(
    store: &mut InstallStore,
    record: &mut InstallRecord,
) -> io::Result<()> {
    for index in 0..record.current.public_directories.len() {
        if record.current.public_directories[index].provenance
            == DirectoryProvenance::CreatedByRemap
        {
            publish_created_directory(store, record, index)?;
        }
    }
    Ok(())
}

fn publish_created_directory(
    store: &mut InstallStore,
    record: &mut InstallRecord,
    index: usize,
) -> io::Result<()> {
    let directory = &record.current.public_directories[index];
    let path = PathBuf::from(&directory.path);
    let temporary = directory_temporary(&record.current, index)?;
    if directory.identity.is_none() {
        require_absent(&path)?;
        stage_directory_temporary(&temporary, &record.current)?;
        write_ownership_nonce(&temporary, *Uuid::new_v4().as_bytes())?;
        let identity = directory_identity(&temporary)?;
        record.current.public_directories[index].identity = Some(identity);
        store.save(record)?;
    }
    let identity = record.current.public_directories[index]
        .identity
        .ok_or_else(|| conflict("a Remap-created public directory has no durable identity"))?;
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            validate_published_created_directory(&path)?;
            require_directory_identity(&path, identity)?;
            require_absent(&temporary)?;
            sync_public_parent(&path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            validate_created_directory(&temporary)?;
            require_directory_identity(&temporary, identity)?;
            require_empty_directory(&temporary)?;
            renameat2(
                AT_FDCWD,
                &temporary,
                AT_FDCWD,
                &path,
                RenameFlags::RENAME_NOREPLACE,
            )
            .map_err(io::Error::from)?;
            sync_public_parent(&path)?;
            validate_published_created_directory(&path)?;
            require_directory_identity(&path, identity)
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn remove_owned_public_links(generation: &Generation) -> io::Result<()> {
    validate_fixed_publication_parents()?;
    for (destination, expected) in public_link_specs_for_generation(generation) {
        match std::fs::symlink_metadata(&destination) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    && std::fs::read_link(&destination)? == expected =>
            {
                std::fs::remove_file(destination)?;
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Ok(_) => return Err(conflict("a public Remap path changed ownership")),
            Err(error) => return Err(error),
        }
    }
    sync_public_directories()?;
    remove_created_public_directories(generation)
}

pub(crate) fn verify_public_links(generation: &Generation) -> io::Result<()> {
    validate_fixed_publication_parents()?;
    for (destination, expected) in public_link_specs_for_generation(generation) {
        verify_symlink(&destination, &expected)?;
    }
    Ok(())
}

pub(crate) fn public_link_specs() -> Vec<(PathBuf, PathBuf)> {
    let mut links = vec![(
        PathBuf::from(CLI_LINK),
        Path::new(CURRENT_LINK).join("remap"),
    )];
    for name in MANPAGES {
        links.push((
            Path::new(MAN_DIRECTORY).join(name),
            Path::new(CURRENT_LINK)
                .join("share")
                .join("man")
                .join("man1")
                .join(name),
        ));
    }
    links.extend([
        (
            Path::new(BASH_COMPLETION_DIRECTORY).join("remap"),
            Path::new(CURRENT_LINK)
                .join("share")
                .join("completions")
                .join("remap.bash"),
        ),
        (
            Path::new(FISH_COMPLETION_DIRECTORY).join("remap.fish"),
            Path::new(CURRENT_LINK)
                .join("share")
                .join("completions")
                .join("remap.fish"),
        ),
        (
            Path::new(ZSH_COMPLETION_DIRECTORY).join("_remap"),
            Path::new(CURRENT_LINK)
                .join("share")
                .join("completions")
                .join("remap.zsh"),
        ),
        (
            Path::new(DOCUMENT_DIRECTORY).join("LICENSE"),
            Path::new(CURRENT_LINK).join("LICENSE"),
        ),
        (
            Path::new(DOCUMENT_DIRECTORY).join("NOTICE"),
            Path::new(CURRENT_LINK).join("NOTICE"),
        ),
    ]);
    links
}

fn public_link_specs_for_generation(generation: &Generation) -> Vec<(PathBuf, PathBuf)> {
    let artifact_paths = generation
        .artifacts
        .iter()
        .map(|artifact| artifact.relative_path.as_str())
        .collect::<BTreeSet<_>>();
    public_link_specs()
        .into_iter()
        .filter(|(_destination, target)| {
            target
                .strip_prefix(CURRENT_LINK)
                .ok()
                .and_then(Path::to_str)
                .is_some_and(|relative| artifact_paths.contains(relative))
        })
        .collect()
}

pub(crate) fn public_link_additions(
    previous: &Generation,
    current: &Generation,
) -> Vec<(PathBuf, PathBuf)> {
    public_link_difference(current, previous)
}

pub(crate) fn public_link_removals(
    previous: &Generation,
    current: &Generation,
) -> Vec<(PathBuf, PathBuf)> {
    public_link_difference(previous, current)
}

fn public_link_difference(included: &Generation, excluded: &Generation) -> Vec<(PathBuf, PathBuf)> {
    let excluded = public_link_specs_for_generation(excluded)
        .into_iter()
        .map(|(destination, _target)| destination)
        .collect::<BTreeSet<_>>();
    public_link_specs_for_generation(included)
        .into_iter()
        .filter(|(destination, _target)| !excluded.contains(destination))
        .collect()
}

fn publish_expected_symlink(destination: &Path, target: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(destination) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            publish_new_symlink(target, destination)
        }
        Ok(metadata)
            if metadata.file_type().is_symlink() && std::fs::read_link(destination)? == target =>
        {
            Ok(())
        }
        Ok(_) => Err(conflict("a public Remap installation path is occupied")),
        Err(error) => Err(error),
    }
}

fn remove_expected_symlink(destination: &Path, target: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(destination) {
        Ok(metadata)
            if metadata.file_type().is_symlink() && std::fs::read_link(destination)? == target =>
        {
            std::fs::remove_file(destination)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Ok(_) => Err(conflict("a public Remap path changed ownership")),
        Err(error) => Err(error),
    }
}

pub(crate) fn publication_paths() -> Vec<PathBuf> {
    let mut paths = vec![
        PathBuf::from(CURRENT_LINK),
        PathBuf::from(DOCUMENT_DIRECTORY),
    ];
    paths.extend(unit_publication_paths());
    paths.extend(
        public_link_specs()
            .into_iter()
            .map(|(destination, _target)| destination),
    );
    paths.sort();
    paths.dedup();
    paths
}

fn ensure_public_directories(generation: &Generation) -> io::Result<()> {
    for directory in &generation.public_directories {
        let path = Path::new(&directory.path);
        match directory.provenance {
            DirectoryProvenance::Preexisting => validate_directory(path, 0o755)?,
            DirectoryProvenance::CreatedByRemap => {
                let identity = directory.identity.ok_or_else(|| {
                    conflict("a Remap-created public directory has no durable identity")
                })?;
                validate_published_created_directory(path)?;
                require_directory_identity(path, identity)?;
            }
        }
    }
    Ok(())
}

fn validate_fixed_publication_parents() -> io::Result<()> {
    validate_directory(Path::new("/usr/bin"), 0o755)
}

pub(crate) fn verify_public_directories(generation: &Generation) -> io::Result<()> {
    let mut document_directory = None;
    for directory in &generation.public_directories {
        if directory.path == DOCUMENT_DIRECTORY {
            document_directory = Some(directory);
        } else {
            verify_public_directory(directory)?;
        }
    }
    verify_document_directory(
        document_directory.ok_or_else(|| {
            conflict("the Remap documentation directory is absent from the generation manifest")
        })?,
        Path::new(DOCUMENT_DIRECTORY),
    )
}

fn verify_public_directory(directory: &PublicDirectory) -> io::Result<()> {
    let path = Path::new(&directory.path);
    match directory.provenance {
        DirectoryProvenance::Preexisting => validate_directory(path, 0o755),
        DirectoryProvenance::CreatedByRemap => {
            let identity = directory.identity.ok_or_else(|| {
                conflict("a Remap-created public directory has no durable identity")
            })?;
            validate_published_created_directory(path)?;
            require_directory_identity(path, identity)
        }
    }
}

fn verify_document_directory(directory: &PublicDirectory, path: &Path) -> io::Result<()> {
    if Path::new(&directory.path) != path {
        return Err(conflict(
            "the Remap documentation directory does not match its generation manifest",
        ));
    }
    verify_public_directory(directory)?;
    validate_document_namespace_at(path)
}

pub(crate) fn removable_public_directories(generation: &Generation) -> io::Result<Vec<PathBuf>> {
    let mut created = generation
        .public_directories
        .iter()
        .filter(|directory| directory.provenance == DirectoryProvenance::CreatedByRemap)
        .map(|directory| PathBuf::from(&directory.path))
        .collect::<Vec<_>>();
    created.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    let known_links = public_link_specs()
        .into_iter()
        .map(|(destination, _target)| destination)
        .collect::<Vec<_>>();
    let mut removable = Vec::new();
    for path in created {
        match std::fs::symlink_metadata(&path) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
            Ok(_metadata) => {
                validate_published_created_directory(&path)?;
                let Some(expected) = generation
                    .public_directories
                    .iter()
                    .find(|directory| directory.path == path.to_string_lossy())
                    .and_then(|directory| directory.identity)
                else {
                    continue;
                };
                if directory_identity(&path)? != expected {
                    continue;
                }
            }
        }
        let mut only_owned = true;
        for entry in std::fs::read_dir(&path)? {
            let child = entry?.path();
            if !known_links.contains(&child)
                && child != Path::new(DOCUMENT_DIRECTORY)
                && !removable.contains(&child)
            {
                only_owned = false;
                break;
            }
        }
        if only_owned {
            removable.push(path);
        }
    }
    Ok(removable)
}

pub(crate) fn remove_created_public_directories(generation: &Generation) -> io::Result<()> {
    let mut created = generation
        .public_directories
        .iter()
        .enumerate()
        .filter(|(_index, directory)| directory.provenance == DirectoryProvenance::CreatedByRemap)
        .map(|(index, directory)| (index, PathBuf::from(&directory.path)))
        .collect::<Vec<_>>();
    created.sort_by_key(|(_index, path)| std::cmp::Reverse(path.components().count()));
    for (index, directory) in &created {
        remove_directory_temporary(generation, *index, directory)?;
    }
    let removable = removable_public_directories(generation)?;
    for (_index, directory) in created {
        if !removable.contains(&directory) {
            if !directory.try_exists()? {
                sync_public_parent(&directory)?;
            }
            continue;
        }
        validate_published_created_directory(&directory)?;
        match std::fs::remove_dir(&directory) {
            Ok(()) => sync_directory(
                directory
                    .parent()
                    .ok_or_else(|| invalid_data("a public directory parent is unavailable"))?,
            )?,
            Err(error) if error.kind() == io::ErrorKind::DirectoryNotEmpty => {
                return Err(conflict(
                    "a public directory changed after lifecycle authorization",
                ));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn sync_public_parent(path: &Path) -> io::Result<()> {
    let mut candidate = path
        .parent()
        .ok_or_else(|| invalid_data("a public directory parent is unavailable"))?;
    loop {
        match std::fs::symlink_metadata(candidate) {
            Ok(_) => {
                validate_created_directory(candidate)?;
                return sync_directory(candidate);
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                candidate = candidate.parent().ok_or_else(|| {
                    invalid_data("a public directory durable ancestor is unavailable")
                })?;
            }
            Err(error) => return Err(error),
        }
    }
}

fn stage_directory_temporary(path: &Path, generation: &Generation) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("a public directory has no parent"))?;
    validate_publication_parent(parent, generation)?;
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700).create(path)?;
        }
        Err(error) => return Err(error),
        Ok(_) => validate_created_directory(path)?,
    }
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))?;
    sync_directory(parent)?;
    validate_created_directory(path)?;
    require_empty_directory(path)
}

fn validate_publication_parent(parent: &Path, generation: &Generation) -> io::Result<()> {
    let Some(directory) = generation
        .public_directories
        .iter()
        .find(|directory| Path::new(&directory.path) == parent)
    else {
        return validate_directory(parent, 0o755);
    };
    match directory.provenance {
        DirectoryProvenance::Preexisting => validate_directory(parent, 0o755),
        DirectoryProvenance::CreatedByRemap => {
            let identity = directory.identity.ok_or_else(|| {
                conflict("a Remap-created parent directory has no durable identity")
            })?;
            validate_published_created_directory(parent)?;
            require_directory_identity(parent, identity)
        }
    }
}

fn validate_created_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(conflict(
            "a Remap-created public directory changed ownership or metadata",
        ));
    }
    let directory = File::open(path)?;
    if !created_directory_xattrs_safe(&directory)? {
        return Err(conflict(
            "a Remap-created public directory has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn validate_published_created_directory(path: &Path) -> io::Result<()> {
    validate_created_directory(path)?;
    if std::fs::symlink_metadata(path)?.mode() & 0o777 == 0o755 {
        Ok(())
    } else {
        Err(conflict(
            "a Remap-created public directory does not have its exact published mode",
        ))
    }
}

fn directory_temporary(generation: &Generation, index: usize) -> io::Result<PathBuf> {
    let path = Path::new(&generation.public_directories[index].path);
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("a public directory has no parent"))?;
    Ok(parent.join(format!(".remap-directory-{}-{index}", generation.id)))
}

fn remove_directory_temporary(
    generation: &Generation,
    index: usize,
    final_path: &Path,
) -> io::Result<()> {
    let temporary = directory_temporary(generation, index)?;
    match std::fs::symlink_metadata(&temporary) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => sync_public_parent(final_path),
        Err(error) => Err(error),
        Ok(_) => {
            validate_created_directory(&temporary)?;
            require_empty_directory(&temporary)?;
            if let Some(identity) = generation.public_directories[index].identity {
                require_directory_identity(&temporary, identity)?;
            }
            std::fs::remove_dir(&temporary)?;
            sync_public_parent(final_path)
        }
    }
}

fn directory_identity(path: &Path) -> io::Result<DirectoryIdentity> {
    let requested = rustix::fs::StatxFlags::INO | rustix::fs::StatxFlags::BTIME;
    let metadata = rustix::fs::statx(
        rustix::fs::CWD,
        path,
        rustix::fs::AtFlags::SYMLINK_NOFOLLOW,
        requested,
    )?;
    let available = rustix::fs::StatxFlags::from_bits_retain(metadata.stx_mask);
    if !available.contains(requested) {
        return Err(invalid_data(
            "the public directory filesystem does not expose durable creation identity",
        ));
    }
    let directory = File::open(path)?;
    let ownership_nonce = directory
        .get_xattr(OWNERSHIP_XATTR)?
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid_data("the public directory has no valid Remap ownership marker"))?;
    Ok(DirectoryIdentity {
        inode: metadata.stx_ino,
        birth_seconds: metadata.stx_btime.tv_sec,
        birth_nanoseconds: metadata.stx_btime.tv_nsec,
        ownership_nonce,
    })
}

fn write_ownership_nonce(path: &Path, ownership_nonce: [u8; 16]) -> io::Result<()> {
    let directory = File::open(path)?;
    directory.set_xattr(OWNERSHIP_XATTR, &ownership_nonce)?;
    directory.sync_all()?;
    if directory.get_xattr(OWNERSHIP_XATTR)?.as_deref() == Some(ownership_nonce.as_slice()) {
        Ok(())
    } else {
        Err(invalid_data(
            "the public directory ownership marker could not be verified",
        ))
    }
}

fn require_directory_identity(path: &Path, expected: DirectoryIdentity) -> io::Result<()> {
    if directory_identity(path)? == expected {
        Ok(())
    } else {
        Err(conflict(
            "a Remap-created public directory identity changed",
        ))
    }
}

fn require_empty_directory(path: &Path) -> io::Result<()> {
    if std::fs::read_dir(path)?.next().is_none() {
        Ok(())
    } else {
        Err(conflict("a Remap directory staging path is not empty"))
    }
}

fn require_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(conflict("a planned Remap publication path became occupied")),
    }
}

#[cfg(test)]
fn validate_document_directory_at(path: &Path) -> io::Result<()> {
    validate_directory(path, 0o755)?;
    validate_document_namespace_at(path)
}

fn validate_document_namespace_at(path: &Path) -> io::Result<()> {
    let observed = std::fs::read_dir(path)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_name| conflict("the Remap documentation directory has an invalid name"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    if observed == BTreeSet::from(["LICENSE".to_owned(), "NOTICE".to_owned()]) {
        Ok(())
    } else {
        Err(conflict(
            "the Remap documentation directory contains an unowned or missing publication",
        ))
    }
}

fn sync_public_directories() -> io::Result<()> {
    for directory in [
        "/usr/bin",
        MAN_DIRECTORY,
        BASH_COMPLETION_DIRECTORY,
        FISH_COMPLETION_DIRECTORY,
        ZSH_COMPLETION_DIRECTORY,
    ] {
        match sync_directory(Path::new(directory)) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
    }
    sync_directory(Path::new("/usr/share/doc"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use crate::install_model::{Artifact, DirectoryProvenance, PublicDirectory};

    use super::{
        directory_identity, directory_temporary, public_link_additions, public_link_removals,
        public_link_specs_for_generation, remove_created_public_directories,
        stage_directory_temporary, validate_document_directory_at, verify_document_directory,
        verify_public_directory, write_ownership_nonce,
    };

    #[test]
    fn documentation_namespace_rejects_foreign_entries_before_removal() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let parent = tempfile::tempdir()?;
        let directory = parent.path().join("remap");
        std::fs::create_dir(&directory)?;
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755))?;
        symlink("license-target", directory.join("LICENSE"))?;
        symlink("notice-target", directory.join("NOTICE"))?;
        validate_document_directory_at(&directory)?;
        std::fs::write(directory.join("foreign"), b"foreign")?;
        assert!(validate_document_directory_at(&directory).is_err());
        Ok(())
    }

    #[test]
    fn created_document_directory_accepts_its_recorded_ownership_marker() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let parent = tempfile::tempdir()?;
        let path = parent.path().join("remap");
        std::fs::create_dir(&path)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        write_ownership_nonce(&path, [0x5a; 16])?;
        let directory = PublicDirectory {
            path: path.to_string_lossy().into_owned(),
            provenance: DirectoryProvenance::CreatedByRemap,
            identity: Some(directory_identity(&path)?),
        };
        std::fs::write(path.join("LICENSE"), b"license")?;
        std::fs::write(path.join("NOTICE"), b"notice")?;

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
        assert!(verify_public_directory(&directory).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o750))?;
        assert!(verify_public_directory(&directory).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        verify_document_directory(&directory, &path)
    }

    #[test]
    fn directory_birth_identity_survives_namespace_changes() -> std::io::Result<()> {
        let parent = tempfile::tempdir()?;
        let directory = parent.path().join("owned");
        std::fs::create_dir(&directory)?;
        write_ownership_nonce(&directory, [0x5a; 16])?;
        let identity = directory_identity(&directory)?;
        std::fs::write(directory.join("entry"), b"entry")?;
        assert_eq!(directory_identity(&directory)?, identity);
        std::fs::remove_file(directory.join("entry"))?;
        assert_eq!(directory_identity(&directory)?, identity);
        assert_ne!(identity.inode, 0);
        assert!(identity.birth_seconds > 0);
        Ok(())
    }

    #[test]
    fn nested_temporary_is_removed_before_parent_removability() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let root = tempfile::tempdir()?;
        let shared = root.path().join("share");
        let parent = shared.join("fish");
        let child = parent.join("vendor_completions.d");
        std::fs::create_dir(&shared)?;
        std::fs::create_dir(&parent)?;
        for directory in [root.path(), shared.as_path(), parent.as_path()] {
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o755))?;
        }
        write_ownership_nonce(&parent, [0x11; 16])?;
        let mut generation = crate::install_model::tests::generation(29);
        generation.public_directories = vec![
            PublicDirectory {
                path: parent.to_string_lossy().into_owned(),
                provenance: DirectoryProvenance::CreatedByRemap,
                identity: Some(directory_identity(&parent)?),
            },
            PublicDirectory {
                path: child.to_string_lossy().into_owned(),
                provenance: DirectoryProvenance::CreatedByRemap,
                identity: None,
            },
        ];
        let child_temporary = directory_temporary(&generation, 1)?;
        std::fs::create_dir(&child_temporary)?;
        std::fs::set_permissions(&child_temporary, std::fs::Permissions::from_mode(0o755))?;
        write_ownership_nonce(&child_temporary, [0x22; 16])?;
        generation.public_directories[1].identity = Some(directory_identity(&child_temporary)?);

        remove_created_public_directories(&generation)?;
        assert!(!parent.exists());
        assert!(!child_temporary.exists());
        Ok(())
    }

    #[test]
    fn nested_staging_accepts_only_the_recorded_created_parent() -> std::io::Result<()> {
        if !nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let root = tempfile::tempdir()?;
        let parent = root.path().join("fish");
        std::fs::create_dir(&parent)?;
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755))?;
        write_ownership_nonce(&parent, [0x33; 16])?;
        let mut generation = crate::install_model::tests::generation(31);
        generation.public_directories = vec![PublicDirectory {
            path: parent.to_string_lossy().into_owned(),
            provenance: DirectoryProvenance::CreatedByRemap,
            identity: Some(directory_identity(&parent)?),
        }];
        let temporary = parent.join(".remap-directory-child");
        stage_directory_temporary(&temporary, &generation)?;
        assert!(temporary.is_dir());

        generation.public_directories[0].identity = None;
        assert!(stage_directory_temporary(&temporary, &generation).is_err());
        Ok(())
    }

    #[test]
    fn publication_verification_uses_only_manifest_declared_assets() {
        let mut generation = crate::install_model::tests::generation(41);
        generation.artifacts = ["remap", "share/man/man1/remap.1"]
            .into_iter()
            .map(|relative_path| Artifact {
                relative_path: relative_path.to_owned(),
                mode: 0o644,
                byte_length: 1,
                digest: [1; 32],
            })
            .collect();
        let legacy = public_link_specs_for_generation(&generation);
        assert_eq!(legacy.len(), 2);
        assert!(legacy.iter().all(|(path, _target)| {
            path == std::path::Path::new("/usr/bin/remap")
                || path == std::path::Path::new("/usr/share/man/man1/remap.1")
        }));

        generation.artifacts.push(Artifact {
            relative_path: "share/man/man1/remap-system.1".to_owned(),
            mode: 0o644,
            byte_length: 1,
            digest: [2; 32],
        });
        assert_eq!(public_link_specs_for_generation(&generation).len(), 3);
    }

    #[test]
    fn generation_update_declares_only_added_and_removed_public_links() {
        let mut previous = crate::install_model::tests::generation(51);
        previous.artifacts = ["remap", "share/man/man1/remap.1"]
            .into_iter()
            .map(|relative_path| Artifact {
                relative_path: relative_path.to_owned(),
                mode: 0o644,
                byte_length: 1,
                digest: [1; 32],
            })
            .collect();
        let mut current = previous.clone();
        current.artifacts.push(Artifact {
            relative_path: "share/man/man1/remap-system.1".to_owned(),
            mode: 0o644,
            byte_length: 1,
            digest: [2; 32],
        });

        let added = public_link_additions(&previous, &current);
        assert_eq!(added.len(), 1);
        assert_eq!(
            added[0].0,
            std::path::Path::new("/usr/share/man/man1/remap-system.1")
        );
        assert!(public_link_removals(&previous, &current).is_empty());
        assert_eq!(public_link_removals(&current, &previous), added);
    }
}
