use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use nix::fcntl::{AT_FDCWD, RenameFlags, renameat2};

use crate::generation::PreparedArtifact;
use crate::install_model::{Artifact, Generation, LEGACY_EXPECTED_ARTIFACTS};
use crate::installer::{conflict, invalid_data, sync_directory, validate_directory};
use crate::source_io::{MAX_ASSET_BYTES, MAX_BINARY_BYTES, installed_xattrs_safe, read_owned_file};

pub(crate) const PRODUCT_ROOT: &str = "/usr/libexec/remap";
pub(crate) const GENERATION_ROOT: &str = "/usr/libexec/remap/generations";
const OWNED_DIRECTORIES: [&str; 5] = [
    "units",
    "share",
    "share/completions",
    "share/man",
    "share/man/man1",
];
const STAGE_PREFIX: &str = ".remap-stage-";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum StageMoment {
    Before,
    After,
}

pub(crate) fn stage_generation(
    generation: &Generation,
    artifacts: &[PreparedArtifact],
    first_install: bool,
) -> io::Result<()> {
    stage_generation_at(
        generation,
        artifacts,
        Path::new(GENERATION_ROOT),
        first_install,
        &mut |_moment| Ok(()),
    )
}

pub(crate) fn stage_generation_at(
    generation: &Generation,
    artifacts: &[PreparedArtifact],
    generation_root: &Path,
    first_install: bool,
    hook: &mut impl FnMut(StageMoment) -> io::Result<()>,
) -> io::Result<()> {
    let product_root = generation_root
        .parent()
        .ok_or_else(|| invalid_data("the generation root has no product parent"))?;
    if first_install {
        stage_directory(product_root, hook)?;
        stage_directory(generation_root, hook)?;
    } else {
        validate_directory(product_root, 0o755)?;
        validate_directory(generation_root, 0o755)?;
    }
    let directory = generation_directory_at(generation_root, generation.id);
    stage_directory(&directory, hook)?;
    for relative in OWNED_DIRECTORIES {
        stage_directory(&directory.join(relative), hook)?;
    }
    for artifact in artifacts {
        stage_artifact(&directory, artifact, hook)?;
    }
    for relative in ["units", "share/completions", "share/man/man1"] {
        stage_effect(hook, || sync_directory(&directory.join(relative)))?;
    }
    stage_effect(hook, || sync_directory(&directory))?;
    stage_effect(hook, || sync_directory(generation_root))
}

pub(crate) fn verify_generation(generation: &Generation) -> io::Result<()> {
    verify_generation_at(generation, Path::new(GENERATION_ROOT))
}

pub(crate) fn verify_generation_at(generation: &Generation, root: &Path) -> io::Result<()> {
    let directory = generation_directory_at(root, generation.id);
    let legacy_digests = generation_uses_legacy_digests(generation);
    validate_directory(&directory, 0o755)?;
    for relative in OWNED_DIRECTORIES {
        validate_directory(&directory.join(relative), 0o755)?;
    }
    for artifact in &generation.artifacts {
        verify_artifact(
            &directory.join(&artifact.relative_path),
            artifact,
            legacy_digests,
        )?;
    }
    verify_namespace(&directory, generation, false)
}

pub(crate) fn verify_generation_root(
    generations: impl IntoIterator<Item = uuid::Uuid>,
) -> io::Result<()> {
    verify_product_root_namespace()?;
    verify_generation_root_at(Path::new(GENERATION_ROOT), generations)
}

fn verify_product_root_namespace() -> io::Result<()> {
    let root = Path::new(PRODUCT_ROOT);
    validate_directory(root, 0o755)?;
    let observed = std::fs::read_dir(root)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_name| conflict("the product root contains an invalid name"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    let expected = BTreeSet::from(["current".to_owned(), "generations".to_owned()]);
    if observed == expected {
        Ok(())
    } else {
        Err(conflict(
            "the product root contains an unowned or missing publication",
        ))
    }
}

fn verify_generation_root_at(
    root: &Path,
    generations: impl IntoIterator<Item = uuid::Uuid>,
) -> io::Result<()> {
    validate_directory(root, 0o755)?;
    let expected = generations
        .into_iter()
        .map(|id| id.to_string())
        .collect::<BTreeSet<_>>();
    let observed = std::fs::read_dir(root)?
        .map(|entry| {
            entry?
                .file_name()
                .into_string()
                .map_err(|_name| conflict("the generation root contains an invalid name"))
        })
        .collect::<io::Result<BTreeSet<_>>>()?;
    if observed == expected {
        Ok(())
    } else {
        Err(conflict(
            "the generation root contains an unowned or missing generation",
        ))
    }
}

pub(crate) fn remove_generation_partial(generation: &Generation) -> io::Result<()> {
    remove_generation_partial_at(generation, Path::new(GENERATION_ROOT))
}

pub(crate) fn remove_empty_staging_roots(generation_root: &Path) -> io::Result<()> {
    let product_root = generation_root
        .parent()
        .ok_or_else(|| invalid_data("the generation root has no product parent"))?;
    remove_empty_staging_directory(generation_root)?;
    remove_empty_staging_directory(product_root)
}

pub(crate) fn remove_generation_partial_at(
    generation: &Generation,
    generation_root: &Path,
) -> io::Result<()> {
    let directory = generation_directory_at(generation_root, generation.id);
    match std::fs::symlink_metadata(&directory) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return sync_if_present(generation_root);
        }
        Err(error) => return Err(error),
        Ok(_metadata) => validate_owned_stage_directory(&directory)?,
    }
    verify_namespace(&directory, generation, true)?;
    let legacy_digests = generation_uses_legacy_digests(generation);
    for artifact in &generation.artifacts {
        remove_partial_artifact(&directory, artifact, legacy_digests)?;
    }
    for relative in OWNED_DIRECTORIES.into_iter().rev() {
        remove_owned_directory(&directory.join(relative))?;
    }
    validate_owned_stage_directory(&directory)?;
    std::fs::remove_dir(&directory)?;
    sync_directory(generation_root)
}

fn stage_directory(
    path: &Path,
    hook: &mut impl FnMut(StageMoment) -> io::Result<()>,
) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            stage_effect(hook, || {
                let mut builder = std::fs::DirBuilder::new();
                builder.mode(0o700).create(path)
            })?;
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }
    validate_owned_stage_directory(path)?;
    stage_effect(hook, || {
        std::fs::set_permissions(path, Permissions::from_mode(0o755))
    })?;
    let parent = path
        .parent()
        .ok_or_else(|| invalid_data("a generation directory has no parent"))?;
    stage_effect(hook, || sync_directory(parent))?;
    validate_directory(path, 0o755)
}

fn stage_artifact(
    root: &Path,
    artifact: &PreparedArtifact,
    hook: &mut impl FnMut(StageMoment) -> io::Result<()>,
) -> io::Result<()> {
    let final_path = root.join(&artifact.relative_path);
    let temporary = stage_path(&final_path)?;
    ensure_absent(&final_path)?;
    ensure_absent(&temporary)?;
    let mut file = stage_effect_value(hook, || {
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
            .open(&temporary)
    })?;
    stage_effect(hook, || file.write_all(&artifact.bytes))?;
    stage_effect(hook, || {
        file.set_permissions(Permissions::from_mode(artifact.mode))
    })?;
    stage_effect(hook, || file.sync_all())?;
    drop(file);
    stage_effect(hook, || rename_no_replace(&temporary, &final_path))?;
    stage_effect(hook, || {
        sync_directory(
            final_path
                .parent()
                .ok_or_else(|| invalid_data("an artifact has no parent"))?,
        )
    })
}

fn rename_no_replace(source: &Path, destination: &Path) -> io::Result<()> {
    renameat2(
        AT_FDCWD,
        source,
        AT_FDCWD,
        destination,
        RenameFlags::RENAME_NOREPLACE,
    )
    .map_err(io::Error::from)
}

fn verify_namespace(root: &Path, generation: &Generation, partial: bool) -> io::Result<()> {
    let mut expected = BTreeMap::<PathBuf, BTreeSet<String>>::new();
    for relative in OWNED_DIRECTORIES {
        add_expected(&mut expected, Path::new(relative));
    }
    for artifact in &generation.artifacts {
        let relative = Path::new(&artifact.relative_path);
        add_expected(&mut expected, relative);
        if partial {
            let staged = stage_path(relative)?;
            add_expected(&mut expected, &staged);
        }
    }
    for (relative, names) in expected {
        let directory = root.join(relative);
        let observed = match std::fs::read_dir(&directory) {
            Ok(entries) => entries
                .map(|entry| {
                    entry?
                        .file_name()
                        .into_string()
                        .map_err(|_name| conflict("an immutable generation has an invalid name"))
                })
                .collect::<io::Result<BTreeSet<_>>>()?,
            Err(error) if partial && error.kind() == io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        let valid = if partial {
            observed.is_subset(&names)
        } else {
            observed == names
        };
        if !valid {
            return Err(conflict(
                "an immutable generation contains an unowned or missing entry",
            ));
        }
    }
    Ok(())
}

fn add_expected(expected: &mut BTreeMap<PathBuf, BTreeSet<String>>, relative: &Path) {
    let parent = relative.parent().unwrap_or_else(|| Path::new(""));
    if let Some(name) = relative.file_name().and_then(OsStr::to_str) {
        expected
            .entry(parent.to_path_buf())
            .or_default()
            .insert(name.to_owned());
    }
}

fn remove_partial_artifact(
    root: &Path,
    artifact: &Artifact,
    legacy_digest: bool,
) -> io::Result<()> {
    let final_path = root.join(&artifact.relative_path);
    match std::fs::symlink_metadata(&final_path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            sync_if_present(final_path.parent().unwrap_or(root))?;
        }
        Err(error) => return Err(error),
        Ok(_) => {
            verify_artifact(&final_path, artifact, legacy_digest)?;
            std::fs::remove_file(&final_path)?;
            sync_directory(final_path.parent().unwrap_or(root))?;
        }
    }
    let temporary = stage_path(&final_path)?;
    match OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(&temporary)
    {
        Ok(file) => {
            validate_partial_file(&file, artifact)?;
            std::fs::remove_file(&temporary)?;
            sync_directory(temporary.parent().unwrap_or(root))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            sync_if_present(temporary.parent().unwrap_or(root))
        }
        Err(error) => Err(error),
    }
}

fn verify_artifact(path: &Path, artifact: &Artifact, legacy_digest: bool) -> io::Result<()> {
    let maximum = if artifact.mode == 0o755 {
        MAX_BINARY_BYTES
    } else {
        MAX_ASSET_BYTES
    };
    let bytes = read_owned_file(path, artifact.mode, artifact.byte_length, maximum)?;
    if artifact_digest_matches(&bytes, artifact, legacy_digest) {
        Ok(())
    } else {
        Err(conflict("an installed artifact digest changed"))
    }
}

fn generation_uses_legacy_digests(generation: &Generation) -> bool {
    generation.artifacts.len() == LEGACY_EXPECTED_ARTIFACTS
        && crate::generation::validate_legacy_identity(generation).is_ok()
}

fn artifact_digest_matches(bytes: &[u8], artifact: &Artifact, legacy_digest: bool) -> bool {
    crate::digest::sha256(bytes) == artifact.digest
        || (legacy_digest && *blake3::hash(bytes).as_bytes() == artifact.digest)
}

fn validate_partial_file(file: &File, artifact: &Artifact) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
        || metadata.len() > artifact.byte_length
        || !installed_xattrs_safe(file)?
    {
        return Err(conflict("a staged artifact changed ownership or metadata"));
    }
    Ok(())
}

fn validate_owned_stage_directory(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(conflict("a staged generation directory is unsafe"));
    }
    let directory = File::open(path)?;
    if !installed_xattrs_safe(&directory)? {
        return Err(conflict(
            "a staged generation directory has unsafe extended attributes",
        ));
    }
    Ok(())
}

fn remove_owned_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => sync_if_present(
            path.parent()
                .ok_or_else(|| invalid_data("a generation directory has no parent"))?,
        ),
        Err(error) => Err(error),
        Ok(_) => {
            validate_owned_stage_directory(path)?;
            std::fs::remove_dir(path).map_err(|error| {
                if error.kind() == io::ErrorKind::DirectoryNotEmpty {
                    conflict("an immutable generation contains an unowned entry")
                } else {
                    error
                }
            })?;
            sync_directory(
                path.parent()
                    .ok_or_else(|| invalid_data("a generation directory has no parent"))?,
            )
        }
    }
}

fn remove_empty_staging_directory(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let Some(parent) = path.parent() else {
                return Err(invalid_data("a staging directory has no parent"));
            };
            sync_if_present(parent)
        }
        Err(error) => Err(error),
        Ok(_) => {
            validate_owned_stage_directory(path)?;
            std::fs::remove_dir(path).map_err(|error| {
                if error.kind() == io::ErrorKind::DirectoryNotEmpty {
                    conflict("a staging directory contains an unowned entry")
                } else {
                    error
                }
            })?;
            sync_if_present(
                path.parent()
                    .ok_or_else(|| invalid_data("a staging directory has no parent"))?,
            )
        }
    }
}

fn stage_path(path: &Path) -> io::Result<PathBuf> {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| invalid_data("an artifact path has no safe file name"))?;
    Ok(path.with_file_name(format!("{STAGE_PREFIX}{name}")))
}

fn ensure_absent(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(conflict("a staged generation path is already occupied")),
    }
}

fn sync_if_present(path: &Path) -> io::Result<()> {
    match File::open(path) {
        Ok(directory) => directory.sync_all(),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

fn stage_effect<T>(
    hook: &mut impl FnMut(StageMoment) -> io::Result<()>,
    effect: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    hook(StageMoment::Before)?;
    let value = effect()?;
    hook(StageMoment::After)?;
    Ok(value)
}

fn stage_effect_value<T>(
    hook: &mut impl FnMut(StageMoment) -> io::Result<()>,
    effect: impl FnOnce() -> io::Result<T>,
) -> io::Result<T> {
    stage_effect(hook, effect)
}

fn generation_directory_at(root: &Path, id: uuid::Uuid) -> PathBuf {
    root.join(id.to_string())
}

#[cfg(test)]
mod tests {
    use super::artifact_digest_matches;
    use crate::install_model::Artifact;

    #[test]
    fn legacy_artifact_digest_requires_an_explicit_legacy_generation() {
        let bytes = b"legacy artifact";
        let artifact = Artifact {
            relative_path: "legacy".to_owned(),
            mode: 0o644,
            byte_length: bytes.len() as u64,
            digest: *blake3::hash(bytes).as_bytes(),
        };
        assert!(!artifact_digest_matches(bytes, &artifact, false));
        assert!(artifact_digest_matches(bytes, &artifact, true));
        assert!(!artifact_digest_matches(b"changed", &artifact, true));
    }
}
