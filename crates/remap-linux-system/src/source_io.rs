use std::fs::File;
use std::io::{self, Read};
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Component, Path};

use nix::fcntl::{OFlag, open, openat};
use nix::sys::stat::Mode;
use xattr::FileExt;

use crate::installer::{conflict, invalid_data};

pub(crate) const MAX_BINARY_BYTES: u64 = 128 * 1024 * 1024;
pub(crate) const MAX_ASSET_BYTES: u64 = 1024 * 1024;
const MAX_PLATFORM_XATTR_BYTES: usize = 4096;
const PLATFORM_XATTRS: [&str; 3] = ["security.evm", "security.ima", "security.selinux"];
const OWNERSHIP_XATTR: &str = "user.remap.owner";
const OWNERSHIP_NONCE_BYTES: usize = 16;

struct XattrStatus {
    empty: bool,
    installed_safe: bool,
}

pub(crate) fn read_source(path: &Path, owner_uid: u32) -> io::Result<Vec<u8>> {
    let (bytes, metadata, xattrs) = read_file_with_metadata(path, MAX_BINARY_BYTES)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != owner_uid)
        || metadata.mode() & 0o022 != 0
        || !xattrs.empty
        || !bytes.starts_with(b"\x7fELF")
    {
        return Err(conflict("an installation source binary is unsafe"));
    }
    Ok(bytes)
}

pub(crate) fn read_asset(path: &Path, owner_uid: u32) -> io::Result<Vec<u8>> {
    let (bytes, metadata, xattrs) = read_file_with_metadata(path, MAX_ASSET_BYTES)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || (metadata.uid() != 0 && metadata.uid() != owner_uid)
        || metadata.mode() & 0o022 != 0
        || !xattrs.empty
        || bytes.contains(&0)
        || std::str::from_utf8(&bytes).is_err()
    {
        return Err(conflict("a Linux documentation asset is unsafe"));
    }
    Ok(bytes)
}

pub(crate) fn read_owned_file(
    path: &Path,
    mode: u32,
    length: u64,
    maximum: u64,
) -> io::Result<Vec<u8>> {
    let (bytes, metadata, xattrs) = read_file_with_metadata(path, maximum)?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.nlink() != 1
        || metadata.mode() & 0o777 != mode
        || metadata.len() != length
        || !xattrs.installed_safe
    {
        return Err(conflict(
            "an installed artifact changed ownership or metadata",
        ));
    }
    Ok(bytes)
}

fn read_file_with_metadata(
    path: &Path,
    maximum: u64,
) -> io::Result<(Vec<u8>, std::fs::Metadata, XattrStatus)> {
    let file = File::from(open_file_descriptor_rooted(path)?);
    let metadata = file.metadata()?;
    let xattrs = inspect_xattrs(&file)?;
    let length = metadata.len();
    if length == 0 || length > maximum {
        return Err(invalid_data("an installation file exceeds its bound"));
    }
    let mut bytes = Vec::with_capacity(
        usize::try_from(length)
            .map_err(|_error| invalid_data("an installation file length cannot be represented"))?,
    );
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 != length {
        return Err(invalid_data(
            "an installation file changed while it was read",
        ));
    }
    Ok((bytes, metadata, xattrs))
}

pub(crate) fn installed_xattrs_safe(file: &File) -> io::Result<bool> {
    inspect_xattrs_with_marker(file, false).map(|status| status.installed_safe)
}

fn inspect_xattrs(file: &File) -> io::Result<XattrStatus> {
    inspect_xattrs_with_marker(file, false)
}

pub(crate) fn created_directory_xattrs_safe(file: &File) -> io::Result<bool> {
    inspect_xattrs_with_marker(file, true).map(|status| status.installed_safe)
}

fn inspect_xattrs_with_marker(
    file: &File,
    allow_ownership_marker: bool,
) -> io::Result<XattrStatus> {
    let names = file.list_xattr()?.collect::<Vec<_>>();
    let mut installed_safe = true;
    for name in &names {
        let Some(name_text) = name.to_str() else {
            installed_safe = false;
            continue;
        };
        let value = file.get_xattr(name)?.ok_or_else(|| {
            conflict("an installation file extended attribute changed during inspection")
        })?;
        let platform_safe =
            PLATFORM_XATTRS.contains(&name_text) && value.len() <= MAX_PLATFORM_XATTR_BYTES;
        let ownership_safe = allow_ownership_marker
            && name_text == OWNERSHIP_XATTR
            && value.len() == OWNERSHIP_NONCE_BYTES;
        if !platform_safe && !ownership_safe {
            installed_safe = false;
        }
    }
    Ok(XattrStatus {
        empty: names.is_empty(),
        installed_safe,
    })
}

fn open_file_descriptor_rooted(path: &Path) -> io::Result<OwnedFd> {
    if !path.is_absolute() {
        return Err(invalid_data("an installation source path must be absolute"));
    }
    let mut components = path.components().peekable();
    let mut directory = open(
        Path::new("/"),
        OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_error| invalid_data("the filesystem root could not be opened safely"))?;
    while let Some(component) = components.next() {
        match component {
            Component::RootDir => {}
            Component::Normal(name) if components.peek().is_some() => {
                directory = openat(
                    &directory,
                    name,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_error| {
                    invalid_data("an installation source ancestor could not be opened safely")
                })?;
            }
            Component::Normal(name) => {
                return openat(
                    &directory,
                    name,
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_error| {
                    invalid_data("an installation source file could not be opened safely")
                });
            }
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => {
                return Err(invalid_data(
                    "an installation source path contains an unsafe component",
                ));
            }
        }
    }
    Err(invalid_data("an installation source path has no file name"))
}
