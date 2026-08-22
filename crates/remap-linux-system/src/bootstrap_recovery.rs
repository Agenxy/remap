use std::ffi::OsStr;
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use nix::errno::Errno;
use nix::fcntl::{Flock, FlockArg};
use serde::Serialize;
use sha2::{Digest, Sha256};
use xattr::FileExt;

const RUNTIME_ROOT: &str = "/run";
const DIRECTORY_PREFIX: &str = "remap-bootstrap-";
const HELPER_NAME: &str = "remap-linux-system";
const MAX_RESIDUES: usize = 32;
const MAX_HELPER_BYTES: u64 = 128 * 1024 * 1024;
const MAX_XATTR_BYTES: usize = 64 * 1024;
const ALLOWED_XATTRS: [&str; 3] = ["security.evm", "security.ima", "security.selinux"];

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct BootstrapResidue {
    pub(crate) directory: DirectoryIdentity,
    pub(crate) helper: Option<HelperIdentity>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct DirectoryIdentity {
    pub(crate) path: String,
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    xattrs: Vec<XattrIdentity>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct HelperIdentity {
    pub(crate) path: String,
    device: u64,
    inode: u64,
    mode: u32,
    owner_uid: u32,
    owner_gid: u32,
    links: u64,
    byte_length: u64,
    #[serde(rename = "sha256")]
    sha256: String,
    xattrs: Vec<XattrIdentity>,
}

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
struct XattrIdentity {
    name: String,
    byte_length: u32,
    digest: [u8; 32],
}

struct LockedScan {
    runtime: Flock<File>,
    residues: Vec<LockedResidue>,
}

struct LockedResidue {
    state: BootstrapResidue,
    _directory: Flock<File>,
    helper: Option<Flock<File>>,
}

pub(crate) fn inspect() -> io::Result<Vec<BootstrapResidue>> {
    Ok(scan_locked()?
        .residues
        .into_iter()
        .map(|residue| residue.state)
        .collect())
}

pub(crate) fn cleanup(expected: &[BootstrapResidue]) -> io::Result<()> {
    let scan = scan_locked()?;
    let actual = scan
        .residues
        .iter()
        .map(|residue| residue.state.clone())
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(conflict(
            "the verified Linux bootstrap residue changed after approval",
        ));
    }
    for residue in &scan.residues {
        remove_locked(residue)?;
    }
    scan.runtime.sync_all()
}

fn scan_locked() -> io::Result<LockedScan> {
    let runtime = open_directory(Path::new(RUNTIME_ROOT))?;
    validate_runtime(&runtime)?;
    let runtime = Flock::lock(runtime, FlockArg::LockExclusiveNonblock)
        .map_err(|(_file, _error)| conflict("another Linux bootstrap transaction is active"))?;
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(RUNTIME_ROOT)? {
        let path = entry?.path();
        let Some(name) = path.file_name().and_then(OsStr::to_str) else {
            continue;
        };
        if !is_residue_name(name) {
            continue;
        }
        if paths.len() == MAX_RESIDUES {
            return Err(conflict(
                "too many Linux bootstrap residues require recovery",
            ));
        }
        paths.push(path);
    }
    paths.sort();
    let mut residues = Vec::new();
    for path in paths {
        if let Some(residue) = lock_residue(&path)? {
            residues.push(residue);
        }
    }
    Ok(LockedScan { runtime, residues })
}

fn lock_residue(path: &Path) -> io::Result<Option<LockedResidue>> {
    let directory = open_directory(path)?;
    let directory = match Flock::lock(directory, FlockArg::LockExclusiveNonblock) {
        Ok(lock) => lock,
        Err((_file, error)) if lock_is_busy(error) => return Ok(None),
        Err((_file, error)) => return Err(io::Error::from_raw_os_error(error as i32)),
    };
    let directory_identity = directory_identity(path, &directory)?;
    let helper_path = path.join(HELPER_NAME);
    let mut helper_present = false;
    for entry in std::fs::read_dir(path)? {
        let entry = entry?;
        if entry.file_name() == HELPER_NAME && !helper_present {
            helper_present = true;
        } else {
            return Err(conflict(
                "a Linux bootstrap residue contains an unowned entry",
            ));
        }
    }
    let helper = if helper_present {
        let file = open_helper(&helper_path)?;
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(mut lock) => {
                let identity = helper_identity(&helper_path, &mut lock)?;
                Some((lock, identity))
            }
            Err((_file, error)) if lock_is_busy(error) => return Ok(None),
            Err((_file, error)) => return Err(io::Error::from_raw_os_error(error as i32)),
        }
    } else {
        None
    };
    let state = BootstrapResidue {
        directory: directory_identity,
        helper: helper.as_ref().map(|(_lock, identity)| identity.clone()),
    };
    Ok(Some(LockedResidue {
        state,
        _directory: directory,
        helper: helper.map(|(lock, _identity)| lock),
    }))
}

fn remove_locked(residue: &LockedResidue) -> io::Result<()> {
    if residue.helper.is_some() {
        let helper = residue
            .state
            .helper
            .as_ref()
            .ok_or_else(|| invalid_data("the bootstrap helper identity is unavailable"))?;
        std::fs::remove_file(&helper.path)?;
    }
    std::fs::remove_dir(&residue.state.directory.path).map_err(|error| {
        if error.kind() == io::ErrorKind::DirectoryNotEmpty {
            conflict("a Linux bootstrap residue changed while being removed")
        } else {
            error
        }
    })
}

fn directory_identity(path: &Path, directory: &File) -> io::Result<DirectoryIdentity> {
    let metadata = directory.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o711
    {
        return Err(conflict(
            "a Linux bootstrap residue directory has unsafe metadata",
        ));
    }
    Ok(DirectoryIdentity {
        path: path_string(path)?,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        xattrs: xattr_identity(directory)?,
    })
}

fn helper_identity(path: &Path, helper: &mut File) -> io::Result<HelperIdentity> {
    let metadata = helper.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o7777 != 0o555
        || metadata.nlink() != 1
        || metadata.len() == 0
        || metadata.len() > MAX_HELPER_BYTES
    {
        return Err(conflict(
            "a Linux bootstrap residue helper has unsafe metadata",
        ));
    }
    Ok(HelperIdentity {
        path: path_string(path)?,
        device: metadata.dev(),
        inode: metadata.ino(),
        mode: metadata.mode() & 0o7777,
        owner_uid: metadata.uid(),
        owner_gid: metadata.gid(),
        links: metadata.nlink(),
        byte_length: metadata.len(),
        sha256: sha256(helper)?,
        xattrs: xattr_identity(helper)?,
    })
}

fn xattr_identity(file: &File) -> io::Result<Vec<XattrIdentity>> {
    let mut attributes = Vec::new();
    for name in file.list_xattr()? {
        let name = name
            .into_string()
            .map_err(|_name| conflict("a Linux bootstrap residue has an invalid xattr name"))?;
        if !ALLOWED_XATTRS.contains(&name.as_str()) {
            return Err(conflict(
                "a Linux bootstrap residue has an unapproved extended attribute",
            ));
        }
        let value = file
            .get_xattr(&name)?
            .ok_or_else(|| conflict("a Linux bootstrap residue xattr changed during review"))?;
        if value.len() > MAX_XATTR_BYTES {
            return Err(conflict(
                "a Linux bootstrap residue xattr exceeds its bound",
            ));
        }
        attributes.push(XattrIdentity {
            name,
            byte_length: u32::try_from(value.len())
                .map_err(|_error| invalid_data("a bootstrap xattr length is invalid"))?,
            digest: crate::digest::sha256(&value),
        });
    }
    attributes.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(attributes)
}

fn sha256(file: &mut File) -> io::Result<String> {
    file.seek(SeekFrom::Start(0))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    Ok(hex(&bytes))
}

fn validate_runtime(runtime: &File) -> io::Result<()> {
    let metadata = runtime.metadata()?;
    if !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.gid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(conflict("the Linux runtime directory has unsafe metadata"));
    }
    let _attributes = xattr_identity(runtime)?;
    Ok(())
}

fn open_directory(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_DIRECTORY | nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
}

fn open_helper(path: &Path) -> io::Result<File> {
    OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)
}

fn is_residue_name(name: &str) -> bool {
    name.strip_prefix(DIRECTORY_PREFIX).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn lock_is_busy(error: Errno) -> bool {
    matches!(error, Errno::EAGAIN | Errno::EACCES)
}

fn path_string(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(str::to_owned)
        .ok_or_else(|| invalid_data("a Linux bootstrap residue path is invalid UTF-8"))
}

fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn conflict(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::AlreadyExists, message)
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::is_residue_name;

    #[test]
    fn residue_names_require_the_exact_random_namespace() {
        assert!(is_residue_name(
            "remap-bootstrap-0123456789abcdef0123456789abcdef"
        ));
        assert!(!is_residue_name(
            "remap-bootstrap-0123456789ABCDEF0123456789ABCDEF"
        ));
        assert!(!is_residue_name("remap-bootstrap-short"));
        assert!(!is_residue_name(
            "other-bootstrap-0123456789abcdef0123456789abcdef"
        ));
    }
}
