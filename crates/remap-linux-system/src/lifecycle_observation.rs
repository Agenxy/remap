use std::fs::OpenOptions;
use std::io::{self, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use serde::Serialize;

const MAX_OS_RELEASE_BYTES: u64 = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 16 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Distribution {
    id: String,
    #[serde(rename = "versionID")]
    version_id: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PathState {
    path: String,
    kind: &'static str,
    target: Option<String>,
    uid: Option<u32>,
    mode: Option<u32>,
    link_count: Option<u64>,
    entry_count: Option<u32>,
    entry_digest: Option<[u8; 32]>,
}

impl PathState {
    pub(crate) fn is_absent(&self) -> bool {
        self.kind == "absent"
    }
}

pub(crate) fn path_state(path: &Path) -> io::Result<PathState> {
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(PathState {
            path: path.to_string_lossy().into_owned(),
            kind: "absent",
            target: None,
            uid: None,
            mode: None,
            link_count: None,
            entry_count: None,
            entry_digest: None,
        }),
        Err(error) => Err(error),
        Ok(metadata) => {
            let entries = if metadata.is_dir() {
                Some(directory_entries(path)?)
            } else {
                None
            };
            Ok(PathState {
                path: path.to_string_lossy().into_owned(),
                kind: if metadata.file_type().is_symlink() {
                    "symlink"
                } else if metadata.is_file() {
                    "file"
                } else if metadata.is_dir() {
                    "directory"
                } else {
                    "other"
                },
                target: metadata
                    .file_type()
                    .is_symlink()
                    .then(|| {
                        std::fs::read_link(path).map(|value| value.to_string_lossy().into_owned())
                    })
                    .transpose()?,
                uid: Some(metadata.uid()),
                mode: Some(metadata.mode() & 0o7777),
                link_count: Some(metadata.nlink()),
                entry_count: entries.as_ref().map(|(count, _digest)| *count),
                entry_digest: entries.map(|(_count, digest)| digest),
            })
        }
    }
}

pub(crate) fn distribution() -> io::Result<Distribution> {
    let path = Path::new("/usr/lib/os-release");
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_OS_RELEASE_BYTES {
        return Err(invalid_data(
            "the Linux distribution identity is unavailable",
        ));
    }
    let mut text = String::new();
    file.take(MAX_OS_RELEASE_BYTES + 1)
        .read_to_string(&mut text)?;
    let id = os_release_value(&text, "ID").unwrap_or_else(|| "unknown".to_owned());
    let version_id = os_release_value(&text, "VERSION_ID").unwrap_or_else(|| "unknown".to_owned());
    Ok(Distribution { id, version_id })
}

fn directory_entries(path: &Path) -> io::Result<(u32, [u8; 32])> {
    use std::os::unix::ffi::OsStrExt;
    let mut entries = Vec::new();
    for entry in std::fs::read_dir(path)? {
        if entries.len() == MAX_DIRECTORY_ENTRIES {
            return Err(invalid_data(
                "a public directory exceeds the lifecycle snapshot bound",
            ));
        }
        entries.push(entry?.file_name().as_bytes().to_vec());
    }
    entries.sort();
    let count = u32::try_from(entries.len())
        .map_err(|_error| invalid_data("a public directory entry count is invalid"))?;
    let mut encoded = b"remap.linux-directory-entries/v1\0".to_vec();
    for entry in entries {
        encoded.extend_from_slice(&(entry.len() as u64).to_le_bytes());
        encoded.extend_from_slice(&entry);
    }
    Ok((count, crate::digest::sha256(&encoded)))
}

pub(crate) fn os_release_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        (candidate == key).then(|| value.trim_matches('"').to_owned())
    })
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
