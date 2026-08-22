use std::path::{Path, PathBuf};

#[cfg(target_os = "linux")]
use std::os::unix::fs::{FileTypeExt, MetadataExt};

use nix::unistd::{Uid, User};

use crate::Diagnostic;

/// Native filesystem locations used by a per-user Remap daemon.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ControlPaths {
    data_dir: PathBuf,
    database: PathBuf,
    lock: PathBuf,
    socket: PathBuf,
    system_socket: PathBuf,
}

impl ControlPaths {
    /// Resolves the operating system's native per-user application-data path.
    ///
    /// # Errors
    ///
    /// Returns a diagnostic when the platform cannot supply a user data path.
    pub fn discover() -> Result<Self, Diagnostic> {
        native_data_directory().map(Self::under)
    }

    /// Builds deterministic paths under an explicit root for tests and tools.
    #[must_use]
    pub fn under(root: impl AsRef<Path>) -> Self {
        let data_dir = root.as_ref().to_path_buf();
        Self {
            database: data_dir.join("registry.sqlite3"),
            lock: data_dir.join("authority.lock"),
            socket: data_dir.join("control.sock"),
            system_socket: data_dir.join("system.sock"),
            data_dir,
        }
    }

    /// Returns the private data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the registry database path.
    #[must_use]
    pub fn database(&self) -> &Path {
        &self.database
    }

    /// Returns the lifetime lock that excludes a second authority.
    #[must_use]
    pub fn lock(&self) -> &Path {
        &self.lock
    }

    /// Returns the local-control socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Returns the root-only resolver-supervisor socket path.
    #[must_use]
    pub fn system_socket(&self) -> &Path {
        &self.system_socket
    }
}

fn native_data_directory() -> Result<PathBuf, Diagnostic> {
    #[cfg(target_os = "macos")]
    {
        return Ok(native_home_directory()?
            .join("Library")
            .join("Application Support")
            .join("org.Agenxy.Remap"));
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(path) = installed_data_directory() {
            return Ok(path);
        }
        if let Some(path) = std::env::var_os("XDG_DATA_HOME").map(PathBuf::from)
            && path.is_absolute()
        {
            return Ok(path.join("remap"));
        }
        return Ok(native_home_directory()?.join(".local/share/remap"));
    }
    #[allow(unreachable_code)]
    Err(data_path_error(
        "this operating system has no implemented Remap data-directory policy",
    ))
}

#[cfg(target_os = "linux")]
fn installed_data_directory() -> Option<PathBuf> {
    let path = PathBuf::from("/var/lib/remap");
    let metadata = std::fs::symlink_metadata(&path).ok()?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != Uid::current().as_raw()
        || metadata.mode() & 0o777 != 0o700
    {
        return None;
    }
    let socket = std::fs::symlink_metadata(path.join("control.sock")).ok()?;
    if socket.file_type().is_symlink()
        || !socket.file_type().is_socket()
        || socket.uid() != Uid::current().as_raw()
        || socket.mode() & 0o777 != 0o600
    {
        return None;
    }
    Some(path)
}

fn native_home_directory() -> Result<PathBuf, Diagnostic> {
    let user = User::from_uid(Uid::current())
        .map_err(|_| data_path_error("the operating system user record could not be read"))?
        .ok_or_else(|| {
            data_path_error("the current user has no operating system account record")
        })?;
    if !user.dir.is_absolute() {
        return Err(data_path_error(
            "the operating system user record contains a relative home directory",
        ));
    }
    Ok(user.dir)
}

fn data_path_error(message: &str) -> Diagnostic {
    Diagnostic::new(
        "E_DATA_PATH",
        message,
        Some("run Remap from a normal signed-in user session".to_owned()),
        false,
    )
}
