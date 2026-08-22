use std::io;

use tokio::net::UnixStream;

/// Verifies that the socket peer is either the daemon's owning user or root.
///
/// The root-only native installer must authenticate the exact runtime before
/// committing system DNS and publications. No unrelated non-root account is
/// admitted to the per-user control plane.
pub(crate) fn authorize(stream: &UnixStream) -> io::Result<()> {
    let peer_uid = peer_uid(stream)?;
    let daemon_uid = nix::unistd::Uid::effective().as_raw();
    if control_peer_is_authorized(peer_uid, daemon_uid) {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "local-control peer user does not match the daemon user",
    ))
}

const fn control_peer_is_authorized(peer_uid: u32, daemon_uid: u32) -> bool {
    peer_uid == daemon_uid || peer_uid == 0
}

/// Verifies that a system-control peer is the operating-system superuser.
pub(crate) fn authorize_root(stream: &UnixStream) -> io::Result<()> {
    if peer_uid(stream)? == 0 {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "system-control peer is not root",
    ))
}

#[cfg(any(
    target_os = "macos",
    target_os = "freebsd",
    target_os = "openbsd",
    target_os = "netbsd",
    target_os = "dragonfly"
))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    nix::unistd::getpeereid(stream)
        .map(|(uid, _gid)| uid.as_raw())
        .map_err(io::Error::other)
}

#[cfg(any(target_os = "linux", target_os = "android"))]
fn peer_uid(stream: &UnixStream) -> io::Result<u32> {
    nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .map(|credentials| credentials.uid())
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use tokio::net::{UnixListener, UnixStream};

    #[test]
    fn control_peer_allows_only_the_owner_or_root() {
        assert!(super::control_peer_is_authorized(501, 501));
        assert!(super::control_peer_is_authorized(0, 501));
        assert!(!super::control_peer_is_authorized(502, 501));
    }

    #[tokio::test]
    async fn ordinary_user_cannot_publish_system_resolver_state() -> Result<(), Box<dyn Error>> {
        if nix::unistd::Uid::effective().is_root() {
            return Ok(());
        }
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("peer.sock");
        let listener = UnixListener::bind(&path)?;
        let client = UnixStream::connect(&path).await?;
        let (server, _address) = listener.accept().await?;
        assert!(super::authorize(&client).is_ok());
        assert!(super::authorize_root(&server).is_err());
        Ok(())
    }
}
