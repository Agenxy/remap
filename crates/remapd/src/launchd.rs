#[cfg(target_os = "macos")]
mod platform {
    #![allow(unsafe_code)]

    use std::net::{TcpListener, UdpSocket};
    use std::os::fd::{FromRawFd, OwnedFd};
    use std::os::unix::net::UnixListener;

    use nix::unistd::Uid;
    use remap_network::{DnsBindings, DnsRuntimeConfig, GatewayBindings, NetworkError};
    use remap_protocol::Diagnostic;

    use crate::server::{DaemonConfig, PreboundNetwork};

    const DNS_UDP_SOCKET: &str = "remap-dns-udp";
    const DNS_TCP_SOCKET: &str = "remap-dns-tcp";
    const HTTP_SOCKET: &str = "remap-http";
    const SYSTEM_SOCKET: &str = "remap-system";

    pub(crate) fn activate(config: &DaemonConfig) -> Result<PreboundNetwork, Diagnostic> {
        if Uid::effective().is_root() {
            return Err(activation_error(
                "the launchd Remap service must run as its declared non-root user",
            ));
        }
        let dns = if let Some(dns_config) = &config.dns {
            let udp = std::net::UdpSocket::from(activate_one(DNS_UDP_SOCKET)?);
            let tcp = std::net::TcpListener::from(activate_one(DNS_TCP_SOCKET)?);
            Some(
                dns_bindings(dns_config, udp, tcp)
                    .map_err(|_error| activation_error("activated DNS sockets are invalid"))?,
            )
        } else {
            None
        };
        let gateway = if let Some(gateway_config) = &config.gateway {
            let listener = std::net::TcpListener::from(activate_one(HTTP_SOCKET)?);
            Some(
                GatewayBindings::from_listener(gateway_config, listener)
                    .map_err(|_error| activation_error("the activated HTTP socket is invalid"))?,
            )
        } else {
            None
        };
        let system_control = UnixListener::from(activate_one(SYSTEM_SOCKET)?);
        if !is_published_at(&system_control, &config.system_socket) {
            let remembered = remembered_path(&system_control).map_or_else(
                || "an unnamed socket".to_owned(),
                |p| p.display().to_string(),
            );
            return Err(activation_error(&format!(
                "the activated resolver-supervisor socket is invalid: launchd bound {remembered}, the service declares {}",
                config.system_socket.display()
            )));
        }
        Ok(PreboundNetwork {
            dns,
            gateway,
            system_control: Some(system_control),
        })
    }

    /// Whether the socket launchd handed over is the one published at `path`,
    /// where the resolver supervisor will dial it. launchd binds a declared
    /// Unix socket as `<its private directory>/<socket key>` and moves it to
    /// the declared path, so the address the socket remembers is the key's
    /// name under that directory, not the path; the daemon cannot open the
    /// root-only published socket to prove more than that the key matches
    /// and a socket stands at the path.
    fn is_published_at(listener: &UnixListener, path: &std::path::Path) -> bool {
        use std::os::unix::fs::FileTypeExt;

        let Some(remembered) = remembered_path(listener) else {
            return false;
        };
        if remembered == path {
            return true;
        }
        remembered.file_name() == Some(std::ffi::OsStr::new(SYSTEM_SOCKET))
            && std::fs::symlink_metadata(path)
                .is_ok_and(|published| published.file_type().is_socket())
    }

    /// The address a launchd-activated socket remembers, as a path. launchd
    /// hands the socket over with its address padded to the full `sun_path`,
    /// so the name is read up to its first NUL.
    fn remembered_path(listener: &UnixListener) -> Option<std::path::PathBuf> {
        use std::os::unix::ffi::OsStrExt;

        let address = listener.local_addr().ok()?;
        let bytes = address.as_pathname()?.as_os_str().as_bytes();
        let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
        Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
            &bytes[..end],
        )))
    }

    fn dns_bindings(
        config: &DnsRuntimeConfig,
        udp: UdpSocket,
        tcp: TcpListener,
    ) -> Result<DnsBindings, NetworkError> {
        if config.upstreams.is_empty() {
            DnsBindings::from_dormant_sockets(config, udp, tcp)
        } else {
            DnsBindings::from_sockets(config, udp, tcp)
        }
    }

    fn activate_one(name: &'static str) -> Result<OwnedFd, Diagnostic> {
        let descriptors = raunch::activate_socket(name)
            .map_err(|_error| activation_error("launchd did not provide a declared socket"))?;
        if descriptors.len() != 1 {
            for descriptor in descriptors {
                let _closed = nix::unistd::close(descriptor);
            }
            return Err(activation_error(
                "launchd provided an unexpected number of sockets",
            ));
        }
        let descriptor = descriptors
            .into_iter()
            .next()
            .ok_or_else(|| activation_error("launchd did not provide a socket"))?;
        // SAFETY: launch_activate_socket transfers each returned descriptor to
        // the caller. The count is exactly one, it has not been closed or
        // adopted elsewhere, and OwnedFd becomes its sole closing owner.
        Ok(unsafe { OwnedFd::from_raw_fd(descriptor) })
    }

    fn activation_error(message: &str) -> Diagnostic {
        Diagnostic::new(
            "E_LAUNCHD_SOCKET_ACTIVATION",
            message,
            Some("repair or reinstall the native Remap service, then retry".to_owned()),
            false,
        )
    }

    #[cfg(test)]
    mod tests {
        use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};

        use remap_network::DnsRuntimeConfig;

        use super::{dns_bindings, is_published_at};

        #[test]
        fn launchd_accepts_dormant_dns_sockets_before_the_supervisor_plan()
        -> Result<(), Box<dyn std::error::Error>> {
            let address = SocketAddr::from((Ipv4Addr::LOCALHOST, 0));
            let udp = UdpSocket::bind(address)?;
            let bound = udp.local_addr()?;
            let tcp = TcpListener::bind(bound)?;
            let config = DnsRuntimeConfig::new(bound, Vec::new());

            let result = dns_bindings(&config, udp, tcp);

            assert!(result.is_ok());
            Ok(())
        }

        #[test]
        fn the_activated_socket_is_the_published_one_by_path_or_by_launchd_key()
        -> Result<(), Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            let published = directory.path().join("system.sock");
            let direct = std::os::unix::net::UnixListener::bind(&published)?;
            assert!(is_published_at(&direct, &published));

            // As launchd hands it over: bound as the socket key under a private
            // directory, published elsewhere by a move.
            let private = directory.path().join("private");
            std::fs::create_dir(&private)?;
            let managed = std::os::unix::net::UnixListener::bind(private.join("remap-system"))?;
            assert!(is_published_at(&managed, &published));
            assert!(!is_published_at(
                &managed,
                &directory.path().join("missing.sock")
            ));

            let other = std::os::unix::net::UnixListener::bind(private.join("other"))?;
            assert!(!is_published_at(&other, &published));
            Ok(())
        }

        #[test]
        fn a_remembered_address_is_read_up_to_its_first_nul()
        -> Result<(), Box<dyn std::error::Error>> {
            use std::os::unix::ffi::OsStrExt;

            let directory = tempfile::tempdir()?;
            let listener =
                std::os::unix::net::UnixListener::bind(directory.path().join("remap-system"))?;
            let remembered = super::remembered_path(&listener).ok_or("no path")?;
            assert!(!remembered.as_os_str().as_bytes().contains(&0));
            assert_eq!(
                remembered.file_name(),
                Some(std::ffi::OsStr::new("remap-system"))
            );
            Ok(())
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    use remap_protocol::Diagnostic;

    use crate::server::{DaemonConfig, PreboundNetwork};

    pub(crate) fn activate(_config: &DaemonConfig) -> Result<PreboundNetwork, Diagnostic> {
        Err(Diagnostic::new(
            "E_LAUNCHD_SOCKET_ACTIVATION",
            "launchd socket activation is available only on macOS",
            Some("use the native service integration for this operating system".to_owned()),
            false,
        ))
    }
}

pub(crate) use platform::activate;
