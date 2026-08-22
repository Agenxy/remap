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
        let observed_path = system_control
            .local_addr()
            .ok()
            .and_then(|address| address.as_pathname().map(std::path::Path::to_path_buf));
        if observed_path.as_deref() != Some(config.system_socket.as_path()) {
            return Err(activation_error(
                "the activated resolver-supervisor socket is invalid",
            ));
        }
        Ok(PreboundNetwork {
            dns,
            gateway,
            system_control: Some(system_control),
        })
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

        use super::dns_bindings;

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
