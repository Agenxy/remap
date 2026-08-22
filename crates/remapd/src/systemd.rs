use remap_protocol::Diagnostic;

#[cfg(target_os = "linux")]
mod platform {
    use remap_linux::{adopt_systemd_sockets, reject_unrequested_activation};
    use remap_network::{DnsBindings, GatewayBindings};
    use remap_protocol::Diagnostic;

    use crate::server::{DaemonConfig, PreboundNetwork};

    pub(crate) fn activate(config: &DaemonConfig) -> Result<PreboundNetwork, Diagnostic> {
        let sockets = adopt_systemd_sockets().map_err(|_error| activation_error())?;
        let (udp, tcp, http) = sockets.into_parts();
        let dns_config = config.dns.as_ref().ok_or_else(activation_error)?;
        let gateway_config = config.gateway.as_ref().ok_or_else(activation_error)?;
        let dns = if dns_config.upstreams.is_empty() {
            DnsBindings::from_dormant_sockets(dns_config, udp, tcp)
        } else {
            DnsBindings::from_sockets(dns_config, udp, tcp)
        }
        .map_err(|_error| activation_error())?;
        let gateway = GatewayBindings::from_listener(gateway_config, http)
            .map_err(|_error| activation_error())?;
        Ok(PreboundNetwork {
            dns: Some(dns),
            gateway: Some(gateway),
            system_control: None,
        })
    }

    pub(crate) fn reject_unrequested() -> Result<(), Diagnostic> {
        reject_unrequested_activation().map_err(|_error| activation_error())
    }

    fn activation_error() -> Diagnostic {
        Diagnostic::new(
            "E_SYSTEMD_SOCKET_ACTIVATION",
            "the native systemd socket-activation contract failed",
            Some("repair or reinstall the native Remap systemd service".to_owned()),
            false,
        )
    }
}

#[cfg(not(target_os = "linux"))]
mod platform {
    use remap_protocol::Diagnostic;

    use crate::server::{DaemonConfig, PreboundNetwork};

    pub(crate) fn activate(_config: &DaemonConfig) -> Result<PreboundNetwork, Diagnostic> {
        Err(Diagnostic::new(
            "E_SYSTEMD_SOCKET_ACTIVATION",
            "systemd socket activation is available only on Linux",
            Some("use this operating system's native Remap service".to_owned()),
            false,
        ))
    }
}

pub(crate) use platform::activate;
#[cfg(target_os = "linux")]
pub(crate) use platform::reject_unrequested;

pub(crate) fn validate_config(config: &crate::server::DaemonConfig) -> Result<(), Diagnostic> {
    if config.systemd_sockets && (config.launchd_sockets || config.run_as.is_some()) {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "systemd socket activation cannot be combined with another privilege path",
            Some("use only --systemd-sockets in the Linux system service".to_owned()),
            false,
        ));
    }
    if config.systemd_sockets && (config.dns.is_none() || config.gateway.is_none()) {
        return Err(Diagnostic::new(
            "E_DAEMON_CONFIG",
            "systemd socket activation requires DNS and HTTP listener configuration",
            Some("repair or reinstall the native Remap systemd units".to_owned()),
            false,
        ));
    }
    Ok(())
}
