use std::io;
use std::net::{IpAddr, SocketAddr};

use remap_linux::ActivationRecord;

const DEFAULT_DNS_PORT: u16 = 53;
const MAX_UPSTREAMS: usize = 4;

pub(crate) fn upstreams(record: &ActivationRecord) -> io::Result<Vec<SocketAddr>> {
    let mut upstreams = Vec::with_capacity(record.before().dns_servers().len());
    for server in record.before().dns_servers() {
        if !server.server_name().is_empty() {
            return Err(unsupported(
                "DNS-over-TLS upstreams are not supported by this slice",
            ));
        }
        let port = if server.port() == 0 {
            DEFAULT_DNS_PORT
        } else {
            server.port()
        };
        let address = SocketAddr::new(server.address(), port);
        if address.ip().is_unspecified()
            || address.ip().is_multicast()
            || address.ip().is_loopback()
            || address == SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 53)
        {
            return Err(unsupported(
                "captured resolver upstream is unsafe for forwarding",
            ));
        }
        upstreams.push(address);
    }
    if upstreams.is_empty() || upstreams.len() > MAX_UPSTREAMS {
        return Err(unsupported(
            "captured resolver upstream count is unsupported",
        ));
    }
    Ok(upstreams)
}

fn unsupported(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message)
}
