//! Advisory reachability of a loopback HTTP target (ADR-0028).
//!
//! A mapping to a port with nothing listening is valid owner intent, and it
//! still looks healthy until a request fails. Before a change is committed
//! or previewed, the authority may ask whether anything accepts a TCP
//! connection where a loopback HTTP target points. The answer is advice: it
//! never blocks a change.
//!
//! The probe is confined to this machine. Only an address literal on the
//! loopback interface, or the name `localhost`, is probed; any other name
//! would need a DNS lookup, and any other address could be another
//! machine. Peer targets are never probed. The probe connects and closes
//! without sending a byte.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use remap_core::{HttpScheme, MappingTarget, UpstreamHost};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::timeout;

/// The longest one probe waits for a connection to be accepted.
pub const PROBE_DEADLINE: Duration = Duration::from_secs(1);

/// What one bounded connection attempt to a loopback target observed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reachability {
    /// Something accepted the connection.
    Accepted,
    /// The connection was refused: nothing is listening there.
    Refused,
    /// Nothing accepted the connection before the deadline.
    TimedOut,
    /// The connection failed in another way.
    Failed,
}

/// The loopback addresses `target` would be dialled at, or `None` when the
/// target is not one Remap probes: anything other than an HTTP target whose
/// host is a loopback address literal or `localhost`.
#[must_use]
pub fn loopback_addresses(target: &MappingTarget) -> Option<Vec<SocketAddr>> {
    let MappingTarget::Http(upstream) = target else {
        return None;
    };
    let port = upstream.port().map_or_else(
        || match upstream.scheme() {
            HttpScheme::Http => 80,
            HttpScheme::Https => 443,
        },
        std::num::NonZeroU16::get,
    );
    match upstream.host() {
        UpstreamHost::Address(address) if address.to_canonical().is_loopback() => {
            Some(vec![SocketAddr::new(*address, port)])
        }
        UpstreamHost::Name(name) if name.as_str() == "localhost" => Some(vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), port),
        ]),
        UpstreamHost::Address(_) | UpstreamHost::Name(_) => None,
    }
}

/// Tries every address at once, each for at most `deadline`, and reports
/// the most useful observation: any acceptance, else any refusal, else a
/// timeout, else a failure. Addresses that are not loopback are skipped.
pub async fn probe(addresses: &[SocketAddr], deadline: Duration) -> Reachability {
    let mut attempts = JoinSet::new();
    for address in addresses
        .iter()
        .copied()
        .filter(|address| address.ip().to_canonical().is_loopback())
    {
        attempts.spawn(attempt(address, deadline));
    }
    let mut observed = Vec::with_capacity(attempts.len());
    while let Some(outcome) = attempts.join_next().await {
        observed.push(outcome.unwrap_or(Reachability::Failed));
    }
    [
        Reachability::Accepted,
        Reachability::Refused,
        Reachability::TimedOut,
    ]
    .into_iter()
    .find(|wanted| observed.contains(wanted))
    .unwrap_or(Reachability::Failed)
}

async fn attempt(address: SocketAddr, deadline: Duration) -> Reachability {
    match timeout(deadline, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            Reachability::Accepted
        }
        Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
            Reachability::Refused
        }
        Ok(Err(_error)) => Reachability::Failed,
        Err(_elapsed) => Reachability::TimedOut,
    }
}

#[cfg(test)]
mod tests {
    use remap_core::{HostHeaderPolicy, MappingTarget};

    use super::loopback_addresses;

    fn addresses(target: &str) -> Result<Option<Vec<String>>, Box<dyn std::error::Error>> {
        let target = MappingTarget::parse_with_http_policy(target, HostHeaderPolicy::UseUpstream)?;
        Ok(
            loopback_addresses(&target)
                .map(|found| found.iter().map(ToString::to_string).collect()),
        )
    }

    #[test]
    fn only_loopback_http_targets_are_probed() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(
            addresses("http://127.0.0.1:5173/")?,
            Some(vec!["127.0.0.1:5173".to_owned()])
        );
        assert_eq!(
            addresses("https://[::1]/")?,
            Some(vec!["[::1]:443".to_owned()])
        );
        assert_eq!(
            addresses("http://localhost:8080/")?,
            Some(vec!["127.0.0.1:8080".to_owned(), "[::1]:8080".to_owned()])
        );
        assert_eq!(
            addresses("http://127.8.9.10/")?,
            Some(vec!["127.8.9.10:80".to_owned()])
        );
        for unprobed in [
            "http://192.168.1.20:8080/",
            "http://10.0.0.8/",
            "http://example.test:3000/",
            "http://app.localhost:3000/",
            "supgang://solis/dibs",
            "supgang+http://solis/preview",
            "127.0.0.1",
            "moved://renamed.test",
        ] {
            assert_eq!(addresses(unprobed)?, None, "{unprobed}");
        }
        Ok(())
    }
}
