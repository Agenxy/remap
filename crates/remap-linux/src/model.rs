#[cfg(target_os = "linux")]
use std::net::Ipv6Addr;
use std::net::{IpAddr, Ipv4Addr};

use serde::{Deserialize, Serialize};

use crate::{LinuxError, LinuxErrorKind, LinuxResult};

/// Maximum DNS servers accepted from one resolved link.
pub const MAX_DNS_SERVERS: usize = 32;
/// Maximum routing and search domains accepted from one resolved link.
pub const MAX_DOMAINS: usize = 128;
const MAX_DOMAIN_BYTES: usize = 253;

/// Positive Linux interface index accepted by systemd-resolved.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LinkIndex(u32);

impl LinkIndex {
    /// Validates one kernel interface index.
    ///
    /// # Errors
    ///
    /// Returns an invalid-scope error for zero or an index outside resolved's range.
    pub fn new(value: u32) -> LinuxResult<Self> {
        if value == 0 || value > i32::MAX.cast_unsigned() {
            return Err(invalid_scope("the resolver link index is invalid"));
        }
        Ok(Self(value))
    }

    /// Returns the positive kernel interface index.
    #[must_use]
    pub const fn get(self) -> u32 {
        self.0
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn as_i32(self) -> i32 {
        self.0.cast_signed()
    }
}

/// One exact systemd-resolved `DNSEx` entry.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DnsServer {
    address: IpAddr,
    port: u16,
    server_name: String,
}

impl DnsServer {
    /// Validates a DNS server including its optional DNS-over-TLS server name.
    ///
    /// # Errors
    ///
    /// Returns an invalid-state error when the server name is unsafe or oversized.
    pub fn new(address: IpAddr, port: u16, server_name: impl Into<String>) -> LinuxResult<Self> {
        let server_name = server_name.into();
        validate_text(
            &server_name,
            MAX_DOMAIN_BYTES,
            "the DNS server name is invalid",
        )?;
        Ok(Self {
            address,
            port,
            server_name,
        })
    }

    /// Returns the server address.
    #[must_use]
    pub const fn address(&self) -> IpAddr {
        self.address
    }

    /// Returns the exact resolved port, where zero means its protocol default.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Returns the exact DNS-over-TLS server name, or an empty string when absent.
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn from_resolved(
        family: i32,
        bytes: &[u8],
        port: u16,
        name: String,
    ) -> LinuxResult<Self> {
        let address = match (family, bytes) {
            (2, [a, b, c, d]) => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
            (10, bytes) if bytes.len() == 16 => {
                let octets: [u8; 16] = bytes.try_into().map_err(|_error| {
                    invalid_state("systemd-resolved returned an invalid IPv6 DNS server")
                })?;
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            _ => {
                return Err(invalid_state(
                    "systemd-resolved returned an unsupported DNS address family",
                ));
            }
        };
        Self::new(address, port, name)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn to_resolved(&self) -> (i32, Vec<u8>, u16, String) {
        let (family, bytes) = match self.address {
            IpAddr::V4(address) => (2, address.octets().to_vec()),
            IpAddr::V6(address) => (10, address.octets().to_vec()),
        };
        (family, bytes, self.port, self.server_name.clone())
    }
}

/// One exact systemd-resolved search or route-only domain.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkDomain {
    name: String,
    route_only: bool,
}

impl LinkDomain {
    /// Validates one resolved domain. The root domain is represented as `.`.
    ///
    /// # Errors
    ///
    /// Returns an invalid-state error for an empty, unsafe, or oversized name.
    pub fn new(name: impl Into<String>, route_only: bool) -> LinuxResult<Self> {
        let name = name.into();
        if name.is_empty() {
            return Err(invalid_state("a resolver domain cannot be empty"));
        }
        validate_text(&name, MAX_DOMAIN_BYTES, "the resolver domain is invalid")?;
        Ok(Self { name, route_only })
    }

    /// Returns the exact domain name without systemd's route-only marker.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Reports whether this is a route-only domain.
    #[must_use]
    pub const fn route_only(&self) -> bool {
        self.route_only
    }
}

/// Complete resolver state Remap reads or writes for one link.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LinkState {
    link: LinkIndex,
    dns_servers: Vec<DnsServer>,
    domains: Vec<LinkDomain>,
    default_route: bool,
}

impl LinkState {
    /// Validates a complete per-link resolver snapshot.
    ///
    /// # Errors
    ///
    /// Returns an invalid-state error when a collection exceeds its fixed bound.
    pub fn new(
        link: LinkIndex,
        dns_servers: Vec<DnsServer>,
        domains: Vec<LinkDomain>,
        default_route: bool,
    ) -> LinuxResult<Self> {
        if dns_servers.len() > MAX_DNS_SERVERS || domains.len() > MAX_DOMAINS {
            return Err(invalid_state(
                "the per-link resolver state exceeds its bound",
            ));
        }
        Ok(Self {
            link,
            dns_servers,
            domains,
            default_route,
        })
    }

    /// Builds Remap's route-all loopback state for one link.
    ///
    /// # Errors
    ///
    /// Returns an invalid-state error if the fixed resolver target cannot be represented.
    pub fn remap_loopback(link: LinkIndex) -> LinuxResult<Self> {
        Self::new(
            link,
            vec![DnsServer::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0, "")?],
            vec![LinkDomain::new(".", true)?],
            true,
        )
    }

    /// Returns the owned link.
    #[must_use]
    pub const fn link(&self) -> LinkIndex {
        self.link
    }

    /// Returns DNS servers in resolved order.
    #[must_use]
    pub fn dns_servers(&self) -> &[DnsServer] {
        &self.dns_servers
    }

    /// Returns search and route domains in resolved order.
    #[must_use]
    pub fn domains(&self) -> &[LinkDomain] {
        &self.domains
    }

    /// Returns the exact per-link default-route setting.
    #[must_use]
    pub const fn default_route(&self) -> bool {
        self.default_route
    }

    pub(crate) fn with_dns_from(&self, source: &Self) -> Self {
        let mut next = self.clone();
        next.dns_servers.clone_from(&source.dns_servers);
        next
    }

    pub(crate) fn with_domains_from(&self, source: &Self) -> Self {
        let mut next = self.clone();
        next.domains.clone_from(&source.domains);
        next
    }

    pub(crate) fn with_default_route_from(&self, source: &Self) -> Self {
        let mut next = self.clone();
        next.default_route = source.default_route;
        next
    }

    pub(crate) fn merge_external_changes(
        &self,
        owned: &Self,
        observed: &Self,
    ) -> LinuxResult<Self> {
        if self.link != owned.link || self.link != observed.link {
            return Err(invalid_scope(
                "resolver rebase states refer to different links",
            ));
        }
        Self::new(
            self.link,
            if observed.dns_servers == owned.dns_servers {
                self.dns_servers.clone()
            } else {
                observed.dns_servers.clone()
            },
            if observed.domains == owned.domains {
                self.domains.clone()
            } else {
                observed.domains.clone()
            },
            if observed.default_route == owned.default_route {
                self.default_route
            } else {
                observed.default_route
            },
        )
    }
}

pub(crate) fn validate_single_scope(states: &[LinkState]) -> LinuxResult<&LinkState> {
    match states {
        [state] => Ok(state),
        [] => Err(invalid_scope("no systemd-resolved link was selected")),
        _ => Err(invalid_scope(
            "multiple resolver links require an explicit scoped-routing design",
        )),
    }
}

fn validate_text(value: &str, maximum: usize, message: &'static str) -> LinuxResult<()> {
    if value.len() > maximum || value.chars().any(char::is_control) {
        return Err(invalid_state(message));
    }
    Ok(())
}

const fn invalid_scope(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::InvalidScope, message)
}

const fn invalid_state(message: &'static str) -> LinuxError {
    LinuxError::new(LinuxErrorKind::InvalidState, message)
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{DnsServer, LinkDomain, LinkIndex, LinkState};

    #[test]
    fn sequential_external_fields_never_launder_owned_resolver_values() -> crate::LinuxResult<()> {
        let link = LinkIndex::new(2)?;
        let before = LinkState::new(
            link,
            vec![DnsServer::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 5, 2)),
                0,
                "",
            )?],
            vec![LinkDomain::new("attlocal.net", false)?],
            false,
        )?;
        let owned = LinkState::remap_loopback(link)?;
        let dns_only = LinkState::new(
            link,
            vec![DnsServer::new(
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                0,
                "",
            )?],
            owned.domains().to_vec(),
            owned.default_route(),
        )?;
        let after_dns = before.merge_external_changes(&owned, &dns_only)?;
        assert_eq!(after_dns.dns_servers(), dns_only.dns_servers());
        assert_eq!(after_dns.domains(), before.domains());
        assert_eq!(after_dns.default_route(), before.default_route());

        let domain_only = LinkState::new(
            link,
            owned.dns_servers().to_vec(),
            vec![LinkDomain::new("transition.test", false)?],
            owned.default_route(),
        )?;
        let after_domain = after_dns.merge_external_changes(&owned, &domain_only)?;
        assert_eq!(after_domain.dns_servers(), dns_only.dns_servers());
        assert_eq!(after_domain.domains(), domain_only.domains());
        assert_eq!(after_domain.default_route(), before.default_route());
        Ok(())
    }
}
