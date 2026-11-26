// SPDX-License-Identifier: GPL-3.0-or-later
//! A Supgang peer machine and the exposed TCP services its name reaches
//! (ADR-0033). The name answers one stable loopback address; Supgang alone
//! follows the peer.

use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;
use std::num::NonZeroU16;

use crate::target::{MAX_SERVICE_NAME_BYTES, service_name_valid};

/// The loopback network peer-machine addresses are allocated from, as its
/// base address and prefix length. The privileged reservation and every
/// surface that validates an address use this one range.
pub const PEER_MACHINE_LOOPBACK: (Ipv4Addr, u8) = (Ipv4Addr::new(127, 77, 0, 0), 16);
/// Maximum peer-machine mappings, enabled or not, one registry holds. Each
/// holds one allocated address, and the privileged reservation carries the
/// whole set in one bounded frame.
pub const MAX_PEER_MACHINE_MAPPINGS: usize = 256;
/// Maximum service and port pairs in one peer-machine target.
pub const MAX_PEER_MACHINE_SERVICES: usize = 16;
/// Bytes in a Supgang node ID, written as lowercase hexadecimal.
pub const NODE_ID_HEX_BYTES: usize = 64;
/// Bytes in a Supgang shown fingerprint, written as lowercase hexadecimal.
pub const FINGERPRINT_HEX_BYTES: usize = 8;

const fn network_bits() -> u32 {
    u32::from_be_bytes(PEER_MACHINE_LOOPBACK.0.octets())
}

const fn host_mask() -> u32 {
    u32::MAX >> PEER_MACHINE_LOOPBACK.1
}

/// Returns whether `address` may be allocated to a peer-machine mapping: it
/// lies inside [`PEER_MACHINE_LOOPBACK`] and is neither that network's first
/// nor its last address.
#[must_use]
pub const fn is_peer_machine_address(address: Ipv4Addr) -> bool {
    let bits = u32::from_be_bytes(address.octets());
    let host = bits & host_mask();
    bits & !host_mask() == network_bits() && host != 0 && host != host_mask()
}

/// Returns the lowest allocatable address not in `used`, or `None` when
/// every address in [`PEER_MACHINE_LOOPBACK`] is taken.
#[must_use]
pub fn lowest_free_peer_machine_address(used: &BTreeSet<Ipv4Addr>) -> Option<Ipv4Addr> {
    (1..host_mask())
        .map(|host| Ipv4Addr::from(network_bits() | host))
        .find(|address| !used.contains(address))
}

/// One exposed service on the peer and the port this machine listens on for
/// it.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PeerMachineService {
    name: String,
    port: NonZeroU16,
}

impl PeerMachineService {
    /// Returns the service name the peer's owner exposes.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the local port the mapping's address listens on.
    #[must_use]
    pub const fn port(&self) -> NonZeroU16 {
        self.port
    }
}

/// `supgang://<selector>?<service>=<port>[,<service>=<port>...]`: a Supgang
/// peer machine, selected by its node ID or shown fingerprint, and the
/// exposed services its name reaches (ADR-0033).
///
/// Validated and stored as text. Whether a stream opens is the peer owner's
/// exposure, judged by Supgang when a connection arrives.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PeerMachine {
    selector: String,
    services: Vec<PeerMachineService>,
}

impl PeerMachine {
    /// Parses a peer-machine target.
    ///
    /// # Errors
    ///
    /// Returns a precise [`PeerMachineError`] for a selector that is not a
    /// node ID or fingerprint, a template, or a malformed, duplicated, or
    /// oversized service list.
    pub fn parse(input: &str) -> Result<Self, PeerMachineError> {
        let remainder = input
            .strip_prefix("supgang://")
            .ok_or_else(|| PeerMachineError::InvalidUrl(input.to_owned()))?;
        if remainder.contains(['{', '}']) {
            return Err(PeerMachineError::Template);
        }
        let (selector, query) = remainder
            .split_once('?')
            .ok_or(PeerMachineError::MissingServices)?;
        validate_selector(selector)?;
        if query.is_empty() {
            return Err(PeerMachineError::MissingServices);
        }
        let services = parse_services(query)?;
        Ok(Self {
            selector: selector.to_owned(),
            services,
        })
    }

    /// Returns the node ID or fingerprint that selects the peer.
    #[must_use]
    pub fn selector(&self) -> &str {
        &self.selector
    }

    /// Returns the service and port pairs in the order the owner wrote them.
    #[must_use]
    pub fn services(&self) -> &[PeerMachineService] {
        &self.services
    }
}

fn validate_selector(selector: &str) -> Result<(), PeerMachineError> {
    let identity_length = matches!(selector.len(), NODE_ID_HEX_BYTES | FINGERPRINT_HEX_BYTES);
    if identity_length
        && selector
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    if identity_length && selector.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(PeerMachineError::SelectorNotLowercase(selector.to_owned()));
    }
    Err(PeerMachineError::SelectorNotIdentity(
        selector.chars().take(NODE_ID_HEX_BYTES).collect(),
    ))
}

fn parse_services(query: &str) -> Result<Vec<PeerMachineService>, PeerMachineError> {
    let count = query.split(',').count();
    if count > MAX_PEER_MACHINE_SERVICES {
        return Err(PeerMachineError::TooManyServices(count));
    }
    let mut names = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut services = Vec::with_capacity(count);
    for pair in query.split(',') {
        let (name, raw_port) = pair
            .split_once('=')
            .ok_or_else(|| PeerMachineError::InvalidPair(bounded(pair)))?;
        if !service_name_valid(name) {
            return Err(PeerMachineError::InvalidService(bounded(name)));
        }
        let port = parse_port(raw_port).ok_or_else(|| PeerMachineError::InvalidPort {
            service: name.to_owned(),
            port: bounded(raw_port),
        })?;
        if !names.insert(name) {
            return Err(PeerMachineError::DuplicateService(name.to_owned()));
        }
        if !ports.insert(port) {
            return Err(PeerMachineError::DuplicatePort(port));
        }
        services.push(PeerMachineService {
            name: name.to_owned(),
            port,
        });
    }
    Ok(services)
}

/// Accepts only decimal digits, so `+22` and `0x16` are never ports.
fn parse_port(raw: &str) -> Option<NonZeroU16> {
    if raw.is_empty() || raw.len() > 5 || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// Keeps an echoed fragment of the owner's input short.
fn bounded(value: &str) -> String {
    value.chars().take(32).collect()
}

impl Display for PeerMachine {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "supgang://{}?", self.selector)?;
        for (index, service) in self.services.iter().enumerate() {
            if index > 0 {
                formatter.write_str(",")?;
            }
            write!(formatter, "{}={}", service.name, service.port)?;
        }
        Ok(())
    }
}

/// A validation failure for a `supgang://<selector>?<service>=<port>` target.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PeerMachineError {
    /// The input does not start with `supgang://`.
    InvalidUrl(String),
    /// No `?<service>=<port>` list follows the selector.
    MissingServices,
    /// The selector is not a node ID or fingerprint, such as a Supgang name.
    SelectorNotIdentity(String),
    /// The selector is a node ID or fingerprint written with uppercase.
    SelectorNotLowercase(String),
    /// The target contains a template placeholder.
    Template,
    /// A list entry is not `<service>=<port>`.
    InvalidPair(String),
    /// A service name is not one Supgang would expose.
    InvalidService(String),
    /// A port is not an integer from 1 through 65535.
    InvalidPort {
        /// The service the port was written for.
        service: String,
        /// The port as written.
        port: String,
    },
    /// A service is listed twice.
    DuplicateService(String),
    /// A port is listed twice.
    DuplicatePort(NonZeroU16),
    /// More pairs than [`MAX_PEER_MACHINE_SERVICES`].
    TooManyServices(usize),
}

impl Display for PeerMachineError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(value) => write!(formatter, "'{value}' is not a supgang:// target"),
            Self::MissingServices => formatter.write_str(
                "a supgang:// target names a peer's service, supgang://<peer>/<service>, or a peer \
                 machine and the services it exposes, supgang://<node-id>?<service>=<port>[,...]",
            ),
            Self::SelectorNotIdentity(selector) => write!(
                formatter,
                "'{selector}' does not select a peer machine: use its Supgang node ID \
                 ({NODE_ID_HEX_BYTES} lowercase hex) or fingerprint ({FINGERPRINT_HEX_BYTES} lowercase \
                 hex), never its name, which may repeat or change; `supgang resolve <name>` shows both"
            ),
            Self::SelectorNotLowercase(selector) => write!(
                formatter,
                "'{selector}' must be written in lowercase hex, as Supgang shows node IDs and fingerprints"
            ),
            Self::Template => formatter.write_str(
                "a peer machine target cannot be a template; {1} and {2} apply only to \
                 supgang://<peer>/<service> on a wildcard",
            ),
            Self::InvalidPair(pair) => write!(
                formatter,
                "'{pair}' is not a <service>=<port> pair, such as ssh=22"
            ),
            Self::InvalidService(service) => write!(
                formatter,
                "'{service}' is not a service name: 1 through {MAX_SERVICE_NAME_BYTES} lowercase ASCII \
                 letters, digits, or hyphens, not starting with a hyphen"
            ),
            Self::InvalidPort { service, port } => write!(
                formatter,
                "the port '{port}' for {service} must be an integer from 1 through 65535"
            ),
            Self::DuplicateService(service) => {
                write!(formatter, "the service {service} is listed more than once")
            }
            Self::DuplicatePort(port) => write!(
                formatter,
                "the port {port} is listed more than once; each service needs its own port"
            ),
            Self::TooManyServices(count) => write!(
                formatter,
                "the target lists {count} services; a peer machine target lists 1 through \
                 {MAX_PEER_MACHINE_SERVICES}"
            ),
        }
    }
}

impl Error for PeerMachineError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::net::Ipv4Addr;

    use super::{is_peer_machine_address, lowest_free_peer_machine_address};

    #[test]
    fn the_range_excludes_its_first_and_last_address() {
        assert!(!is_peer_machine_address(Ipv4Addr::new(127, 77, 0, 0)));
        assert!(is_peer_machine_address(Ipv4Addr::new(127, 77, 0, 1)));
        assert!(is_peer_machine_address(Ipv4Addr::new(127, 77, 255, 254)));
        assert!(!is_peer_machine_address(Ipv4Addr::new(127, 77, 255, 255)));
        assert!(!is_peer_machine_address(Ipv4Addr::LOCALHOST));
        assert!(!is_peer_machine_address(Ipv4Addr::new(127, 78, 0, 1)));
    }

    #[test]
    fn allocation_takes_the_lowest_gap_and_reports_exhaustion() {
        let mut used = BTreeSet::new();
        assert_eq!(
            lowest_free_peer_machine_address(&used),
            Some(Ipv4Addr::new(127, 77, 0, 1))
        );
        used.extend([Ipv4Addr::new(127, 77, 0, 1), Ipv4Addr::new(127, 77, 0, 3)]);
        assert_eq!(
            lowest_free_peer_machine_address(&used),
            Some(Ipv4Addr::new(127, 77, 0, 2))
        );
        let every: BTreeSet<Ipv4Addr> = (1..u32::from(u16::MAX))
            .map(|host| Ipv4Addr::from(0x7f4d_0000 | host))
            .collect();
        assert!(
            every
                .iter()
                .all(|address| is_peer_machine_address(*address))
        );
        assert_eq!(lowest_free_peer_machine_address(&every), None);
    }
}
