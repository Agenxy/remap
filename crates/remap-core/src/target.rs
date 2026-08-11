use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::{IpAddr, Ipv6Addr};
use std::num::NonZeroU16;
use std::str::FromStr;

use crate::{RemapName, RemapNameError};

/// Supported upstream HTTP schemes.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum HttpScheme {
    /// Cleartext HTTP.
    Http,
    /// HTTP over TLS.
    Https,
}

impl Display for HttpScheme {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "http",
            Self::Https => "https",
        })
    }
}

/// How Remap constructs the upstream HTTP `Host` value and TLS SNI.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum HostHeaderPolicy {
    /// Preserve the client-facing Remap name.
    PreserveClient,
    /// Replace it with the configured upstream host.
    UseUpstream,
}

impl HostHeaderPolicy {
    /// Returns the stable machine-readable value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PreserveClient => "preserve-client",
            Self::UseUpstream => "use-upstream",
        }
    }
}

impl Display for HostHeaderPolicy {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A validated HTTP upstream host.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum UpstreamHost {
    /// A canonical hostname.
    Name(RemapName),
    /// An IPv4 or IPv6 address.
    Address(IpAddr),
}

impl Display for UpstreamHost {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(name) => Display::fmt(name, formatter),
            Self::Address(IpAddr::V4(address)) => Display::fmt(address, formatter),
            Self::Address(IpAddr::V6(address)) => write!(formatter, "[{address}]"),
        }
    }
}

/// A validation failure for an HTTP upstream URL.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HttpUpstreamError {
    /// The URL does not contain `scheme://authority`.
    InvalidUrl(String),
    /// Only HTTP and HTTPS are routed by the initial gateway.
    UnsupportedScheme(String),
    /// The authority has no host.
    MissingHost,
    /// User information is forbidden in persisted upstream URLs.
    CredentialsNotSupported,
    /// An upstream base URL cannot include a query.
    QueryNotSupported,
    /// An upstream base URL cannot include a fragment.
    FragmentNotSupported,
    /// The port is missing, zero, non-numeric, or greater than 65535.
    InvalidPort(String),
    /// IPv6 literals must use URL brackets.
    UnbracketedIpv6,
    /// The hostname is invalid under Remap's canonical name policy.
    InvalidHost(RemapNameError),
}

impl Display for HttpUpstreamError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(value) => write!(formatter, "'{value}' is not an HTTP upstream URL"),
            Self::UnsupportedScheme(scheme) => write!(
                formatter,
                "the upstream scheme '{scheme}' is unsupported; use http or https"
            ),
            Self::MissingHost => formatter.write_str("an HTTP upstream URL must include a host"),
            Self::CredentialsNotSupported => {
                formatter.write_str("credentials are not accepted in an upstream URL")
            }
            Self::QueryNotSupported => {
                formatter.write_str("an upstream base URL cannot contain a query")
            }
            Self::FragmentNotSupported => {
                formatter.write_str("an upstream base URL cannot contain a fragment")
            }
            Self::InvalidPort(port) => write!(
                formatter,
                "the upstream port '{port}' must be an integer from 1 through 65535"
            ),
            Self::UnbracketedIpv6 => {
                formatter.write_str("an IPv6 URL host must be enclosed in brackets")
            }
            Self::InvalidHost(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for HttpUpstreamError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidHost(error) => Some(error),
            _ => None,
        }
    }
}

/// A canonical HTTP or HTTPS upstream base URL.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct HttpUpstream {
    scheme: HttpScheme,
    host: UpstreamHost,
    port: Option<NonZeroU16>,
    base_path: String,
    host_header_policy: HostHeaderPolicy,
}

impl HttpUpstream {
    /// Parses an upstream with the default preserve-client host policy.
    ///
    /// # Errors
    ///
    /// Returns a precise [`HttpUpstreamError`] when the URL uses an unsupported
    /// scheme, malformed authority, credentials, query, fragment, or bad port.
    pub fn parse(input: &str) -> Result<Self, HttpUpstreamError> {
        Self::parse_with_policy(input, HostHeaderPolicy::PreserveClient)
    }

    /// Parses an upstream with an explicit host policy.
    ///
    /// # Errors
    ///
    /// Returns a precise [`HttpUpstreamError`] when the URL uses an unsupported
    /// scheme, malformed authority, credentials, query, fragment, or bad port.
    pub fn parse_with_policy(
        input: &str,
        host_header_policy: HostHeaderPolicy,
    ) -> Result<Self, HttpUpstreamError> {
        let (raw_scheme, remainder) = input
            .split_once("://")
            .ok_or_else(|| HttpUpstreamError::InvalidUrl(input.to_owned()))?;
        let scheme = match raw_scheme.to_ascii_lowercase().as_str() {
            "http" => HttpScheme::Http,
            "https" => HttpScheme::Https,
            _ => return Err(HttpUpstreamError::UnsupportedScheme(raw_scheme.to_owned())),
        };

        if remainder.contains('?') {
            return Err(HttpUpstreamError::QueryNotSupported);
        }
        if remainder.contains('#') {
            return Err(HttpUpstreamError::FragmentNotSupported);
        }

        let (authority, base_path) = remainder
            .find('/')
            .map_or((remainder, "/"), |index| remainder.split_at(index));
        if authority.is_empty() {
            return Err(HttpUpstreamError::MissingHost);
        }
        if authority.contains('@') {
            return Err(HttpUpstreamError::CredentialsNotSupported);
        }

        let (host, port) = Self::parse_authority(authority)?;
        Ok(Self {
            scheme,
            host,
            port,
            base_path: base_path.to_owned(),
            host_header_policy,
        })
    }

    /// Returns the upstream scheme.
    #[must_use]
    pub const fn scheme(&self) -> HttpScheme {
        self.scheme
    }

    /// Returns the upstream host.
    #[must_use]
    pub const fn host(&self) -> &UpstreamHost {
        &self.host
    }

    /// Returns an explicitly configured port.
    #[must_use]
    pub const fn port(&self) -> Option<NonZeroU16> {
        self.port
    }

    /// Returns the base path prepended by the future gateway.
    #[must_use]
    pub fn base_path(&self) -> &str {
        &self.base_path
    }

    /// Returns the explicit upstream host policy.
    #[must_use]
    pub const fn host_header_policy(&self) -> HostHeaderPolicy {
        self.host_header_policy
    }

    fn parse_authority(
        authority: &str,
    ) -> Result<(UpstreamHost, Option<NonZeroU16>), HttpUpstreamError> {
        if let Some(bracketed) = authority.strip_prefix('[') {
            let close_index = bracketed.find(']').ok_or(HttpUpstreamError::MissingHost)?;
            let (raw_address, trailing) = bracketed.split_at(close_index);
            let address = raw_address.parse::<Ipv6Addr>().map_err(|_| {
                HttpUpstreamError::InvalidHost(RemapNameError::AddressLiteral(
                    raw_address.to_owned(),
                ))
            })?;
            let trailing = trailing
                .strip_prefix(']')
                .ok_or(HttpUpstreamError::MissingHost)?;
            let port = if trailing.is_empty() {
                None
            } else {
                let raw_port = trailing
                    .strip_prefix(':')
                    .ok_or_else(|| HttpUpstreamError::InvalidUrl(authority.to_owned()))?;
                Some(Self::parse_port(raw_port)?)
            };
            return Ok((UpstreamHost::Address(IpAddr::V6(address)), port));
        }

        if authority.matches(':').count() > 1 {
            return Err(HttpUpstreamError::UnbracketedIpv6);
        }
        let (raw_host, port) = authority.rsplit_once(':').map_or_else(
            || Ok((authority, None)),
            |(host, raw_port)| Self::parse_port(raw_port).map(|port| (host, Some(port))),
        )?;
        if raw_host.is_empty() {
            return Err(HttpUpstreamError::MissingHost);
        }

        let host = raw_host.parse::<IpAddr>().map_or_else(
            |_| {
                RemapName::parse(raw_host)
                    .map(UpstreamHost::Name)
                    .map_err(HttpUpstreamError::InvalidHost)
            },
            |address| Ok(UpstreamHost::Address(address)),
        )?;
        Ok((host, port))
    }

    fn parse_port(raw_port: &str) -> Result<NonZeroU16, HttpUpstreamError> {
        raw_port
            .parse::<NonZeroU16>()
            .map_err(|_| HttpUpstreamError::InvalidPort(raw_port.to_owned()))
    }
}

impl Display for HttpUpstream {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}://{}", self.scheme, self.host)?;
        if let Some(port) = self.port {
            write!(formatter, ":{port}")?;
        }
        formatter.write_str(&self.base_path)
    }
}

impl FromStr for HttpUpstream {
    type Err = HttpUpstreamError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// A validation failure for an inferred mapping destination.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum MappingTargetError {
    /// A DNS alias is not a valid Remap hostname.
    InvalidName(RemapNameError),
    /// An HTTP upstream is invalid.
    InvalidHttpUpstream(HttpUpstreamError),
}

impl Display for MappingTargetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(error) => Display::fmt(error, formatter),
            Self::InvalidHttpUpstream(error) => Display::fmt(error, formatter),
        }
    }
}

impl Error for MappingTargetError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidName(error) => Some(error),
            Self::InvalidHttpUpstream(error) => Some(error),
        }
    }
}

/// A direct DNS destination, DNS alias, or routed HTTP service.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum MappingTarget {
    /// Return an IPv4 or IPv6 DNS answer directly.
    DnsAddress(IpAddr),
    /// Resolve or return a DNS alias under the finalized DNS policy.
    DnsAlias(RemapName),
    /// Return loopback from DNS and route HTTP by Host or TLS SNI.
    Http(HttpUpstream),
}

/// The stable category of a mapping destination.
#[derive(Debug, Clone, Copy, Eq, Hash, PartialEq)]
pub enum MappingTargetKind {
    /// A direct IPv4 or IPv6 DNS answer.
    DnsAddress,
    /// A DNS alias destination.
    DnsAlias,
    /// A locally routed HTTP or HTTPS service.
    Http,
}

impl MappingTargetKind {
    /// Returns the stable machine-readable value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DnsAddress => "dns-address",
            Self::DnsAlias => "dns-alias",
            Self::Http => "http",
        }
    }
}

impl Display for MappingTargetKind {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl MappingTarget {
    /// Parses a destination and applies an explicit policy to HTTP upstreams.
    ///
    /// # Errors
    ///
    /// Returns a validation error when the input is neither an IP address, a
    /// valid alias hostname, nor a supported HTTP upstream.
    pub fn parse_with_http_policy(
        input: &str,
        host_header_policy: HostHeaderPolicy,
    ) -> Result<Self, MappingTargetError> {
        if input.contains("://") {
            return HttpUpstream::parse_with_policy(input, host_header_policy)
                .map(Self::Http)
                .map_err(MappingTargetError::InvalidHttpUpstream);
        }
        if let Ok(address) = input.parse::<IpAddr>() {
            return Ok(Self::DnsAddress(address));
        }
        RemapName::parse(input)
            .map(Self::DnsAlias)
            .map_err(MappingTargetError::InvalidName)
    }

    /// Returns the stable destination category.
    #[must_use]
    pub const fn kind(&self) -> MappingTargetKind {
        match self {
            Self::DnsAddress(_) => MappingTargetKind::DnsAddress,
            Self::DnsAlias(_) => MappingTargetKind::DnsAlias,
            Self::Http(_) => MappingTargetKind::Http,
        }
    }
}

impl Display for MappingTarget {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::DnsAddress(address) => Display::fmt(address, formatter),
            Self::DnsAlias(name) => Display::fmt(name, formatter),
            Self::Http(upstream) => Display::fmt(upstream, formatter),
        }
    }
}

impl FromStr for MappingTarget {
    type Err = MappingTargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse_with_http_policy(input, HostHeaderPolicy::PreserveClient)
    }
}
