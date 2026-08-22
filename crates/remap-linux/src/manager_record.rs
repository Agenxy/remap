use serde::{Deserialize, Serialize};

use crate::{LinuxError, LinuxErrorKind, LinuxResult};

const MAX_DNS_VALUES: usize = 16;
const MAX_DNS_VALUE_BYTES: usize = 1024;
const MAX_INTERFACE_NAME_BYTES: usize = 15;

/// Native resolver owner whose exact restoration data accompanies a link record.
#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum ResolverManagerRecord {
    /// Legacy record that predates exact systemd manager identity.
    #[default]
    Systemd,
    /// Direct transient `systemd-resolved` ownership of one exact interface.
    SystemdResolved(String),
    /// Persistent systemd-networkd ownership of one exact interface.
    SystemdNetworkd(String),
    /// `NetworkManager` applied-connection DNS fields and full-state digests.
    NetworkManager(Box<NetworkManagerOwnership>),
}

impl ResolverManagerRecord {
    pub(crate) fn validate(&self) -> LinuxResult<()> {
        match self {
            Self::Systemd => Ok(()),
            Self::SystemdResolved(interface_name) | Self::SystemdNetworkd(interface_name) => {
                validate_interface_name(interface_name)
            }
            Self::NetworkManager(ownership) => ownership.validate(),
        }
    }

    /// Returns the stable interface identity when the manager record is exact.
    #[must_use]
    pub fn interface_name(&self) -> Option<&str> {
        match self {
            Self::Systemd => None,
            Self::SystemdResolved(interface_name) | Self::SystemdNetworkd(interface_name) => {
                Some(interface_name)
            }
            Self::NetworkManager(ownership) => Some(ownership.interface_name()),
        }
    }
}

/// Integrity-covered `NetworkManager` applied-connection ownership facts.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkManagerOwnership {
    interface_name: String,
    before_connection_digest: [u8; 32],
    protected_connection_digest: [u8; 32],
    ipv4: Option<NetworkManagerIpDns>,
    ipv6: Option<NetworkManagerIpDns>,
}

impl NetworkManagerOwnership {
    /// Creates a bounded exact applied-connection DNS snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid interface identity, empty ownership, or
    /// unbounded DNS fields.
    pub fn new(
        interface_name: String,
        before_connection_digest: [u8; 32],
        protected_connection_digest: [u8; 32],
        ipv4: Option<NetworkManagerIpDns>,
        ipv6: Option<NetworkManagerIpDns>,
    ) -> LinuxResult<Self> {
        let ownership = Self {
            interface_name,
            before_connection_digest,
            protected_connection_digest,
            ipv4,
            ipv6,
        };
        ownership.validate()?;
        Ok(ownership)
    }

    /// Returns the exact interface name used to resolve the NM device object.
    #[must_use]
    pub fn interface_name(&self) -> &str {
        &self.interface_name
    }

    /// Returns the canonical digest before Remap's applied-connection mutation.
    #[must_use]
    pub const fn before_connection_digest(&self) -> [u8; 32] {
        self.before_connection_digest
    }

    /// Returns the digest of every applied-connection field Remap does not own.
    #[must_use]
    pub const fn protected_connection_digest(&self) -> [u8; 32] {
        self.protected_connection_digest
    }

    /// Returns the exact prior IPv4 DNS properties, when the section existed.
    #[must_use]
    pub const fn ipv4(&self) -> Option<&NetworkManagerIpDns> {
        self.ipv4.as_ref()
    }

    /// Returns the exact prior IPv6 DNS properties, when the section existed.
    #[must_use]
    pub const fn ipv6(&self) -> Option<&NetworkManagerIpDns> {
        self.ipv6.as_ref()
    }

    fn validate(&self) -> LinuxResult<()> {
        if validate_interface_name(&self.interface_name).is_err()
            || (self.ipv4.is_none() && self.ipv6.is_none())
        {
            return Err(invalid_record());
        }
        if let Some(ipv4) = &self.ipv4 {
            ipv4.validate()?;
        }
        if let Some(ipv6) = &self.ipv6 {
            ipv6.validate()?;
        }
        Ok(())
    }
}

fn validate_interface_name(value: &str) -> LinuxResult<()> {
    if value.is_empty()
        || value.len() > MAX_INTERFACE_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._:-".contains(&byte))
    {
        Err(invalid_record())
    } else {
        Ok(())
    }
}

/// Exact presence and value of every applied-connection DNS property Remap changes.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkManagerIpDns {
    dns_data: Option<Vec<String>>,
    dns_search: Option<Vec<String>>,
    ignore_auto_dns: Option<bool>,
    dns_priority: Option<i32>,
    legacy_dns: Option<NetworkManagerLegacyDns>,
}

impl NetworkManagerIpDns {
    /// Creates one exact property-presence snapshot.
    ///
    /// # Errors
    ///
    /// Returns an error when a string collection exceeds its count or byte bound.
    pub fn new(
        dns_data: Option<Vec<String>>,
        dns_search: Option<Vec<String>>,
        ignore_auto_dns: Option<bool>,
        dns_priority: Option<i32>,
        legacy_dns: Option<NetworkManagerLegacyDns>,
    ) -> LinuxResult<Self> {
        let state = Self {
            dns_data,
            dns_search,
            ignore_auto_dns,
            dns_priority,
            legacy_dns,
        };
        state.validate()?;
        Ok(state)
    }

    /// Returns the prior presence and value of `dns-data`.
    #[must_use]
    pub const fn dns_data(&self) -> Option<&Vec<String>> {
        self.dns_data.as_ref()
    }

    /// Returns the prior presence and value of `dns-search`.
    #[must_use]
    pub const fn dns_search(&self) -> Option<&Vec<String>> {
        self.dns_search.as_ref()
    }

    /// Returns the prior presence and value of `ignore-auto-dns`.
    #[must_use]
    pub const fn ignore_auto_dns(&self) -> Option<bool> {
        self.ignore_auto_dns
    }

    /// Returns the prior presence and value of `dns-priority`.
    #[must_use]
    pub const fn dns_priority(&self) -> Option<i32> {
        self.dns_priority
    }

    /// Returns the prior presence, family, and exact deprecated `dns` value.
    #[must_use]
    pub const fn legacy_dns(&self) -> Option<&NetworkManagerLegacyDns> {
        self.legacy_dns.as_ref()
    }

    fn validate(&self) -> LinuxResult<()> {
        validate_strings(self.dns_data.as_deref())?;
        validate_strings(self.dns_search.as_deref())?;
        if let Some(legacy) = &self.legacy_dns {
            legacy.validate()?;
        }
        Ok(())
    }
}

/// Exact typed value of `NetworkManager`'s deprecated per-family `dns` property.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum NetworkManagerLegacyDns {
    /// IPv4 DNS addresses represented as documented network-order integers.
    Ipv4(Vec<u32>),
    /// IPv6 DNS addresses represented as exact 16-byte arrays.
    Ipv6(Vec<Vec<u8>>),
}

impl NetworkManagerLegacyDns {
    fn validate(&self) -> LinuxResult<()> {
        let valid = match self {
            Self::Ipv4(values) => values.len() <= MAX_DNS_VALUES,
            Self::Ipv6(values) => {
                values.len() <= MAX_DNS_VALUES && values.iter().all(|value| value.len() == 16)
            }
        };
        if valid { Ok(()) } else { Err(invalid_record()) }
    }
}

fn validate_strings(values: Option<&[String]>) -> LinuxResult<()> {
    let Some(values) = values else {
        return Ok(());
    };
    if values.len() > MAX_DNS_VALUES
        || values.iter().any(|value| {
            value.is_empty() || value.len() > MAX_DNS_VALUE_BYTES || value.contains('\0')
        })
    {
        return Err(invalid_record());
    }
    Ok(())
}

const fn invalid_record() -> LinuxError {
    LinuxError::new(
        LinuxErrorKind::InvalidRecord,
        "the NetworkManager resolver ownership record is invalid",
    )
}

#[cfg(test)]
mod tests {
    use super::{NetworkManagerIpDns, NetworkManagerOwnership, ResolverManagerRecord};

    #[test]
    fn network_manager_record_is_bounded_and_requires_ip_state()
    -> Result<(), Box<dyn std::error::Error>> {
        let state = NetworkManagerIpDns::new(None, None, Some(false), None, None)?;
        assert!(
            NetworkManagerOwnership::new(
                String::new(),
                [1; 32],
                [1; 32],
                Some(state.clone()),
                None,
            )
            .is_err()
        );
        assert!(
            NetworkManagerOwnership::new("eth0".to_owned(), [1; 32], [1; 32], Some(state), None,)
                .is_ok()
        );
        assert!(
            ResolverManagerRecord::SystemdNetworkd("eth0".to_owned())
                .validate()
                .is_ok()
        );
        assert!(
            ResolverManagerRecord::SystemdNetworkd("unsafe interface".to_owned())
                .validate()
                .is_err()
        );
        Ok(())
    }
}
