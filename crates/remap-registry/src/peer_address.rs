// SPDX-License-Identifier: GPL-3.0-or-later
//! Stable loopback addresses for peer-machine mappings (ADR-0033). The
//! registry writer allocates one when the mapping is created, keeps it
//! across edits, disable and restarts, and frees it when the mapping is
//! removed or stops being a peer-machine mapping.

use std::collections::{BTreeMap, BTreeSet};
use std::net::Ipv4Addr;

use remap_core::{
    MAX_PEER_MACHINE_MAPPINGS, MappingTargetKind, is_peer_machine_address,
    lowest_free_peer_machine_address,
};
use remap_protocol::Diagnostic;

use crate::project::StoredMapping;

fn is_peer_machine(record: &StoredMapping) -> bool {
    record.target_kind == MappingTargetKind::PeerMachine.as_str()
}

/// Returns the address `after` holds: none for another kind, the address
/// `before` already held, or the lowest one no other mapping holds.
pub(crate) fn assign(
    after: &StoredMapping,
    before: Option<&StoredMapping>,
    mappings: &BTreeMap<String, StoredMapping>,
) -> Result<Option<Ipv4Addr>, Diagnostic> {
    if !is_peer_machine(after) {
        return Ok(None);
    }
    if let Some(address) = before.and_then(|record| record.peer_address) {
        return Ok(Some(address));
    }
    let used: BTreeSet<Ipv4Addr> = mappings
        .values()
        .filter(|record| record.pattern != after.pattern)
        .filter_map(|record| record.peer_address)
        .collect();
    lowest_free_peer_machine_address(&used)
        .map(Some)
        .ok_or_else(|| {
            Diagnostic::new(
                "E_PEER_ADDRESS_EXHAUSTED",
                "every peer-machine address in 127.77.0.0/16 is allocated",
                Some("remove a peer-machine mapping that is no longer needed".to_owned()),
                false,
            )
        })
}

/// Refuses a registry with more than [`MAX_PEER_MACHINE_MAPPINGS`]
/// peer-machine mappings, enabled or not.
pub(crate) fn ensure_capacity(
    mappings: &BTreeMap<String, StoredMapping>,
) -> Result<(), Diagnostic> {
    let count = mappings
        .values()
        .filter(|record| is_peer_machine(record))
        .count();
    if count <= MAX_PEER_MACHINE_MAPPINGS {
        return Ok(());
    }
    Err(Diagnostic::new(
        "E_PEER_MACHINE_CAPACITY",
        format!(
            "the registry cannot hold more than {MAX_PEER_MACHINE_MAPPINGS} peer-machine mappings"
        ),
        Some("remove a peer-machine mapping, or list more services on an existing one".to_owned()),
        false,
    )
    .with_context("limit", MAX_PEER_MACHINE_MAPPINGS.to_string()))
}

/// Reads a stored address column: present and inside the range for a
/// peer-machine mapping, absent for every other kind.
pub(crate) fn parse_stored(
    target_kind: &str,
    stored: Option<&str>,
) -> Result<Option<Ipv4Addr>, &'static str> {
    let expected = target_kind == MappingTargetKind::PeerMachine.as_str();
    match stored {
        None if !expected => Ok(None),
        Some(text) if expected => text
            .parse::<Ipv4Addr>()
            .ok()
            .filter(|address| is_peer_machine_address(*address))
            .filter(|address| address.to_string() == text)
            .map(Some)
            .ok_or("a peer-machine mapping holds an address outside 127.77.0.0/16"),
        None => Err("a peer-machine mapping has no allocated address"),
        Some(_) => Err("a mapping that is not a peer machine holds a peer-machine address"),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    use remap_protocol::HostPolicy;

    use super::assign;
    use crate::project::StoredMapping;

    fn machine(pattern: String, address: Option<Ipv4Addr>) -> StoredMapping {
        StoredMapping {
            landing: None,
            pattern,
            target: "supgang://a8a37e32?ssh=22".to_owned(),
            target_kind: "peer-machine".to_owned(),
            host_policy: HostPolicy::UseUpstream,
            enabled: true,
            updated_revision: 1,
            peer_address: address,
        }
    }

    // The mapping cap keeps a real registry far below the range, so the
    // range's own end is proved here with every address held.
    #[test]
    fn a_full_range_is_a_precise_refusal() {
        let held: BTreeMap<String, StoredMapping> = (1..u32::from(u16::MAX))
            .map(|host| {
                let pattern = format!("m{host}.test");
                let address = Ipv4Addr::from(0x7f4d_0000 | host);
                (pattern.clone(), machine(pattern, Some(address)))
            })
            .collect();
        let error = assign(&machine("new.test".to_owned(), None), None, &held)
            .err()
            .map(|diagnostic| diagnostic.code);
        assert_eq!(error.as_deref(), Some("E_PEER_ADDRESS_EXHAUSTED"));
    }
}
