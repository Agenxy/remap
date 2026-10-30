// SPDX-License-Identifier: GPL-3.0-or-later
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::Ipv4Addr;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{
    LandingPath, LandingPathError, MappingTarget, NamePattern, RemapName, TemplateNameError,
    captured_labels, is_peer_machine_address,
};

/// One user-directed name mapping in an immutable registry revision.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Mapping {
    pattern: NamePattern,
    target: MappingTarget,
    enabled: bool,
    landing: Option<LandingPath>,
    peer_address: Option<Ipv4Addr>,
}

impl Mapping {
    /// Creates an enabled mapping.
    #[must_use]
    pub const fn new(pattern: NamePattern, target: MappingTarget) -> Self {
        Self {
            pattern,
            target,
            enabled: true,
            landing: None,
            peer_address: None,
        }
    }

    /// Returns the lookup pattern.
    #[must_use]
    pub const fn pattern(&self) -> &NamePattern {
        &self.pattern
    }

    /// Returns the mapping destination.
    #[must_use]
    pub const fn target(&self) -> &MappingTarget {
        &self.target
    }

    /// Returns the optional same-origin landing destination.
    #[must_use]
    pub const fn landing(&self) -> Option<&LandingPath> {
        self.landing.as_ref()
    }

    /// Attaches an explicitly validated landing path to this mapping.
    ///
    /// # Errors
    ///
    /// Refuses landing paths on DNS or non-root HTTP targets.
    pub fn with_landing(mut self, landing: Option<LandingPath>) -> Result<Self, LandingPathError> {
        if let Some(path) = &landing {
            path.validate_target(&self.target)?;
        }
        self.landing = landing;
        Ok(self)
    }

    /// Returns the target this mapping routes `name` to: the target itself, or
    /// for a template (ADR-0032) the target filled from the name's labels.
    ///
    /// # Errors
    ///
    /// Returns a [`TemplateNameError`] when `name` cannot fill the template.
    pub fn target_for(&self, name: &RemapName) -> Result<MappingTarget, TemplateNameError> {
        let MappingTarget::Peer(service) = &self.target else {
            return Ok(self.target.clone());
        };
        if service.template_arity().is_none() {
            return Ok(self.target.clone());
        }
        let captures = captured_labels(&self.pattern, name).unwrap_or_default();
        service.instantiate(&captures).map(MappingTarget::Peer)
    }

    /// Returns the loopback address the registry allocated to a peer-machine
    /// mapping (ADR-0033), kept while the mapping exists.
    #[must_use]
    pub const fn peer_address(&self) -> Option<Ipv4Addr> {
        self.peer_address
    }

    /// Returns a copy carrying the registry's allocated peer-machine address.
    #[must_use]
    pub const fn with_peer_address(mut self, address: Option<Ipv4Addr>) -> Self {
        self.peer_address = address;
        self
    }

    /// Returns whether the mapping participates in resolution.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Returns a copy with an explicit enabled state.
    #[must_use]
    pub const fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
}

/// A validation failure while constructing an immutable registry snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum SnapshotError {
    /// A moved mapping would resolve its destination to itself.
    MovedSelf(NamePattern),
    /// A moved mapping would resolve its destination to another moved mapping.
    MovedChain(NamePattern),
    /// Two records claim the same exact pattern in one revision.
    DuplicatePattern(NamePattern),
    /// A target template is attached to an exact name, which has no labels
    /// to fill it.
    TemplateNeedsWildcard(NamePattern),
    /// A peer-machine mapping has no allocated address, or another kind of
    /// mapping has one, or the address is outside the peer-machine range.
    PeerAddress(NamePattern),
    /// Two mappings hold the same peer-machine address.
    DuplicatePeerAddress(Ipv4Addr),
}

impl Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::MovedSelf(pattern) => write!(
                formatter,
                "moved mapping '{pattern}' cannot point at itself"
            ),
            Self::MovedChain(pattern) => write!(
                formatter,
                "moved mapping '{pattern}' cannot point at another moved mapping"
            ),
            Self::TemplateNeedsWildcard(pattern) => write!(
                formatter,
                "'{pattern}' is an exact name, so its target cannot read labels from it; use a wildcard such as '*.{pattern}'"
            ),
            Self::PeerAddress(pattern) => write!(
                formatter,
                "'{pattern}' does not hold exactly one peer-machine address inside 127.77.0.0/16"
            ),
            Self::DuplicatePeerAddress(address) => write!(
                formatter,
                "registry revision allocates peer-machine address {address} twice"
            ),
            Self::DuplicatePattern(pattern) => {
                write!(
                    formatter,
                    "registry revision contains duplicate pattern '{pattern}'"
                )
            }
        }
    }
}

impl Error for SnapshotError {}

/// An immutable, versioned view consumed by DNS and gateway readers.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RegistrySnapshot {
    revision: u64,
    mappings: Vec<Mapping>,
}

impl RegistrySnapshot {
    /// Returns an empty initial snapshot before authority state is published.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            revision: 0,
            mappings: Vec::new(),
        }
    }

    /// Validates and orders a complete registry revision.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::DuplicatePattern`] when two records claim the
    /// same canonical exact or wildcard pattern.
    pub fn new(revision: u64, mut mappings: Vec<Mapping>) -> Result<Self, SnapshotError> {
        let mut patterns = BTreeSet::new();
        let mut addresses = BTreeSet::new();
        for mapping in &mappings {
            if !patterns.insert(mapping.pattern().clone()) {
                return Err(SnapshotError::DuplicatePattern(mapping.pattern().clone()));
            }
            if let Some(error) = template_error(mapping) {
                return Err(error);
            }
            check_peer_address(mapping)?;
            if let Some(address) = mapping.peer_address()
                && !addresses.insert(address)
            {
                return Err(SnapshotError::DuplicatePeerAddress(address));
            }
        }

        mappings.sort_by(|left, right| {
            left.pattern()
                .resolution_rank()
                .cmp(&right.pattern().resolution_rank())
                .then_with(|| left.pattern().cmp(right.pattern()))
        });
        validate_moves(&mappings)?;
        Ok(Self { revision, mappings })
    }

    /// Returns the monotonic authoritative registry revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.revision
    }

    /// Returns the deterministically ordered mappings.
    #[must_use]
    pub fn mappings(&self) -> &[Mapping] {
        &self.mappings
    }

    /// Returns the allocated addresses of the enabled peer-machine mappings,
    /// the loopback aliases this revision needs reserved (ADR-0033). A
    /// disabled mapping keeps its allocation but is not in this set.
    #[must_use]
    pub fn peer_machine_addresses(&self) -> BTreeSet<Ipv4Addr> {
        self.mappings
            .iter()
            .filter(|mapping| mapping.is_enabled())
            .filter_map(Mapping::peer_address)
            .collect()
    }

    /// Resolves with exact-first, most-specific-wildcard precedence.
    /// Observes the native clock so expiring moved mappings participate correctly.
    #[must_use]
    pub fn resolve(&self, name: &RemapName) -> Option<&Mapping> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i128::try_from(duration.as_nanos()).ok());
        self.resolve_at(name, now)
    }

    /// Resolves with observed Unix nanoseconds for expiring moved mappings.
    /// An unavailable clock excludes expiring redirects rather than extending them.
    #[must_use]
    pub fn resolve_at(&self, name: &RemapName, unix_ns: Option<i128>) -> Option<&Mapping> {
        self.mappings.iter().find(|mapping| {
            mapping.is_enabled()
                && mapping.pattern().matches(name)
                && match mapping.target() {
                    MappingTarget::Moved(target) => target.active_at(unix_ns),
                    _ => true,
                }
        })
    }
}

/// Refuses a template on an exact pattern (ADR-0032).
fn template_error(mapping: &Mapping) -> Option<SnapshotError> {
    (matches!(mapping.pattern(), NamePattern::Exact(_))
        && mapping.target().template_arity().is_some())
    .then(|| SnapshotError::TemplateNeedsWildcard(mapping.pattern().clone()))
}

/// A peer-machine mapping holds exactly one address in the range, and no
/// other mapping holds one (ADR-0033).
fn check_peer_address(mapping: &Mapping) -> Result<(), SnapshotError> {
    let expected = matches!(mapping.target(), MappingTarget::PeerMachine(_));
    match mapping.peer_address() {
        Some(address) if expected && is_peer_machine_address(address) => Ok(()),
        None if !expected => Ok(()),
        _ => Err(SnapshotError::PeerAddress(mapping.pattern().clone())),
    }
}

fn validate_moves(mappings: &[Mapping]) -> Result<(), SnapshotError> {
    let mut exact = BTreeMap::new();
    let mut wildcards = BTreeMap::new();
    for mapping in mappings {
        match mapping.pattern() {
            NamePattern::Exact(name) => {
                exact.insert(name.as_str(), mapping);
            }
            NamePattern::Wildcard(name) => {
                wildcards.insert(name.as_str(), mapping);
            }
        }
    }
    for mapping in mappings {
        if let MappingTarget::Moved(target) = mapping.target() {
            for destination in [
                moved_destination(target.name(), &exact, &wildcards, false),
                moved_destination(target.name(), &exact, &wildcards, true),
            ]
            .into_iter()
            .flatten()
            {
                if std::ptr::eq(mapping, destination) {
                    return Err(SnapshotError::MovedSelf(mapping.pattern().clone()));
                }
                if matches!(destination.target(), MappingTarget::Moved(_)) {
                    return Err(SnapshotError::MovedChain(mapping.pattern().clone()));
                }
            }
        }
    }
    Ok(())
}

fn moved_destination<'a>(
    name: &RemapName,
    exact: &BTreeMap<&str, &'a Mapping>,
    wildcards: &BTreeMap<&str, &'a Mapping>,
    enabled_only: bool,
) -> Option<&'a Mapping> {
    if let Some(mapping) = exact
        .get(name.as_str())
        .filter(|mapping| !enabled_only || mapping.is_enabled())
    {
        return Some(*mapping);
    }
    let mut suffix = name.as_str();
    while let Some((_, rest)) = suffix.split_once('.') {
        if let Some(mapping) = wildcards
            .get(rest)
            .filter(|mapping| !enabled_only || mapping.is_enabled())
        {
            return Some(*mapping);
        }
        suffix = rest;
    }
    None
}
