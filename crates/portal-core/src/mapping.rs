use std::collections::BTreeSet;
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::{MappingTarget, NamePattern, PortalName};

/// One user-directed name mapping in an immutable registry revision.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Mapping {
    pattern: NamePattern,
    target: MappingTarget,
    enabled: bool,
}

impl Mapping {
    /// Creates an enabled mapping.
    #[must_use]
    pub const fn new(pattern: NamePattern, target: MappingTarget) -> Self {
        Self {
            pattern,
            target,
            enabled: true,
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
    /// Two records claim the same exact pattern in one revision.
    DuplicatePattern(NamePattern),
}

impl Display for SnapshotError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
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
    /// Validates and orders a complete registry revision.
    ///
    /// # Errors
    ///
    /// Returns [`SnapshotError::DuplicatePattern`] when two records claim the
    /// same canonical exact or wildcard pattern.
    pub fn new(revision: u64, mut mappings: Vec<Mapping>) -> Result<Self, SnapshotError> {
        let mut patterns = BTreeSet::new();
        for mapping in &mappings {
            if !patterns.insert(mapping.pattern().clone()) {
                return Err(SnapshotError::DuplicatePattern(mapping.pattern().clone()));
            }
        }

        mappings.sort_by(|left, right| {
            left.pattern()
                .resolution_rank()
                .cmp(&right.pattern().resolution_rank())
                .then_with(|| left.pattern().cmp(right.pattern()))
        });
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

    /// Resolves with exact-first, most-specific-wildcard precedence.
    #[must_use]
    pub fn resolve(&self, name: &PortalName) -> Option<&Mapping> {
        self.mappings
            .iter()
            .find(|mapping| mapping.is_enabled() && mapping.pattern().matches(name))
    }
}
