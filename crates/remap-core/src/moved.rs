// SPDX-License-Identifier: GPL-3.0-or-later
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use chrono::{DateTime, FixedOffset, SecondsFormat};

use crate::{NamePattern, RemapName};

/// An explicit name redirect with an optional absolute expiry.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct MovedTarget {
    name: RemapName,
    until: Option<DateTime<FixedOffset>>,
}

/// A moved name or its RFC3339 expiry was invalid.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct MovedTargetError(&'static str);

impl Display for MovedTargetError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for MovedTargetError {}

impl MovedTarget {
    /// Validates a new name and an optional RFC3339 expiry.
    ///
    /// # Errors
    ///
    /// Refuses invalid Remap names and malformed absolute timestamps.
    pub fn new(name: &str, until: Option<&str>) -> Result<Self, MovedTargetError> {
        let name = RemapName::parse(name)
            .map_err(|_| MovedTargetError("moved-to must be a valid Remap name"))?;
        let until = until
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(|_| MovedTargetError("until must be an RFC3339 timestamp with a timezone"))?;
        Ok(Self { name, until })
    }

    /// Parses the canonical persisted moved target.
    ///
    /// # Errors
    ///
    /// Refuses malformed moved targets, names and expiry timestamps.
    pub fn parse(input: &str) -> Result<Self, MovedTargetError> {
        let rest = input
            .strip_prefix("moved://")
            .ok_or(MovedTargetError("expected moved://NAME"))?;
        let (name, until) = rest
            .split_once("?until=")
            .map_or((rest, None), |(name, until)| (name, Some(until)));
        Self::new(name, until)
    }

    /// Returns the validated destination name.
    #[must_use]
    pub const fn name(&self) -> &RemapName {
        &self.name
    }

    /// Refuses an exact name redirecting to itself even while disabled.
    ///
    /// # Errors
    ///
    /// Returns a self-redirect diagnostic for the same canonical source name.
    pub fn validate_source(&self, pattern: &NamePattern) -> Result<(), MovedTargetError> {
        if matches!(pattern, NamePattern::Exact(name) if name == &self.name) {
            return Err(MovedTargetError("a moved name cannot point at itself"));
        }
        Ok(())
    }

    /// Returns whether the mapping still matches at the observed Unix nanoseconds.
    /// A missing clock observation cannot activate an expiring mapping.
    #[must_use]
    pub fn active_at(&self, unix_ns: Option<i128>) -> bool {
        self.until.as_ref().is_none_or(|until| {
            let deadline = i128::from(until.timestamp()) * 1_000_000_000
                + i128::from(until.timestamp_subsec_nanos());
            unix_ns.is_some_and(|now| now < deadline)
        })
    }
}

impl Display for MovedTarget {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "moved://{}", self.name)?;
        if let Some(until) = self.until {
            write!(
                formatter,
                "?until={}",
                until.to_utc().to_rfc3339_opts(SecondsFormat::AutoSi, true)
            )?;
        }
        Ok(())
    }
}
