// SPDX-License-Identifier: GPL-3.0-or-later
use std::error::Error;
use std::fmt::{self, Display, Formatter};

use crate::MappingTarget;

/// Maximum encoded size of a same-origin landing path.
pub const MAX_LANDING_BYTES: usize = 2_048;

/// A bounded same-origin redirect destination that cannot resolve to the root.
#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct LandingPath(String);

/// A landing path or its combination with a mapping target is invalid.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum LandingPathError {
    /// The path is unsafe, malformed, too large, or would redirect to itself.
    InvalidPath,
    /// A landing path requires an origin-root HTTP upstream.
    NonRootUpstream,
    /// DNS mappings do not pass through the HTTP gateway.
    DnsTarget,
}

impl Display for LandingPathError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidPath => "landing must be a same-origin path of at most 2048 bytes, starting with a single '/', not resolving to '/', and containing no scheme, '..', fragment, backslash, whitespace or control characters; percent-encode non-ASCII text",
            Self::NonRootUpstream => "landing requires an HTTP target with base path '/'; move the page path to --landing",
            Self::DnsTarget => "landing requires an HTTP or Supgang service target",
        })
    }
}

impl Error for LandingPathError {}

impl LandingPath {
    /// Parses a same-origin path, preserving its encoded bytes and optional query.
    ///
    /// # Errors
    ///
    /// Rejects unsafe raw or percent-encoded paths and root redirect loops.
    pub fn parse(input: &str) -> Result<Self, LandingPathError> {
        if input.len() > MAX_LANDING_BYTES
            || !input.is_ascii()
            || input
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
        {
            return Err(LandingPathError::InvalidPath);
        }
        let decoded = decode_path(input)?;
        let path = decoded.split('?').next().unwrap_or_default();
        if !decoded.starts_with('/')
            || decoded.starts_with("//")
            || decoded.contains("..")
            || decoded.contains("://")
            || decoded.contains(['\\', '#'])
            || decoded.chars().any(char::is_control)
            || path.split('/').all(|part| part.is_empty() || part == ".")
        {
            return Err(LandingPathError::InvalidPath);
        }
        Ok(Self(input.to_owned()))
    }

    /// Returns the exact encoded destination supplied by the owner.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks that a landing path is meaningful for the selected target.
    ///
    /// # Errors
    ///
    /// Refuses DNS targets and HTTP upstreams with a non-root base path.
    pub fn validate_target(&self, target: &MappingTarget) -> Result<(), LandingPathError> {
        match target {
            MappingTarget::Http(upstream) if upstream.base_path() != "/" => {
                Err(LandingPathError::NonRootUpstream)
            }
            MappingTarget::Http(_) | MappingTarget::Peer(_) => Ok(()),
            MappingTarget::Moved(_) | MappingTarget::DnsAddress(_) | MappingTarget::DnsAlias(_) => {
                Err(LandingPathError::DnsTarget)
            }
        }
    }

    /// Carries a root request's encoded query into the landing destination.
    #[must_use]
    pub fn location(&self, query: Option<&str>) -> String {
        query.map_or_else(
            || self.0.clone(),
            |query| {
                let separator = if self.0.contains('?') { '&' } else { '?' };
                format!("{}{separator}{query}", self.0)
            },
        )
    }
}

fn decode_path(input: &str) -> Result<String, LandingPathError> {
    let mut bytes = input.bytes();
    let mut decoded = Vec::with_capacity(input.len());
    while let Some(byte) = bytes.next() {
        if byte == b'%' {
            let high = bytes.next().and_then(|byte| char::from(byte).to_digit(16));
            let low = bytes.next().and_then(|byte| char::from(byte).to_digit(16));
            let (Some(high), Some(low)) = (high, low) else {
                return Err(LandingPathError::InvalidPath);
            };
            decoded.push(u8::try_from(high * 16 + low).map_err(|_| LandingPathError::InvalidPath)?);
        } else {
            decoded.push(byte);
        }
    }
    String::from_utf8(decoded).map_err(|_| LandingPathError::InvalidPath)
}
