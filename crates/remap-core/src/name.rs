use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::net::IpAddr;
use std::str::FromStr;

/// A validation failure for a Remap lookup name or pattern.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RemapNameError {
    /// The supplied name is empty.
    Empty,
    /// The canonical name exceeds the DNS wire limit.
    NameTooLong(usize),
    /// The name contains an empty label.
    EmptyLabel,
    /// A label exceeds 63 bytes.
    LabelTooLong(String),
    /// A label begins with a hyphen.
    LabelStartsWithHyphen(String),
    /// A label ends with a hyphen.
    LabelEndsWithHyphen(String),
    /// A label contains a character outside the initial ASCII hostname policy.
    InvalidCharacter {
        /// The rejected character.
        character: char,
        /// The complete label containing the character.
        label: String,
    },
    /// Address literals are destinations, not names clients resolve through DNS.
    AddressLiteral(String),
    /// A wildcard must identify a suffix.
    WildcardWithoutSuffix,
}

impl Display for RemapNameError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => formatter.write_str("a mapped name cannot be empty"),
            Self::NameTooLong(length) => write!(
                formatter,
                "the canonical name is {length} bytes; DNS names are limited to 253 bytes"
            ),
            Self::EmptyLabel => {
                formatter.write_str("a mapped name cannot contain an empty DNS label")
            }
            Self::LabelTooLong(label) => {
                write!(formatter, "the DNS label '{label}' exceeds 63 bytes")
            }
            Self::LabelStartsWithHyphen(label) => {
                write!(
                    formatter,
                    "the DNS label '{label}' cannot start with a hyphen"
                )
            }
            Self::LabelEndsWithHyphen(label) => {
                write!(
                    formatter,
                    "the DNS label '{label}' cannot end with a hyphen"
                )
            }
            Self::InvalidCharacter { character, label } => write!(
                formatter,
                "the character '{character}' is not valid in the DNS label '{label}'"
            ),
            Self::AddressLiteral(value) => write!(
                formatter,
                "'{value}' is an address literal, not a DNS name that Remap can override"
            ),
            Self::WildcardWithoutSuffix => {
                formatter.write_str("a wildcard must include a suffix, for example '*.lab'")
            }
        }
    }
}

impl Error for RemapNameError {}

/// A canonical ASCII hostname used as a Remap lookup key.
///
/// Single-label names and arbitrary suffixes are valid. A final DNS root dot is
/// accepted and removed. Unicode input is deferred until one explicit IDNA
/// conversion and display policy can be shared by DNS, TLS, URLs, storage, and
/// user interfaces.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RemapName(String);

impl RemapName {
    /// Parses and canonicalizes a Remap lookup name.
    ///
    /// # Errors
    ///
    /// Returns a precise [`RemapNameError`] when the input is empty, an
    /// address literal, too large for DNS, or violates the ASCII label policy.
    pub fn parse(input: &str) -> Result<Self, RemapNameError> {
        if input.is_empty() {
            return Err(RemapNameError::Empty);
        }

        let without_root_dot = input.strip_suffix('.').unwrap_or(input);
        if without_root_dot.is_empty() {
            return Err(RemapNameError::Empty);
        }

        if without_root_dot.parse::<IpAddr>().is_ok() {
            return Err(RemapNameError::AddressLiteral(input.to_owned()));
        }

        let canonical = without_root_dot.to_ascii_lowercase();
        if canonical.len() > 253 {
            return Err(RemapNameError::NameTooLong(canonical.len()));
        }

        for label in canonical.split('.') {
            Self::validate_label(label)?;
        }

        Ok(Self(canonical))
    }

    /// Returns the canonical hostname bytes as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Returns the number of DNS labels in the canonical name.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.0.split('.').count()
    }

    fn validate_label(label: &str) -> Result<(), RemapNameError> {
        if label.is_empty() {
            return Err(RemapNameError::EmptyLabel);
        }
        if label.len() > 63 {
            return Err(RemapNameError::LabelTooLong(label.to_owned()));
        }
        if label.starts_with('-') {
            return Err(RemapNameError::LabelStartsWithHyphen(label.to_owned()));
        }
        if label.ends_with('-') {
            return Err(RemapNameError::LabelEndsWithHyphen(label.to_owned()));
        }

        for character in label.chars() {
            if !character.is_ascii_alphanumeric() && character != '-' {
                return Err(RemapNameError::InvalidCharacter {
                    character,
                    label: label.to_owned(),
                });
            }
        }
        Ok(())
    }
}

impl Display for RemapName {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for RemapName {
    type Err = RemapNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}

/// An exact hostname or suffix wildcard used as a registry key.
#[derive(Debug, Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum NamePattern {
    /// Matches one canonical name exactly.
    Exact(RemapName),
    /// Matches descendants of a suffix, but not the suffix itself.
    Wildcard(RemapName),
}

impl NamePattern {
    /// Parses an exact name or a wildcard such as `*.lab`.
    ///
    /// # Errors
    ///
    /// Returns a [`RemapNameError`] when the exact name or wildcard suffix is
    /// missing or violates the canonical hostname policy.
    pub fn parse(input: &str) -> Result<Self, RemapNameError> {
        if input == "*" {
            return Err(RemapNameError::WildcardWithoutSuffix);
        }
        if let Some(suffix) = input.strip_prefix("*.") {
            if suffix.is_empty() {
                return Err(RemapNameError::WildcardWithoutSuffix);
            }
            return RemapName::parse(suffix).map(Self::Wildcard);
        }
        RemapName::parse(input).map(Self::Exact)
    }

    /// Returns whether this pattern owns the supplied canonical name.
    #[must_use]
    pub fn matches(&self, name: &RemapName) -> bool {
        match self {
            Self::Exact(candidate) => candidate == name,
            Self::Wildcard(suffix) => {
                name != suffix
                    && name.as_str().ends_with(suffix.as_str())
                    && name
                        .as_str()
                        .strip_suffix(suffix.as_str())
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }
        }
    }

    /// Returns wildcard suffix specificity, or `None` for an exact pattern.
    #[must_use]
    pub fn wildcard_specificity(&self) -> Option<usize> {
        match self {
            Self::Exact(_) => None,
            Self::Wildcard(suffix) => Some(suffix.label_count()),
        }
    }

    pub(crate) fn resolution_rank(&self) -> (u8, usize) {
        match self {
            Self::Exact(_) => (0, 0),
            Self::Wildcard(suffix) => (1, usize::MAX - suffix.label_count()),
        }
    }
}

impl Display for NamePattern {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exact(name) => Display::fmt(name, formatter),
            Self::Wildcard(suffix) => write!(formatter, "*.{suffix}"),
        }
    }
}

impl FromStr for NamePattern {
    type Err = RemapNameError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        Self::parse(input)
    }
}
