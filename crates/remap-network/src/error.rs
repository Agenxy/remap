use std::error::Error;
use std::fmt::{self, Display, Formatter};
use std::io;

/// A sanitized network-runtime failure suitable for a local diagnostic.
#[derive(Debug)]
pub enum NetworkError {
    /// Runtime configuration violates a bounded or isolation invariant.
    Configuration(&'static str),
    /// A listener, upstream, or connection operation failed.
    Io {
        /// Stable operation category without private addresses.
        operation: &'static str,
        /// Native error retained for local debugging and retry classification.
        source: io::Error,
    },
    /// DNS encoding failed after validated local construction.
    Encoding,
    /// Every configured upstream failed or returned an unrelated response.
    UpstreamUnavailable,
}

impl NetworkError {
    pub(crate) fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl Display for NetworkError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => formatter.write_str(message),
            Self::Io { operation, .. } => write!(formatter, "DNS {operation} failed"),
            Self::Encoding => formatter.write_str("a local DNS response could not be encoded"),
            Self::UpstreamUnavailable => {
                formatter.write_str("no configured DNS upstream returned a related response")
            }
        }
    }
}

impl Error for NetworkError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            Self::Configuration(_) | Self::Encoding | Self::UpstreamUnavailable => None,
        }
    }
}
