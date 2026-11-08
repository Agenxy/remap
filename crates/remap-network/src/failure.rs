// SPDX-License-Identifier: GPL-3.0-or-later
//! What the gateway tells a client when it cannot route a request (ADR-0028).
//!
//! The body names the stable error code, the mapping pattern the request
//! matched, and, for a failed upstream exchange, a stable cause. It never
//! names the upstream address or port: those stay inside the gateway's
//! boundary, and the owner reads them from the registry.

use std::error::Error;
use std::io;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::header::CONTENT_TYPE;
use hyper::{Response, StatusCode};

pub(crate) type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// How far down an error's source chain the classifier looks.
const MAX_CHAIN_DEPTH: usize = 16;

/// Why an upstream exchange failed, as a stable token for the error body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpstreamCause {
    /// The target refused the connection: nothing is listening there.
    Refused,
    /// The target did not connect or answer before a deadline.
    Timeout,
    /// The TLS handshake with the target failed.
    Tls,
    /// The target closed or reset the connection before answering.
    Reset,
    /// The target's network cannot be reached from this machine.
    Unreachable,
    /// Any failure the categories above do not describe.
    Other,
}

impl UpstreamCause {
    /// The stable token written after `Cause:`.
    pub(crate) const fn token(self) -> &'static str {
        match self {
            Self::Refused => "refused",
            Self::Timeout => "timeout",
            Self::Tls => "tls",
            Self::Reset => "reset",
            Self::Unreachable => "unreachable",
            Self::Other => "other",
        }
    }

    /// The `E_GATEWAY_UPSTREAM` explanation for this cause.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            Self::Refused => "The mapping's target refused the connection.",
            Self::Timeout => "The mapping's target did not accept a connection in time.",
            Self::Tls => "The TLS handshake with the mapping's target failed.",
            Self::Reset => "The mapping's target closed the connection before answering.",
            Self::Unreachable => "The mapping's target is on a network this machine cannot reach.",
            Self::Other => "The selected service did not accept the routed request.",
        }
    }

    /// What the owner can do next, given the mapping pattern.
    fn next_step(self, pattern: &str) -> String {
        let action = match self {
            Self::Refused => "start the service",
            Self::Timeout => "check that the service is running and answering",
            Self::Tls => "check the service's certificate, and whether it speaks https or http",
            Self::Reset | Self::Other => "check the service's own log",
            Self::Unreachable => "check the network the target is on",
        };
        format!("{action}; `remap get {pattern}` shows the target.")
    }

    /// Classifies a client, connector, or TLS failure by walking its
    /// source chain. The first link that says what happened decides.
    pub(crate) fn classify(error: &(dyn Error + 'static)) -> Self {
        let mut current = Some(error);
        for _ in 0..MAX_CHAIN_DEPTH {
            let Some(link) = current else { break };
            if let Some(cause) = classify_link(link) {
                return cause;
            }
            // `io::Error::source` skips the error it wraps, so step into
            // that error directly: a TLS failure arrives as `InvalidData`
            // carrying the rustls error inside.
            current = match link.downcast_ref::<io::Error>() {
                Some(wrapper) => wrapper
                    .get_ref()
                    .map(|inner| inner as &(dyn Error + 'static)),
                None => link.source(),
            };
        }
        Self::Other
    }
}

fn classify_link(link: &(dyn Error + 'static)) -> Option<UpstreamCause> {
    if link.is::<rustls::Error>() {
        return Some(UpstreamCause::Tls);
    }
    if let Some(error) = link.downcast_ref::<io::Error>() {
        if let Some(inner) = error.get_ref()
            && inner.is::<rustls::Error>()
        {
            return Some(UpstreamCause::Tls);
        }
        return io_cause(error.kind());
    }
    if let Some(error) = link.downcast_ref::<hyper::Error>() {
        if error.is_timeout() {
            return Some(UpstreamCause::Timeout);
        }
        if error.is_incomplete_message() || error.is_canceled() {
            return Some(UpstreamCause::Reset);
        }
    }
    None
}

const fn io_cause(kind: io::ErrorKind) -> Option<UpstreamCause> {
    match kind {
        io::ErrorKind::ConnectionRefused => Some(UpstreamCause::Refused),
        io::ErrorKind::TimedOut => Some(UpstreamCause::Timeout),
        io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::UnexpectedEof => Some(UpstreamCause::Reset),
        io::ErrorKind::HostUnreachable
        | io::ErrorKind::NetworkUnreachable
        | io::ErrorKind::NetworkDown
        | io::ErrorKind::AddrNotAvailable => Some(UpstreamCause::Unreachable),
        _ => None,
    }
}

/// A routing failure: its status, stable code, explanation, and, for a
/// failed upstream exchange, why it failed.
#[derive(Debug, Clone, Copy)]
pub(crate) struct RouteError {
    pub(crate) status: StatusCode,
    pub(crate) code: &'static str,
    pub(crate) message: &'static str,
    pub(crate) cause: Option<UpstreamCause>,
}

impl RouteError {
    pub(crate) const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            cause: None,
        }
    }

    /// `502 E_GATEWAY_UPSTREAM`, explained by its cause.
    pub(crate) const fn upstream(cause: UpstreamCause) -> Self {
        Self {
            status: StatusCode::BAD_GATEWAY,
            code: "E_GATEWAY_UPSTREAM",
            message: cause.message(),
            cause: Some(cause),
        }
    }

    /// `504 E_GATEWAY_TIMEOUT`: the routing deadline passed with no answer.
    pub(crate) const fn timeout() -> Self {
        Self {
            status: StatusCode::GATEWAY_TIMEOUT,
            code: "E_GATEWAY_TIMEOUT",
            message: "The selected service did not answer before the routing deadline.",
            cause: Some(UpstreamCause::Timeout),
        }
    }

    /// The error before any mapping matched.
    pub(crate) fn response(self) -> Response<ProxyBody> {
        self.render(None)
    }

    /// The error for a request that matched `pattern`.
    pub(crate) fn response_for(self, pattern: &str) -> Response<ProxyBody> {
        self.render(Some(pattern))
    }

    fn render(self, pattern: Option<&str>) -> Response<ProxyBody> {
        let mut body = format!(
            "Remap could not route this request.\n\n{}: {}\n",
            self.code, self.message
        );
        if let Some(pattern) = pattern {
            body = format!("{body}\nMapping: {pattern}\n");
            if let Some(cause) = self.cause {
                body = format!(
                    "{body}Cause: {}\nNext: {}\n",
                    cause.token(),
                    cause.next_step(pattern)
                );
            }
        }
        Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, "text/plain; charset=utf-8")
            .header(hyper::header::CACHE_CONTROL, "no-store")
            .body(full_body(body))
            .unwrap_or_else(|_error| Response::new(full_body("Remap routing error.\n")))
    }
}

pub(crate) fn full_body(value: impl Into<Bytes>) -> ProxyBody {
    Full::new(value.into())
        .map_err(|never| match never {})
        .boxed()
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::UpstreamCause;

    #[test]
    fn io_kinds_map_to_stable_causes() {
        for (kind, cause) in [
            (io::ErrorKind::ConnectionRefused, "refused"),
            (io::ErrorKind::TimedOut, "timeout"),
            (io::ErrorKind::ConnectionReset, "reset"),
            (io::ErrorKind::UnexpectedEof, "reset"),
            (io::ErrorKind::HostUnreachable, "unreachable"),
            (io::ErrorKind::NetworkUnreachable, "unreachable"),
            (io::ErrorKind::PermissionDenied, "other"),
        ] {
            let error = io::Error::new(kind, "synthetic");
            assert_eq!(UpstreamCause::classify(&error).token(), cause, "{kind:?}");
        }
    }

    #[test]
    fn a_rustls_error_inside_an_io_error_is_tls() {
        let error = io::Error::new(
            io::ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert_eq!(UpstreamCause::classify(&error), UpstreamCause::Tls);
    }

    #[test]
    fn a_nested_refusal_is_found_through_its_wrappers() {
        #[derive(Debug)]
        struct Wrapper(io::Error);
        impl std::fmt::Display for Wrapper {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("wrapped")
            }
        }
        impl std::error::Error for Wrapper {
            fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
                Some(&self.0)
            }
        }
        let error = Wrapper(io::Error::from(io::ErrorKind::ConnectionRefused));
        assert_eq!(UpstreamCause::classify(&error), UpstreamCause::Refused);
    }
}
