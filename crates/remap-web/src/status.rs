// SPDX-License-Identifier: GPL-3.0-or-later
//! HTTP statuses for diagnostics, and the web interface's own diagnostics.
//!
//! Daemon diagnostics pass through unchanged; only the status line is
//! chosen here, by the diagnostic's stable code.

use std::io;

use hyper::StatusCode;
use remap_protocol::Diagnostic;

/// Codes with a fixed status. Anything else is 503 when the daemon says a
/// retry may succeed (unreachable, shutting down, busy or in maintenance)
/// and 500 otherwise.
const STATUSES: &[(&str, StatusCode)] = &[
    // The registry moved, or an operation identifier was reused for a
    // different request: re-read and decide again.
    ("E_REVISION_CONFLICT", StatusCode::CONFLICT),
    ("E_IDEMPOTENCY_CONFLICT", StatusCode::CONFLICT),
    // Well formed, but the daemon refused what the request says.
    ("E_INVALID_PATTERN", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_INVALID_TARGET", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_INVALID_NAME", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_INVALID_LANDING", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_TARGET_TOO_LARGE", StatusCode::UNPROCESSABLE_ENTITY),
    (
        "E_TEMPLATE_NEEDS_WILDCARD",
        StatusCode::UNPROCESSABLE_ENTITY,
    ),
    ("E_MOVED_CHAIN", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_EMPTY_CHANGE_SET", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_TOO_MANY_CHANGES", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_NO_MAPPING", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_MAPPING_CAPACITY", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_PEER_MACHINE_CAPACITY", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_PEER_ADDRESS_EXHAUSTED", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_OPERATION_ID", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_PAGE_LIMIT", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_REVISION_WAIT", StatusCode::UNPROCESSABLE_ENTITY),
    ("E_USAGE", StatusCode::BAD_REQUEST),
    // The daemon answered something this client does not understand.
    ("E_CONTROL_PROTOCOL", StatusCode::BAD_GATEWAY),
    ("E_CONTROL_VERSION", StatusCode::BAD_GATEWAY),
    ("E_CONTROL_COMMAND", StatusCode::BAD_GATEWAY),
    ("E_DAEMON_TIMEOUT", StatusCode::GATEWAY_TIMEOUT),
    // The web interface's own refusals.
    ("web-unauthorized", StatusCode::UNAUTHORIZED),
    ("web-origin-not-allowed", StatusCode::FORBIDDEN),
    ("web-not-found", StatusCode::NOT_FOUND),
    ("web-method-not-allowed", StatusCode::METHOD_NOT_ALLOWED),
    ("web-body-timeout", StatusCode::REQUEST_TIMEOUT),
    ("web-body-too-large", StatusCode::PAYLOAD_TOO_LARGE),
    (
        "web-unsupported-media-type",
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    ),
    ("web-host-not-allowed", StatusCode::MISDIRECTED_REQUEST),
    ("web-query-invalid", StatusCode::BAD_REQUEST),
    ("web-body-malformed", StatusCode::BAD_REQUEST),
    ("web-body-invalid", StatusCode::UNPROCESSABLE_ENTITY),
    ("web-unexpected-result", StatusCode::BAD_GATEWAY),
];

/// The HTTP status that carries one diagnostic.
pub(crate) fn http_status(diagnostic: &Diagnostic) -> StatusCode {
    STATUSES
        .iter()
        .find(|(code, _)| *code == diagnostic.code)
        .map_or_else(
            || {
                if diagnostic.retryable {
                    StatusCode::SERVICE_UNAVAILABLE
                } else {
                    StatusCode::INTERNAL_SERVER_ERROR
                }
            },
            |(_, status)| *status,
        )
}

/// The diagnostic for a listener that could not bind.
pub(crate) fn bind_failure(port: u16, error: &io::Error) -> Diagnostic {
    let diagnostic = match error.kind() {
        io::ErrorKind::AddrInUse => Diagnostic::new(
            "web-port-in-use",
            format!("port {port} on 127.0.0.1 is already in use"),
            Some("choose another --port, or leave --port out to use a free one".to_owned()),
            false,
        ),
        io::ErrorKind::PermissionDenied => Diagnostic::new(
            "web-port-denied",
            format!("this account may not listen on port {port}"),
            Some("choose a --port from 1024 through 65535".to_owned()),
            false,
        ),
        _ => Diagnostic::new(
            "web-bind-failed",
            format!("could not listen on 127.0.0.1:{port}"),
            Some("check that the loopback interface is up, then retry".to_owned()),
            true,
        ),
    };
    diagnostic.with_context("port", port.to_string())
}

pub(crate) fn unauthorized() -> Diagnostic {
    Diagnostic::new(
        "web-unauthorized",
        "this request needs the capability token",
        Some("open the exact URL that remap web printed".to_owned()),
        false,
    )
}

pub(crate) fn host_not_allowed() -> Diagnostic {
    Diagnostic::new(
        "web-host-not-allowed",
        "this server answers only to 127.0.0.1, localhost or its --name",
        Some("open the exact URL that remap web printed, or restart it with --name".to_owned()),
        false,
    )
}

pub(crate) fn origin_not_allowed() -> Diagnostic {
    Diagnostic::new(
        "web-origin-not-allowed",
        "requests from another site are refused",
        Some("use the page that remap web serves".to_owned()),
        false,
    )
}

pub(crate) fn not_found() -> Diagnostic {
    Diagnostic::new(
        "web-not-found",
        "there is nothing at this path",
        Some("open the exact URL that remap web printed".to_owned()),
        false,
    )
}

pub(crate) fn method_not_allowed() -> Diagnostic {
    Diagnostic::new(
        "web-method-not-allowed",
        "this path does not accept that method",
        Some("reads are GET and changes are POST".to_owned()),
        false,
    )
}

pub(crate) fn unsupported_media_type() -> Diagnostic {
    Diagnostic::new(
        "web-unsupported-media-type",
        "changes must be sent as application/json",
        Some("send the body with Content-Type: application/json".to_owned()),
        false,
    )
}

pub(crate) fn body_too_large(limit: usize) -> Diagnostic {
    Diagnostic::new(
        "web-body-too-large",
        format!("the request body is larger than {limit} bytes"),
        Some("send fewer changes in one request".to_owned()),
        false,
    )
}

pub(crate) fn body_timeout() -> Diagnostic {
    Diagnostic::new(
        "web-body-timeout",
        "the request body did not arrive in time",
        Some("retry the request".to_owned()),
        true,
    )
}

pub(crate) fn body_malformed(detail: &str) -> Diagnostic {
    Diagnostic::new(
        "web-body-malformed",
        format!("the request body is not a JSON object: {detail}"),
        Some("send one JSON object, as the page does".to_owned()),
        false,
    )
}

pub(crate) fn body_invalid(detail: &str) -> Diagnostic {
    Diagnostic::new(
        "web-body-invalid",
        format!("the request body does not match the command: {detail}"),
        Some("send the fields the control command takes, as the page does".to_owned()),
        false,
    )
}

pub(crate) fn unexpected_result() -> Diagnostic {
    Diagnostic::new(
        "web-unexpected-result",
        "the daemon answered with a different kind of result",
        Some("update the Remap client and daemon together, then retry".to_owned()),
        false,
    )
}

pub(crate) fn internal(detail: &str) -> Diagnostic {
    Diagnostic::new(
        "web-internal",
        format!("the web interface could not encode its answer: {detail}"),
        Some("retry; if it keeps failing, report it with remap doctor's output".to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use std::io;

    use hyper::StatusCode;
    use remap_protocol::Diagnostic;

    use super::{bind_failure, http_status};

    fn status(code: &str, retryable: bool) -> StatusCode {
        http_status(&Diagnostic::new(code, "message", None, retryable))
    }

    #[test]
    fn maps_daemon_codes_to_statuses() {
        assert_eq!(status("E_REVISION_CONFLICT", false), StatusCode::CONFLICT);
        assert_eq!(
            status("E_IDEMPOTENCY_CONFLICT", false),
            StatusCode::CONFLICT
        );
        assert_eq!(
            status("E_INVALID_PATTERN", false),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status("E_INVALID_TARGET", false),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status("E_NO_MAPPING", false),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(
            status("E_TOO_MANY_CHANGES", false),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(status("E_USAGE", false), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("E_DAEMON_UNAVAILABLE", true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status("E_DAEMON_WRITER_UNAVAILABLE", true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status("E_REGISTRY_CHECKPOINT", true),
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            status("E_DAEMON_TIMEOUT", true),
            StatusCode::GATEWAY_TIMEOUT
        );
        assert_eq!(status("E_CONTROL_PROTOCOL", false), StatusCode::BAD_GATEWAY);
        assert_eq!(
            status("E_REGISTRY_CORRUPT", false),
            StatusCode::INTERNAL_SERVER_ERROR
        );
        assert_eq!(
            http_status(&Diagnostic::daemon_unavailable()),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn maps_web_codes_to_statuses() {
        assert_eq!(status("web-unauthorized", false), StatusCode::UNAUTHORIZED);
        assert_eq!(
            status("web-origin-not-allowed", false),
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            status("web-host-not-allowed", false),
            StatusCode::MISDIRECTED_REQUEST
        );
        assert_eq!(status("web-not-found", false), StatusCode::NOT_FOUND);
        assert_eq!(
            status("web-method-not-allowed", false),
            StatusCode::METHOD_NOT_ALLOWED
        );
        assert_eq!(
            status("web-unsupported-media-type", false),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(
            status("web-body-too-large", false),
            StatusCode::PAYLOAD_TOO_LARGE
        );
        assert_eq!(
            status("web-body-timeout", true),
            StatusCode::REQUEST_TIMEOUT
        );
        assert_eq!(status("web-body-malformed", false), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("web-body-invalid", false),
            StatusCode::UNPROCESSABLE_ENTITY
        );
        assert_eq!(status("web-query-invalid", false), StatusCode::BAD_REQUEST);
        assert_eq!(
            status("web-unexpected-result", false),
            StatusCode::BAD_GATEWAY
        );
        assert_eq!(
            status("web-mappings-unstable", true),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[test]
    fn names_bind_failures_with_hints() {
        for (kind, code) in [
            (io::ErrorKind::AddrInUse, "web-port-in-use"),
            (io::ErrorKind::PermissionDenied, "web-port-denied"),
            (io::ErrorKind::AddrNotAvailable, "web-bind-failed"),
        ] {
            let diagnostic = bind_failure(7341, &io::Error::from(kind));
            assert_eq!(diagnostic.code, code);
            assert!(diagnostic.hint.is_some());
            assert_eq!(
                diagnostic.context.get("port").map(String::as_str),
                Some("7341")
            );
        }
    }
}
