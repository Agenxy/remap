// SPDX-License-Identifier: GPL-3.0-or-later
//! Responses, every one of them carrying the same security headers.

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{self, HeaderName, HeaderValue};
use hyper::{Response, StatusCode};
use remap_protocol::Diagnostic;
use serde::Serialize;

use crate::status;

/// The body type of every response.
pub(crate) type Body = Full<Bytes>;

/// The exact Content Security Policy from ADR-0041.
pub(crate) const CONTENT_SECURITY_POLICY: &str = "default-src 'none'; script-src 'self'; \
style-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; \
form-action 'none'; frame-ancestors 'none'";

pub(crate) const JSON: &str = "application/json";

/// Headers set on every response, success or refusal, page or API.
pub(crate) const SECURITY_HEADERS: [(HeaderName, &str); 6] = [
    (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::REFERRER_POLICY, "no-referrer"),
    (header::CACHE_CONTROL, "no-store"),
    (
        HeaderName::from_static("cross-origin-opener-policy"),
        "same-origin",
    ),
    (
        HeaderName::from_static("cross-origin-resource-policy"),
        "same-origin",
    ),
];

/// A response with a body of one content type and the security headers.
pub(crate) fn bytes(status: StatusCode, content_type: &'static str, body: Bytes) -> Response<Body> {
    let mut response = Response::new(Full::new(body));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    for (name, value) in SECURITY_HEADERS {
        headers.insert(name, HeaderValue::from_static(value));
    }
    headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    response
}

/// A `200 OK` JSON response.
pub(crate) fn json<T: Serialize>(value: &T) -> Response<Body> {
    match serde_json::to_vec(value) {
        Ok(encoded) => bytes(StatusCode::OK, JSON, Bytes::from(encoded)),
        Err(error) => diagnostic(&status::internal(&error.to_string())),
    }
}

/// A diagnostic as JSON, with the status its code selects.
pub(crate) fn diagnostic(diagnostic: &Diagnostic) -> Response<Body> {
    let status = status::http_status(diagnostic);
    // A diagnostic is strings, a flag and a string map: it always encodes.
    let encoded = serde_json::to_vec(diagnostic).unwrap_or_default();
    let mut response = bytes(status, JSON, Bytes::from(encoded));
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    response
}

/// `405`, naming the one method the path takes.
pub(crate) fn method_not_allowed(allow: &'static str) -> Response<Body> {
    let mut response = diagnostic(&status::method_not_allowed());
    response
        .headers_mut()
        .insert(header::ALLOW, HeaderValue::from_static(allow));
    response
}

#[cfg(test)]
mod tests {
    use hyper::StatusCode;
    use hyper::header::{self, HeaderValue};
    use remap_protocol::Diagnostic;

    use super::{CONTENT_SECURITY_POLICY, SECURITY_HEADERS, diagnostic, json, method_not_allowed};

    #[test]
    fn the_policy_is_the_adr_policy() {
        assert_eq!(
            CONTENT_SECURITY_POLICY,
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
             connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        );
    }

    #[test]
    fn every_response_kind_carries_the_security_headers() {
        let responses = [
            json(&serde_json::json!({"ok": true})),
            diagnostic(&Diagnostic::daemon_unavailable()),
            diagnostic(&crate::status::unauthorized()),
            method_not_allowed("GET"),
        ];
        for response in responses {
            for (name, value) in SECURITY_HEADERS {
                assert_eq!(
                    response.headers().get(&name).map(HeaderValue::as_bytes),
                    Some(value.as_bytes())
                );
            }
            assert!(
                response
                    .headers()
                    .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
                    .is_none()
            );
        }
    }

    #[test]
    fn refusals_carry_their_status_and_extra_header() {
        let unauthorized = diagnostic(&crate::status::unauthorized());
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            unauthorized
                .headers()
                .get(header::WWW_AUTHENTICATE)
                .map(HeaderValue::as_bytes),
            Some(&b"Bearer"[..])
        );
        let refused = method_not_allowed("POST");
        assert_eq!(refused.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            refused
                .headers()
                .get(header::ALLOW)
                .map(HeaderValue::as_bytes),
            Some(&b"POST"[..])
        );
    }
}
