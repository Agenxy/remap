// SPDX-License-Identifier: GPL-3.0-or-later
//! `/api/*`: one control command per request (ADR-0041's API table).

use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, LengthLimitError, Limited};
use hyper::body::{Body as _, Incoming};
use hyper::header::CONTENT_TYPE;
use hyper::{HeaderMap, Method, Request, Response};
use remap_protocol::{Command, CommandResult, Diagnostic, MAX_REVISION_WAIT_MS};
use serde_json::Value;

use crate::reply::{self, Body};
use crate::{State, mappings, query, status};

/// Largest accepted request body.
pub(crate) const MAX_BODY_BYTES: usize = 64 * 1024;

/// Longest a request body may take to arrive once its headers have.
const BODY_TIMEOUT: Duration = Duration::from_secs(10);

/// One API path.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum Endpoint {
    Status,
    Mappings,
    Mapping,
    Resolve,
    Wait,
    Validate,
    Preview,
    Apply,
}

impl Endpoint {
    fn parse(path: &str) -> Option<Self> {
        Some(match path {
            "/api/status" => Self::Status,
            "/api/mappings" => Self::Mappings,
            "/api/mapping" => Self::Mapping,
            "/api/resolve" => Self::Resolve,
            "/api/wait" => Self::Wait,
            "/api/validate" => Self::Validate,
            "/api/preview" => Self::Preview,
            "/api/apply" => Self::Apply,
            _ => return None,
        })
    }

    const fn is_write(self) -> bool {
        matches!(self, Self::Validate | Self::Preview | Self::Apply)
    }

    /// The `kind` of the control command a write body becomes.
    const fn command_kind(self) -> &'static str {
        match self {
            Self::Validate => "validate",
            Self::Preview => "preview",
            _ => "apply",
        }
    }

    /// The `kind` of the result the daemon answers with.
    const fn result_kind(self) -> &'static str {
        match self {
            Self::Status => "status",
            Self::Mappings => "list",
            Self::Mapping => "mapping",
            Self::Resolve => "resolution",
            Self::Wait => "revision",
            Self::Validate => "validation",
            Self::Preview => "preview",
            Self::Apply => "apply",
        }
    }
}

/// Answers one `/api/*` request whose `Host` and `Origin` already passed.
pub(crate) async fn handle(state: &State, request: Request<Incoming>) -> Response<Body> {
    // The token is checked before the path, so an unauthenticated caller
    // learns nothing about which paths exist.
    if !state.token.authorizes(request.headers()) {
        return reply::diagnostic(&status::unauthorized());
    }
    let Some(endpoint) = Endpoint::parse(request.uri().path()) else {
        return reply::diagnostic(&status::not_found());
    };
    let (expected, allow) = if endpoint.is_write() {
        (Method::POST, "POST")
    } else {
        (Method::GET, "GET")
    };
    if request.method() != expected {
        return reply::method_not_allowed(allow);
    }
    match answer(state, endpoint, request).await {
        Ok(response) => response,
        Err(diagnostic) => reply::diagnostic(&diagnostic),
    }
}

async fn answer(
    state: &State,
    endpoint: Endpoint,
    request: Request<Incoming>,
) -> Result<Response<Body>, Diagnostic> {
    if endpoint == Endpoint::Mappings {
        return Ok(reply::json(&mappings::read_all(&state.client).await?));
    }
    let command = if endpoint.is_write() {
        write_command(endpoint, request).await?
    } else {
        read_command(endpoint, request.uri().query())?
    };
    let result = state.client.execute(command).await?;
    Ok(reply::json(&result_value(endpoint, &result)?))
}

fn read_command(endpoint: Endpoint, query: Option<&str>) -> Result<Command, Diagnostic> {
    Ok(match endpoint {
        Endpoint::Mapping => Command::Get {
            pattern: query::single(query, "pattern")?,
        },
        Endpoint::Resolve => Command::Resolve {
            name: query::single(query, "name")?,
        },
        Endpoint::Wait => Command::WaitForRevision {
            after: query::single(query, "after")?.parse().map_err(|_| {
                Diagnostic::new(
                    "web-query-invalid",
                    "'after' must be a revision number",
                    Some("pass the revision the page last read".to_owned()),
                    false,
                )
            })?,
            timeout_ms: MAX_REVISION_WAIT_MS,
        },
        _ => Command::Status,
    })
}

/// Reads a bounded JSON object and makes it the endpoint's control command,
/// using the protocol's own serde form, unknown fields refused.
async fn write_command(
    endpoint: Endpoint,
    request: Request<Incoming>,
) -> Result<Command, Diagnostic> {
    if !is_json(request.headers()) {
        return Err(status::unsupported_media_type());
    }
    let body = read_body(request.into_body()).await?;
    let mut value = serde_json::from_slice::<Value>(&body)
        .map_err(|error| status::body_malformed(&error.to_string()))?;
    let Some(object) = value.as_object_mut() else {
        return Err(status::body_malformed("expected an object"));
    };
    object.insert("kind".to_owned(), Value::from(endpoint.command_kind()));
    serde_json::from_value(value).map_err(|error| status::body_invalid(&error.to_string()))
}

/// `application/json`, with or without parameters such as `charset`.
pub(crate) fn is_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let (Some(value), None) = (values.next(), values.next()) else {
        return false;
    };
    let essence = value.as_bytes().split(|&byte| byte == b';').next();
    essence.is_some_and(|essence| {
        essence
            .trim_ascii()
            .eq_ignore_ascii_case(b"application/json")
    })
}

async fn read_body(body: Incoming) -> Result<Bytes, Diagnostic> {
    let too_large = || status::body_too_large(MAX_BODY_BYTES);
    // A declared length over the limit is refused before reading anything.
    if body
        .size_hint()
        .exact()
        .is_some_and(|length| length > MAX_BODY_BYTES as u64)
    {
        return Err(too_large());
    }
    let collected =
        tokio::time::timeout(BODY_TIMEOUT, Limited::new(body, MAX_BODY_BYTES).collect())
            .await
            .map_err(|_| status::body_timeout())?;
    match collected {
        Ok(collected) => Ok(collected.to_bytes()),
        Err(error) if error.is::<LengthLimitError>() => Err(too_large()),
        Err(_) => Err(status::body_malformed("the body was cut off")),
    }
}

/// The result's `value`, after checking it is the kind the endpoint expects.
fn result_value(endpoint: Endpoint, result: &CommandResult) -> Result<Value, Diagnostic> {
    let encoded =
        serde_json::to_value(result).map_err(|error| status::internal(&error.to_string()))?;
    let Value::Object(mut fields) = encoded else {
        return Err(status::unexpected_result());
    };
    if fields.get("kind").and_then(Value::as_str) != Some(endpoint.result_kind()) {
        return Err(status::unexpected_result());
    }
    Ok(fields.remove("value").unwrap_or(Value::Null))
}

#[cfg(test)]
mod tests {
    use hyper::HeaderMap;
    use hyper::header::{CONTENT_TYPE, HeaderValue};
    use remap_protocol::{Command, CommandResult, MAX_REVISION_WAIT_MS, RevisionNotice};

    use super::{Endpoint, is_json, read_command, result_value};

    fn content_type(value: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_str(value)?);
        Ok(headers)
    }

    #[test]
    fn accepts_only_json_bodies() -> Result<(), Box<dyn std::error::Error>> {
        assert!(is_json(&content_type("application/json")?));
        assert!(is_json(&content_type("application/json; charset=utf-8")?));
        assert!(is_json(&content_type("Application/JSON;charset=UTF-8")?));
        assert!(!is_json(&HeaderMap::new()));
        for refused in [
            "text/plain",
            "application/x-www-form-urlencoded",
            "multipart/form-data; boundary=x",
            "application/json5",
            "application/jsonx; charset=utf-8",
            "text/json",
        ] {
            assert!(!is_json(&content_type(refused)?), "{refused}");
        }
        Ok(())
    }

    #[test]
    fn reads_become_their_commands() -> Result<(), remap_protocol::Diagnostic> {
        assert_eq!(
            read_command(Endpoint::Resolve, Some("name=api.test"))?,
            Command::Resolve {
                name: "api.test".to_owned()
            }
        );
        assert_eq!(
            read_command(Endpoint::Mapping, Some("pattern=%2A.lab"))?,
            Command::Get {
                pattern: "*.lab".to_owned()
            }
        );
        assert_eq!(
            read_command(Endpoint::Wait, Some("after=7"))?,
            Command::WaitForRevision {
                after: 7,
                timeout_ms: MAX_REVISION_WAIT_MS
            }
        );
        assert_eq!(read_command(Endpoint::Status, None)?, Command::Status);
        for bad in [
            "after=",
            "after=-1",
            "after=x",
            "after=18446744073709551616",
        ] {
            assert_eq!(
                read_command(Endpoint::Wait, Some(bad))
                    .err()
                    .map(|d| d.code),
                Some("web-query-invalid".to_owned()),
                "{bad}"
            );
        }
        Ok(())
    }

    #[test]
    fn a_result_of_another_kind_is_refused() {
        let notice = CommandResult::Revision(RevisionNotice {
            revision: 3,
            changed: true,
        });
        assert_eq!(
            result_value(Endpoint::Wait, &notice).ok(),
            Some(serde_json::json!({"revision": 3, "changed": true}))
        );
        assert_eq!(
            result_value(Endpoint::Status, &notice)
                .err()
                .map(|d| d.code),
            Some("web-unexpected-result".to_owned())
        );
        assert_eq!(
            result_value(Endpoint::Mapping, &CommandResult::Mapping(None)).ok(),
            Some(serde_json::Value::Null)
        );
    }

    #[test]
    fn every_path_has_one_method() {
        for (path, write) in [
            ("/api/status", false),
            ("/api/mappings", false),
            ("/api/mapping", false),
            ("/api/resolve", false),
            ("/api/wait", false),
            ("/api/validate", true),
            ("/api/preview", true),
            ("/api/apply", true),
        ] {
            assert_eq!(
                Endpoint::parse(path).map(Endpoint::is_write),
                Some(write),
                "{path}"
            );
        }
        assert_eq!(Endpoint::parse("/api/status/"), None);
        assert_eq!(Endpoint::parse("/api/"), None);
    }
}
