// SPDX-License-Identifier: GPL-3.0-or-later
//! The order every request is judged in: `Host`, then `Origin`, then
//! method and path. A request that fails a check learns only which check.

use std::convert::Infallible;

use bytes::Bytes;
use hyper::body::Incoming;
use hyper::header::{HOST, ORIGIN};
use hyper::{HeaderMap, Method, Request, Response, StatusCode};

use crate::reply::{self, Body};
use crate::{State, api, assets, status};

/// The hyper service function.
pub(crate) async fn handle(
    state: &State,
    request: Request<Incoming>,
) -> Result<Response<Body>, Infallible> {
    Ok(respond(state, request).await)
}

async fn respond(state: &State, request: Request<Incoming>) -> Response<Body> {
    if !host_allowed(state, &request) {
        return reply::diagnostic(&status::host_not_allowed());
    }
    if !origin_allowed(state, request.headers()) {
        return reply::diagnostic(&status::origin_not_allowed());
    }
    // A CORS preflight is never answered: no response carries CORS headers.
    if request.method() == Method::OPTIONS {
        return reply::method_not_allowed("GET, POST");
    }
    if request.uri().path().starts_with("/api/") {
        return api::handle(state, request).await;
    }
    let Some(asset) = assets::asset(request.uri().path()) else {
        return reply::diagnostic(&status::not_found());
    };
    if request.method() != Method::GET {
        return reply::method_not_allowed("GET");
    }
    reply::bytes(
        StatusCode::OK,
        asset.content_type,
        Bytes::from_static(asset.body),
    )
}

/// Exactly one `Host` header naming this listener, and no other authority
/// in an absolute-form request target.
fn host_allowed(state: &State, request: &Request<Incoming>) -> bool {
    let mut hosts = request.headers().get_all(HOST).iter();
    let (Some(host), None) = (hosts.next(), hosts.next()) else {
        return false;
    };
    let target_allowed = request
        .uri()
        .authority()
        .is_none_or(|authority| state.allowed.host(authority.as_str().as_bytes()));
    target_allowed && state.allowed.host(host.as_bytes())
}

/// No `Origin`, or exactly one naming this listener.
fn origin_allowed(state: &State, headers: &HeaderMap) -> bool {
    let mut origins = headers.get_all(ORIGIN).iter();
    match (origins.next(), origins.next()) {
        (None, _) => true,
        (Some(origin), None) => state.allowed.origin(origin.as_bytes()),
        (Some(_), Some(_)) => false,
    }
}
