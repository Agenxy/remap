use std::convert::Infallible;
use std::str::FromStr;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST, HeaderName};
use hyper::http::uri::{Authority, PathAndQuery};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use remap_core::{HostHeaderPolicy, HttpScheme, HttpUpstream, MappingTarget, RemapName};
use tokio::time::timeout;

use crate::gateway::SelfRejectingConnector;
use crate::{RuntimeIdentity, SnapshotStore};

const HEALTH_HOST: &[u8] = b"_health.remap.invalid";
const HEALTH_PATH_PREFIX: &str = "/.well-known/remap/health/";

pub(crate) type ProxyClient = Client<HttpsConnector<SelfRejectingConnector>, Incoming>;
type ProxyBody = BoxBody<Bytes, hyper::Error>;

#[derive(Debug, Clone, Copy)]
struct RouteError {
    status: StatusCode,
    code: &'static str,
    message: &'static str,
}

impl RouteError {
    const fn new(status: StatusCode, code: &'static str, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
        }
    }

    fn response(self) -> Response<ProxyBody> {
        gateway_error(self.status, self.code, self.message)
    }
}

pub(crate) async fn route(
    request: Request<Incoming>,
    client: ProxyClient,
    snapshots: SnapshotStore,
    upstream_timeout: Duration,
    identity: Option<RuntimeIdentity>,
) -> Result<Response<ProxyBody>, Infallible> {
    if let Some(response) = health_response(&request, identity.as_ref()) {
        return Ok(response);
    }
    let upstream = match select_upstream(&request, &snapshots) {
        Ok(upstream) => upstream,
        Err(error) => return Ok(error.response()),
    };
    let request = match upstream_request(request, &upstream) {
        Ok(request) => request,
        Err(error) => return Ok(error.response()),
    };
    let response = match timeout(upstream_timeout, client.request(request)).await {
        Ok(Ok(response)) => sanitize_response(response),
        Ok(Err(_error)) => gateway_error(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_UPSTREAM",
            "The selected service did not accept the routed request.",
        ),
        Err(_elapsed) => gateway_error(
            StatusCode::GATEWAY_TIMEOUT,
            "E_GATEWAY_TIMEOUT",
            "The selected service did not answer before the routing deadline.",
        ),
    };
    Ok(response)
}

fn health_response(
    request: &Request<Incoming>,
    identity: Option<&RuntimeIdentity>,
) -> Option<Response<ProxyBody>> {
    let identity = identity?;
    if request.method() != Method::GET || request.uri().query().is_some() {
        return None;
    }
    let mut hosts = request.headers().get_all(HOST).iter();
    if hosts.next()?.as_bytes() != HEALTH_HOST || hosts.next().is_some() {
        return None;
    }
    let nonce = request.uri().path().strip_prefix(HEALTH_PATH_PREFIX)?;
    if nonce.contains('/') {
        return None;
    }
    let proofs = identity.proofs(nonce)?;
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(proofs.http().to_owned()))
        .ok()
}

fn select_upstream(
    request: &Request<Incoming>,
    snapshots: &SnapshotStore,
) -> Result<HttpUpstream, RouteError> {
    let name = client_name(request.headers())?;
    let snapshot = snapshots.load();
    let mapping = snapshot.resolve(&name).ok_or_else(|| {
        RouteError::new(
            StatusCode::NOT_FOUND,
            "E_GATEWAY_UNMAPPED",
            "This name is not mapped to a routed HTTP service.",
        )
    })?;
    match mapping.target() {
        MappingTarget::Http(upstream) => Ok(upstream.clone()),
        MappingTarget::DnsAddress(_) | MappingTarget::DnsAlias(_) => Err(RouteError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "E_GATEWAY_DIRECT_TARGET",
            "This name is a direct DNS mapping, not a routed HTTP service.",
        )),
    }
}

fn client_name(headers: &HeaderMap) -> Result<RemapName, RouteError> {
    let mut hosts = headers.get_all(HOST).iter();
    let value = hosts
        .next()
        .ok_or_else(|| invalid_host("The request has no Host header."))?;
    if hosts.next().is_some() {
        return Err(invalid_host("The request has more than one Host header."));
    }
    let value = value
        .to_str()
        .map_err(|_| invalid_host("The request Host header is not valid ASCII."))?;
    let authority = Authority::from_str(value)
        .map_err(|_| invalid_host("The request Host header is malformed."))?;
    RemapName::parse(authority.host())
        .map_err(|_| invalid_host("The request Host is not a valid Remap name."))
}

const fn invalid_host(message: &'static str) -> RouteError {
    RouteError::new(StatusCode::BAD_REQUEST, "E_GATEWAY_HOST", message)
}

fn upstream_request(
    request: Request<Incoming>,
    upstream: &HttpUpstream,
) -> Result<Request<Incoming>, RouteError> {
    let authority = upstream_authority(upstream);
    let path = upstream_path(upstream.base_path(), request.uri())?;
    let scheme = match upstream.scheme() {
        HttpScheme::Http => "http",
        HttpScheme::Https => "https",
    };
    let uri = Uri::builder()
        .scheme(scheme)
        .authority(authority.as_str())
        .path_and_query(path)
        .build()
        .map_err(|_| {
            RouteError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "E_GATEWAY_ROUTE",
                "The validated route could not be represented as an HTTP request.",
            )
        })?;
    let (mut parts, body) = request.into_parts();
    parts.uri = uri;
    remove_hop_by_hop(&mut parts.headers);
    if upstream.host_header_policy() == HostHeaderPolicy::UseUpstream {
        let host = authority.parse().map_err(|_| {
            RouteError::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                "E_GATEWAY_ROUTE",
                "The validated upstream Host value could not be encoded.",
            )
        })?;
        parts.headers.insert(HOST, host);
    }
    Ok(Request::from_parts(parts, body))
}

fn upstream_authority(upstream: &HttpUpstream) -> String {
    upstream.port().map_or_else(
        || upstream.host().to_string(),
        |port| format!("{}:{port}", upstream.host()),
    )
}

fn upstream_path(base_path: &str, incoming: &Uri) -> Result<PathAndQuery, RouteError> {
    let path = if base_path == "/" {
        incoming.path().to_owned()
    } else {
        format!(
            "{}/{}",
            base_path.trim_end_matches('/'),
            incoming.path().trim_start_matches('/')
        )
    };
    let combined = incoming
        .query()
        .map_or(path.clone(), |query| format!("{path}?{query}"));
    PathAndQuery::from_str(&combined).map_err(|_| {
        RouteError::new(
            StatusCode::BAD_REQUEST,
            "E_GATEWAY_PATH",
            "The request path cannot be combined with this route.",
        )
    })
}

fn sanitize_response(response: Response<Incoming>) -> Response<ProxyBody> {
    let (mut parts, body) = response.into_parts();
    remove_hop_by_hop(&mut parts.headers);
    Response::from_parts(parts, body.boxed())
}

fn remove_hop_by_hop(headers: &mut HeaderMap) {
    let connection_tokens = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|value| HeaderName::from_str(value.trim()).ok())
        .collect::<Vec<_>>();
    for name in connection_tokens {
        headers.remove(name);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}

fn gateway_error(
    status: StatusCode,
    code: &'static str,
    message: &'static str,
) -> Response<ProxyBody> {
    let body = format!("Remap could not route this request.\n\n{code}: {message}\n");
    Response::builder()
        .status(status)
        .header(CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(full_body(body))
        .unwrap_or_else(|_error| Response::new(full_body("Remap routing error.\n")))
}

fn full_body(value: impl Into<Bytes>) -> ProxyBody {
    Full::new(value.into())
        .map_err(|never| match never {})
        .boxed()
}
