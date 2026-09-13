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
use remap_core::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, MappingTarget, PeerService, RemapName,
};
use tokio::time::timeout;

use crate::gateway::{PeerRouting, SelfRejectingConnector};
use crate::peer::PeerResolveError;
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
    routing: PeerRouting,
) -> Result<Response<ProxyBody>, Infallible> {
    if let Some(response) = health_response(&request, identity.as_ref()) {
        return Ok(response);
    }
    let (upstream, client) = match select_upstream(&request, &snapshots, &routing, client).await {
        Ok(selected) => selected,
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

/// The upstream for this request and the client to dial it with: the shared
/// client for an HTTP mapping, the client for the advertised key for a peer.
async fn select_upstream(
    request: &Request<Incoming>,
    snapshots: &SnapshotStore,
    routing: &PeerRouting,
    client: ProxyClient,
) -> Result<(HttpUpstream, ProxyClient), RouteError> {
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
        MappingTarget::Http(upstream) => Ok((upstream.clone(), client)),
        MappingTarget::Peer(service) => peer_upstream(service, routing).await,
        MappingTarget::DnsAddress(_) | MappingTarget::DnsAlias(_) => Err(RouteError::new(
            StatusCode::MISDIRECTED_REQUEST,
            "E_GATEWAY_DIRECT_TARGET",
            "This name is a direct DNS mapping, not a routed HTTP service.",
        )),
    }
}

/// Turns a peer mapping into the upstream to dial now and the client that
/// accepts exactly the key the peer advertised (ADR-0016). The answer's
/// addresses never reach a client; the error names the step.
async fn peer_upstream(
    service: &PeerService,
    routing: &PeerRouting,
) -> Result<(HttpUpstream, ProxyClient), RouteError> {
    let Some(resolver) = routing.resolver.as_ref() else {
        return Err(RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_PEER_NO_SUPGANG",
            "This name routes to a Supgang peer, and Supgang is not installed on this machine.",
        ));
    };
    let destination = resolver
        .resolve(service.peer(), service.service())
        .await
        .map_err(|error| {
            let (code, message) = match error {
                PeerResolveError::NotInstalled => ("E_GATEWAY_PEER_NO_SUPGANG", "Supgang is not installed on this machine."),
                PeerResolveError::NoAddress => ("E_GATEWAY_PEER_UNREACHABLE", "The peer has no address this machine can reach right now."),
                PeerResolveError::NoService => ("E_GATEWAY_PEER_NO_SERVICE", "The peer does not advertise the service this name routes to."),
                PeerResolveError::Refused(_) => ("E_GATEWAY_PEER_UNKNOWN", "Supgang does not know the peer this name routes to."),
                PeerResolveError::Schema(_) | PeerResolveError::Malformed(_) => ("E_GATEWAY_PEER_ANSWER", "Supgang's answer for the peer could not be read; update whichever of Remap or Supgang is older."),
                PeerResolveError::Unavailable(_) => ("E_GATEWAY_PEER_UNAVAILABLE", "Supgang did not answer for the peer in time."),
                PeerResolveError::Expired => (
                    "E_GATEWAY_PEER_EXPIRED",
                    "The peer's signed record has expired; nothing current says where it is.",
                ),
            };
            RouteError::new(StatusCode::BAD_GATEWAY, code, message)
        })?;
    let host = match destination.host {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    };
    let upstream = HttpUpstream::parse_with_policy(
        &format!("https://{host}:{}/", destination.port),
        service.host_header_policy(),
    )
    .map_err(|_| {
        RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_PEER_ANSWER",
            "The peer's advertised address could not be routed.",
        )
    })?;
    let client = routing
        .clients
        .client_for(destination.key_pin)
        .map_err(|_| {
            RouteError::new(
                StatusCode::BAD_GATEWAY,
                "E_GATEWAY_PEER_TLS",
                "A TLS client for the peer's advertised key could not be prepared.",
            )
        })?;
    Ok((upstream, client))
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
