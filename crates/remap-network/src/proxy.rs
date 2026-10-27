use std::convert::Infallible;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::header::{CACHE_CONTROL, CONNECTION, CONTENT_TYPE, HOST, HeaderName, LOCATION};
use hyper::http::uri::{Authority, PathAndQuery};
use hyper::upgrade::OnUpgrade;
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri};
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use remap_core::{
    HostHeaderPolicy, HttpScheme, HttpUpstream, LandingPath, MappingTarget, MovedTarget,
    PeerService, PeerTransport, RemapName,
};
use rustls::pki_types::ServerName;
use tokio::sync::OwnedSemaphorePermit;

use crate::failure::{ProxyBody, RouteError, full_body};
use crate::gateway::{PeerRouting, SelfRejectingConnector, pinned_tls_config};
use crate::peer::{PeerResolveError, PeerResolver};
use crate::stream_route::{Dialer, PinnedTls, SendError, StreamDial};
use crate::tunnel::{self, Tunnels};
use crate::{RuntimeIdentity, SnapshotStore};

const HEALTH_HOST: &[u8] = b"_health.remap.invalid";
const HEALTH_PATH_PREFIX: &str = "/.well-known/remap/health/";

pub(crate) type ProxyClient = Client<HttpsConnector<SelfRejectingConnector>, Incoming>;

/// The mapping a request's Host selected, copied out of the snapshot.
struct Matched {
    /// The mapping's canonical pattern, which every later error names.
    pattern: String,
    target: MappingTarget,
    landing: Option<LandingPath>,
}

/// A client's WebSocket switch, admitted and waiting for the upstream's answer.
struct PendingUpgrade {
    permit: OwnedSemaphorePermit,
    client: OnUpgrade,
}

/// Everything one gateway connection routes its requests with.
#[derive(Clone)]
pub(crate) struct Router {
    pub(crate) client: ProxyClient,
    pub(crate) snapshots: SnapshotStore,
    pub(crate) upstream_timeout: Duration,
    pub(crate) identity: Option<RuntimeIdentity>,
    pub(crate) routing: PeerRouting,
    pub(crate) tunnels: Tunnels,
}

pub(crate) async fn route(
    request: Request<Incoming>,
    router: Router,
) -> Result<Response<ProxyBody>, Infallible> {
    if let Some(response) = health_response(&request, router.identity.as_ref()) {
        return Ok(response);
    }
    let matched = match matched_mapping(&request, &router.snapshots) {
        Ok(matched) => matched,
        Err(error) => return Ok(error.response()),
    };
    let pattern = matched.pattern.clone();
    Ok(forward(request, matched, &router)
        .await
        .unwrap_or_else(|error| error.response_for(&pattern)))
}

/// Routes a request that matched a mapping. Every failure from here on is
/// reported with that mapping's pattern (ADR-0028).
async fn forward(
    mut request: Request<Incoming>,
    matched: Matched,
    router: &Router,
) -> Result<Response<ProxyBody>, RouteError> {
    let (upstream, dialer) = match matched.target {
        MappingTarget::Moved(target) => return Ok(moved_response(&request, &target)),
        MappingTarget::Http(upstream) => (upstream, Dialer::Pooled(router.client.clone())),
        MappingTarget::Peer(service) => match service.transport() {
            PeerTransport::PinnedTls => peer_upstream(&service, &router.routing).await?,
            PeerTransport::PlaintextInTunnel => {
                plaintext_peer_upstream(&service, &router.routing).await?
            }
        },
        MappingTarget::DnsAddress(_) | MappingTarget::DnsAlias(_) => {
            return Err(RouteError::new(
                StatusCode::MISDIRECTED_REQUEST,
                "E_GATEWAY_DIRECT_TARGET",
                "This name is a direct DNS mapping, not a routed HTTP service.",
            ));
        }
    };
    if let Some(response) = landing_response(&request, matched.landing.as_ref())? {
        return Ok(response);
    }
    let upgrade = admit_upgrade(&mut request, &router.tunnels)?;
    let request = upstream_request(request, &upstream, upgrade.is_some())?;
    match dialer.send(request, router.upstream_timeout).await {
        Ok(response) => match upgrade {
            Some(pending) => switch_response(response, pending, &router.tunnels),
            None => sanitize_response(response),
        },
        Err(SendError::Upstream(cause)) => Err(RouteError::upstream(cause)),
        Err(SendError::Timeout) => Err(RouteError::timeout()),
    }
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

/// The mapping this request's Host selects, or why there is none.
fn matched_mapping(
    request: &Request<Incoming>,
    snapshots: &SnapshotStore,
) -> Result<Matched, RouteError> {
    let name = client_name(request.headers())?;
    let snapshot = snapshots.load();
    let mapping = snapshot.resolve(&name).ok_or_else(|| {
        RouteError::new(
            StatusCode::NOT_FOUND,
            "E_GATEWAY_UNMAPPED",
            "This name is not mapped to a routed HTTP service.",
        )
    })?;
    Ok(Matched {
        pattern: mapping.pattern().to_string(),
        target: mapping.target().clone(),
        landing: mapping.landing().cloned(),
    })
}

fn moved_response(request: &Request<Incoming>, target: &MovedTarget) -> Response<ProxyBody> {
    let scheme = request
        .uri()
        .scheme_str()
        .filter(|scheme| matches!(*scheme, "http" | "https"))
        .unwrap_or("http");
    let path = request
        .uri()
        .path_and_query()
        .filter(|path| path.as_str() != "*")
        .map_or("/", PathAndQuery::as_str);
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(LOCATION, format!("{scheme}://{}{path}", target.name()))
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(String::new()))
        .unwrap_or_else(|_| {
            RouteError::new(
                StatusCode::BAD_REQUEST,
                "E_GATEWAY_MOVED",
                "The moved-name redirect could not be encoded.",
            )
            .response()
        })
}

fn landing_response(
    request: &Request<Incoming>,
    landing: Option<&LandingPath>,
) -> Result<Option<Response<ProxyBody>>, RouteError> {
    let Some(landing) = landing else {
        return Ok(None);
    };
    if request.uri().path() != "/"
        || !matches!(*request.method(), Method::GET | Method::HEAD)
        || tunnel::requests_websocket(request.headers())
    {
        return Ok(None);
    }
    Response::builder()
        .status(StatusCode::FOUND)
        .header(LOCATION, landing.location(request.uri().query()))
        .header(CACHE_CONTROL, "no-store")
        .body(full_body(String::new()))
        .map(Some)
        .map_err(|_| {
            RouteError::new(
                StatusCode::BAD_REQUEST,
                "E_GATEWAY_LANDING",
                "The landing redirect could not be encoded.",
            )
        })
}

/// Turns a peer mapping into the upstream to dial now and the client that
/// accepts exactly the key the peer advertised (ADR-0016). The answer's
/// addresses never reach a client; the error names the step.
async fn peer_upstream(
    service: &PeerService,
    routing: &PeerRouting,
) -> Result<(HttpUpstream, Dialer), RouteError> {
    let destination = peer_resolver(routing)?
        .resolve(service.peer(), service.service())
        .await
        .map_err(|error| resolve_error(&error))?;
    let host = match destination.host {
        std::net::IpAddr::V4(address) => address.to_string(),
        std::net::IpAddr::V6(address) => format!("[{address}]"),
    };
    let upstream = HttpUpstream::parse_with_policy(
        &format!("https://{host}:{}/", destination.port),
        service.host_header_policy(),
    )
    .map_err(|_| peer_answer_error("The peer's advertised address could not be routed."))?;
    let client = routing
        .clients
        .client_for(destination.key_pin)
        .map_err(|_| peer_tls_error())?;
    let Some(streams) = routing.streams.clone() else {
        return Ok((upstream, Dialer::Pooled(client)));
    };
    let config = pinned_tls_config(destination.key_pin).map_err(|_| peer_tls_error())?;
    let server_name = ServerName::IpAddress(destination.host.into());
    Ok((
        upstream,
        Dialer::Stream(StreamDial {
            streams,
            node: destination.node_id,
            service: service.service().to_owned(),
            tls: Some(PinnedTls {
                config: Arc::new(config),
                server_name,
            }),
            fallback: Some(client),
        }),
    ))
}

/// A plaintext-in-tunnel peer service: reached only through Supgang's stream,
/// addressed to the target's own loopback, and refused outright without one.
async fn plaintext_peer_upstream(
    service: &PeerService,
    routing: &PeerRouting,
) -> Result<(HttpUpstream, Dialer), RouteError> {
    let resolver = peer_resolver(routing)?;
    let Some(streams) = routing.streams.clone() else {
        return Err(RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_PEER_NO_TUNNEL",
            "This name routes to a plaintext service inside Supgang's tunnel, and no tunnel endpoint is available.",
        ));
    };
    let node = resolver
        .resolve_node(service.peer())
        .await
        .map_err(|error| resolve_error(&error))?;
    let upstream =
        HttpUpstream::parse_with_policy("http://localhost/", service.host_header_policy())
            .map_err(|_| peer_answer_error("The tunnelled service could not be addressed."))?;
    Ok((
        upstream,
        Dialer::Stream(StreamDial {
            streams,
            node,
            service: service.service().to_owned(),
            tls: None,
            fallback: None,
        }),
    ))
}

fn peer_resolver(routing: &PeerRouting) -> Result<&Arc<dyn PeerResolver>, RouteError> {
    routing.resolver.as_ref().ok_or_else(|| {
        RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_PEER_NO_SUPGANG",
            "This name routes to a Supgang peer, and Supgang is not installed on this machine.",
        )
    })
}

const fn peer_answer_error(message: &'static str) -> RouteError {
    RouteError::new(StatusCode::BAD_GATEWAY, "E_GATEWAY_PEER_ANSWER", message)
}

const fn peer_tls_error() -> RouteError {
    RouteError::new(
        StatusCode::BAD_GATEWAY,
        "E_GATEWAY_PEER_TLS",
        "A TLS client for the peer's advertised key could not be prepared.",
    )
}

fn resolve_error(error: &PeerResolveError) -> RouteError {
    let (code, message) = match error {
        PeerResolveError::NotInstalled => (
            "E_GATEWAY_PEER_NO_SUPGANG",
            "Supgang is not installed on this machine.",
        ),
        PeerResolveError::NoAddress => (
            "E_GATEWAY_PEER_UNREACHABLE",
            "The peer has no address this machine can reach right now.",
        ),
        PeerResolveError::NoService => (
            "E_GATEWAY_PEER_NO_SERVICE",
            "The peer does not advertise the service this name routes to.",
        ),
        PeerResolveError::Refused(_) => (
            "E_GATEWAY_PEER_UNKNOWN",
            "Supgang does not know the peer this name routes to.",
        ),
        PeerResolveError::Schema(_) | PeerResolveError::Malformed(_) => (
            "E_GATEWAY_PEER_ANSWER",
            "Supgang's answer for the peer could not be read; update whichever of Remap or Supgang is older.",
        ),
        PeerResolveError::Unavailable(_) => (
            "E_GATEWAY_PEER_UNAVAILABLE",
            "Supgang did not answer for the peer in time.",
        ),
        PeerResolveError::Expired => (
            "E_GATEWAY_PEER_EXPIRED",
            "The peer's signed record has expired; nothing current says where it is.",
        ),
    };
    RouteError::new(StatusCode::BAD_GATEWAY, code, message)
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

/// Takes a tunnel slot and the client's side of the switch when the request
/// asks for WebSocket; any other request passes untouched.
fn admit_upgrade(
    request: &mut Request<Incoming>,
    tunnels: &Tunnels,
) -> Result<Option<PendingUpgrade>, RouteError> {
    if !tunnel::requests_websocket(request.headers()) {
        return Ok(None);
    }
    let permit = tunnels.admit().ok_or_else(|| {
        RouteError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "E_GATEWAY_TUNNEL_LIMIT",
            "The gateway is carrying as many WebSocket connections as it allows.",
        )
    })?;
    Ok(Some(PendingUpgrade {
        permit,
        client: hyper::upgrade::on(request),
    }))
}

/// The upstream's answer to a WebSocket request. A refusal is relayed like
/// any response; a switch is relayed and the two connections joined.
fn switch_response(
    mut response: Response<Incoming>,
    pending: PendingUpgrade,
    tunnels: &Tunnels,
) -> Result<Response<ProxyBody>, RouteError> {
    if response.status() != StatusCode::SWITCHING_PROTOCOLS {
        return sanitize_response(response);
    }
    if !tunnel::upgrades_to_websocket(response.headers()) {
        return Err(RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_UPGRADE",
            "The selected service switched to a protocol other than the WebSocket requested.",
        ));
    }
    let upstream = hyper::upgrade::on(&mut response);
    tunnels.spawn(pending.permit, pending.client, upstream);
    let (mut parts, body) = response.into_parts();
    remove_hop_by_hop(&mut parts.headers);
    tunnel::mark_websocket(&mut parts.headers);
    Ok(Response::from_parts(parts, body.boxed()))
}

fn upstream_request(
    request: Request<Incoming>,
    upstream: &HttpUpstream,
    websocket: bool,
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
    if websocket {
        tunnel::mark_websocket(&mut parts.headers);
    }
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

fn sanitize_response(response: Response<Incoming>) -> Result<Response<ProxyBody>, RouteError> {
    let (mut parts, body) = response.into_parts();
    if parts.status == StatusCode::SWITCHING_PROTOCOLS {
        // Only `switch_response` relays a switch, and only one the client
        // asked for; any other would leave the client on a dead protocol.
        return Err(RouteError::new(
            StatusCode::BAD_GATEWAY,
            "E_GATEWAY_UPGRADE",
            "The selected service switched protocols without being asked to.",
        ));
    }
    remove_hop_by_hop(&mut parts.headers);
    Ok(Response::from_parts(parts, body.boxed()))
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
