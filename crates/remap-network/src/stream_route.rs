//! Sending one routed request upstream: over the pooled client for an HTTP
//! mapping, or over a Supgang stream for a peer mapping (ADR-0026).
//!
//! A pinned peer service rides the stream first, with TLS to the advertised
//! key verified inside it, and falls back to the direct pinned connection
//! of ADR-0016 when no stream can be opened. A plaintext-in-tunnel service
//! rides the stream only: it is never sent in the clear on the network.

use std::sync::Arc;
use std::time::Duration;

use hyper::body::Incoming;
use hyper::client::conn::http1;
use hyper::http::uri::PathAndQuery;
use hyper::{Request, Response, Uri};
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use crate::proxy::ProxyClient;
use crate::supgang_stream::SupgangStreams;

/// How the request leaves the gateway.
pub(crate) enum Dialer {
    /// The shared or per-key pooled client.
    Pooled(ProxyClient),
    /// A Supgang stream to a peer's exposed service.
    Stream(StreamDial),
}

/// One peer service reached through Supgang's local stream endpoint.
pub(crate) struct StreamDial {
    pub(crate) streams: Arc<SupgangStreams>,
    pub(crate) node: [u8; 32],
    pub(crate) service: String,
    pub(crate) tls: Option<PinnedTls>,
    /// The direct pinned client to use when no stream opens; `None` for a
    /// plaintext-in-tunnel service, which never leaves the tunnel.
    pub(crate) fallback: Option<ProxyClient>,
}

/// TLS inside the stream, verified against exactly one advertised key.
pub(crate) struct PinnedTls {
    pub(crate) config: Arc<rustls::ClientConfig>,
    pub(crate) server_name: ServerName<'static>,
}

/// Why the request got no response.
pub(crate) enum SendError {
    /// The upstream, or every way to it, refused or failed.
    Upstream,
    /// Nothing answered before the routing deadline.
    Timeout,
}

impl Dialer {
    /// Sends `request` and waits at most `deadline` for the response head.
    pub(crate) async fn send(
        self,
        request: Request<Incoming>,
        deadline: Duration,
    ) -> Result<Response<Incoming>, SendError> {
        let sent = match self {
            Self::Pooled(client) => {
                timeout(deadline, async {
                    client
                        .request(request)
                        .await
                        .map_err(|_| SendError::Upstream)
                })
                .await
            }
            Self::Stream(dial) => timeout(deadline, dial.send(request)).await,
        };
        sent.unwrap_or(Err(SendError::Timeout))
    }
}

impl StreamDial {
    async fn send(self, request: Request<Incoming>) -> Result<Response<Incoming>, SendError> {
        let stream = match self.streams.open(&self.node, &self.service).await {
            Ok(stream) => stream,
            Err(_refused) => {
                let client = self.fallback.ok_or(SendError::Upstream)?;
                return client
                    .request(request)
                    .await
                    .map_err(|_| SendError::Upstream);
            }
        };
        let request = origin_form(request)?;
        match self.tls {
            Some(tls) => {
                let connector = TlsConnector::from(tls.config);
                let secured = connector
                    .connect(tls.server_name, stream)
                    .await
                    .map_err(|_| SendError::Upstream)?;
                exchange(secured, request).await
            }
            None => exchange(stream, request).await,
        }
    }
}

/// One HTTP/1.1 exchange on a fresh connection, kept open for an upgrade.
async fn exchange<T>(io: T, request: Request<Incoming>) -> Result<Response<Incoming>, SendError>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = http1::Builder::new()
        .handshake(TokioIo::new(io))
        .await
        .map_err(|_| SendError::Upstream)?;
    tokio::spawn(async move {
        let _closed = connection.with_upgrades().await;
    });
    sender
        .send_request(request)
        .await
        .map_err(|_| SendError::Upstream)
}

/// A stream is already addressed to the service, so the request target is
/// the path alone, as an origin server expects.
fn origin_form(request: Request<Incoming>) -> Result<Request<Incoming>, SendError> {
    let (mut parts, body) = request.into_parts();
    let path = parts
        .uri
        .path_and_query()
        .cloned()
        .unwrap_or_else(|| PathAndQuery::from_static("/"));
    parts.uri = Uri::builder()
        .path_and_query(path)
        .build()
        .map_err(|_| SendError::Upstream)?;
    Ok(Request::from_parts(parts, body))
}
