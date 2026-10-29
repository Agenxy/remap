// SPDX-License-Identifier: GPL-3.0-or-later
//! Peer mappings carried through Supgang's local stream endpoint (ADR-0026),
//! against a stand-in endpoint that speaks version 1 and pipes each stream
//! to a real upstream: plaintext only when the owner chose it, pinned TLS
//! verified inside the stream, WebSocket switches carried, and refusals named.

use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{Empty, Full};
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HOST, HeaderValue, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::{
    GatewayRuntime, GatewayRuntimeConfig, PeerResolveError, PeerResolver, ResolvedPeerService,
    SnapshotStore, SupgangStreams,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

type TestResult = Result<(), Box<dyn Error>>;
type Seen = Arc<Mutex<Vec<(String, Option<String>)>>>;

const NODE: [u8; 32] = [0x42; 32];

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = match name {
        "ca" => include_str!("fixtures/ca.der.hex"),
        "leaf" => include_str!("fixtures/leaf.der.hex"),
        "leaf-key" => include_str!("fixtures/leaf.key.pkcs8.hex"),
        "pin" => include_str!("fixtures/ca.pin.hex"),
        _ => return Err("unknown fixture".into()),
    }
    .trim();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn pin() -> Result<[u8; 32], Box<dyn Error>> {
    fixture("pin")?
        .try_into()
        .map_err(|_| "the pin fixture is not 32 bytes".into())
}

/// Stands in for Supgang: the one peer `solis`, at node `NODE`, advertising
/// `pinned` under `key`, and resolvable to a node for a plaintext service.
#[derive(Debug)]
struct Solis {
    key: [u8; 32],
}

impl PeerResolver for Solis {
    fn resolve<'a>(
        &'a self,
        _peer: &'a str,
        service: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ResolvedPeerService, PeerResolveError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            if service != "pinned" {
                return Err(PeerResolveError::NoService);
            }
            Ok(ResolvedPeerService {
                node_id: NODE,
                host: IpAddr::V4(Ipv4Addr::LOCALHOST),
                // Never dialled: the stream carries the bytes.
                port: 9,
                key_pin: self.key,
                expires_at: u64::MAX,
            })
        })
    }

    fn resolve_node<'a>(
        &'a self,
        _peer: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<[u8; 32], PeerResolveError>> + Send + 'a>,
    > {
        Box::pin(async { Ok(NODE) })
    }
}

/// A stand-in for Supgang's version-1 endpoint: for each request it checks
/// the frame, then either refuses or pipes the socket to the upstream that
/// `services` names.
fn endpoint(
    socket: &Path,
    services: Vec<(&'static str, SocketAddr)>,
) -> Result<(), Box<dyn Error>> {
    let listener = UnixListener::bind(socket)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let services = services.clone();
            tokio::spawn(async move {
                let mut frame = [0_u8; 61];
                if stream.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let valid = frame[..4] == 57_u32.to_be_bytes()
                    && &frame[4..12] == b"SUPGIPC1"
                    && frame[12] == 0x07
                    && frame[13..45] == NODE;
                let name: String = frame[45..]
                    .iter()
                    .take_while(|byte| **byte != 0)
                    .map(|byte| char::from(*byte))
                    .collect();
                let target = services
                    .iter()
                    .find(|(service, _)| *service == name)
                    .map(|(_, address)| *address);
                let (Some(target), true) = (target, valid) else {
                    let _sent = reply(&mut stream, br#"{"response":"error","message":"no"}"#).await;
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    return;
                };
                if reply(&mut stream, br#"{"response":"connected"}"#)
                    .await
                    .is_ok()
                {
                    let _copied = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                }
            });
        }
    });
    Ok(())
}

async fn reply(stream: &mut tokio::net::UnixStream, body: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(body.len()).unwrap_or(0).to_be_bytes();
    stream.write_all(&length).await?;
    stream.write_all(body).await
}

/// A plain HTTP upstream recording each request target and Host, switching
/// to an echo for a WebSocket request.
async fn plain_upstream(seen: Seen) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            let service = service_fn(move |mut request: Request<Incoming>| {
                let host = request
                    .headers()
                    .get(HOST)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned);
                if let Ok(mut seen) = seen.lock() {
                    seen.push((request.uri().to_string(), host));
                }
                let switching = request.headers().contains_key(UPGRADE);
                if switching {
                    let pending = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        let Ok(upgraded) = pending.await else { return };
                        let (mut reader, mut writer) = tokio::io::split(TokioIo::new(upgraded));
                        let _copied = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
                async move {
                    if switching {
                        let mut response = Response::new(Full::new(Bytes::new()));
                        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        response
                            .headers_mut()
                            .insert(UPGRADE, HeaderValue::from_static("websocket"));
                        response
                            .headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
                        return Ok::<_, Infallible>(response);
                    }
                    Ok(Response::new(Full::new(Bytes::from_static(
                        b"tunnelled page",
                    ))))
                }
            });
            tokio::spawn(async move {
                let _served = http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), service)
                    .with_upgrades()
                    .await;
            });
        }
    });
    Ok(address)
}

/// An HTTPS upstream serving the fixture chain.
async fn tls_upstream() -> Result<SocketAddr, Box<dyn Error>> {
    let chain = vec![
        CertificateDer::from(fixture("leaf")?),
        CertificateDer::from(fixture("ca")?),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(fixture("leaf-key")?));
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(chain, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_request: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Empty::<Bytes>::new()))
                });
                let _served = http1::Builder::new()
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Ok(address)
}

struct Gateway {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: tokio::task::JoinHandle<Result<(), remap_network::NetworkError>>,
}

fn gateway(
    mappings: &[(&str, &str)],
    key: [u8; 32],
    socket: Option<PathBuf>,
) -> Result<Gateway, Box<dyn Error>> {
    gateway_with_landing(mappings, key, socket, None)
}

fn gateway_with_landing(
    mappings: &[(&str, &str)],
    key: [u8; 32],
    socket: Option<PathBuf>,
    landing: Option<&str>,
) -> Result<Gateway, Box<dyn Error>> {
    let store = SnapshotStore::empty();
    let mut built = Vec::new();
    for (name, target) in mappings {
        let target = MappingTarget::parse_with_http_policy(target, HostHeaderPolicy::UseUpstream)?;
        built.push(
            Mapping::new(NamePattern::parse(name)?, target)
                .with_landing(landing.map(remap_core::LandingPath::parse).transpose()?)?,
        );
    }
    assert!(store.publish(RegistrySnapshot::new(1, built)?));
    let mut runtime = GatewayRuntime::bind(
        GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into()),
        store,
    )?
    .with_peer_resolver(Arc::new(Solis { key }) as Arc<dyn PeerResolver>);
    if let Some(socket) = socket {
        runtime = runtime.with_supgang_streams(SupgangStreams::at(socket));
    }
    let address = runtime.local_addr();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(runtime.serve(receiver));
    Ok(Gateway {
        address,
        shutdown,
        task,
    })
}

impl Gateway {
    async fn stop(self) -> TestResult {
        self.shutdown.send_replace(true);
        self.task.await??;
        Ok(())
    }
}

async fn exchange(
    gateway: SocketAddr,
    request: &[u8],
) -> Result<(TcpStream, String), Box<dyn Error>> {
    let mut stream = TcpStream::connect(gateway).await?;
    stream.write_all(request).await?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if timeout(Duration::from_secs(5), stream.read(&mut byte)).await?? == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok((stream, String::from_utf8(head)?.to_ascii_lowercase()))
}

fn get(host: &str) -> Vec<u8> {
    format!("GET /docs?page=2 HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n").into_bytes()
}

fn endpoint_path(directory: &tempfile::TempDir) -> PathBuf {
    directory.path().join("control.sock")
}

#[tokio::test]
async fn landing_peer_routes_redirect_root_and_preserve_other_paths() -> TestResult {
    for target in ["supgang://solis/pinned", "supgang+http://solis/preview"] {
        let directory = tempfile::tempdir()?;
        let socket = endpoint_path(&directory);
        endpoint(&socket, Vec::new())?;
        let gateway = gateway_with_landing(
            &[("preview.test", target)],
            pin()?,
            Some(socket),
            Some("/page"),
        )?;
        let request = b"GET /?x=1 HTTP/1.1\r\nHost: preview.test\r\nConnection: close\r\n\r\n";
        let (_stream, head) = exchange(gateway.address, request).await?;
        assert!(head.starts_with("http/1.1 302"), "{head}");
        assert!(head.contains("location: /page?x=1\r\n"), "{head}");
        gateway.stop().await?;
    }
    Ok(())
}

#[tokio::test]
async fn a_plaintext_service_is_reached_only_through_the_stream() -> TestResult {
    let seen = Seen::default();
    let upstream = plain_upstream(Arc::clone(&seen)).await?;
    let directory = tempfile::tempdir()?;
    let socket = endpoint_path(&directory);
    endpoint(&socket, vec![("preview", upstream)])?;
    let gateway = gateway(
        &[("preview.test", "supgang+http://solis/preview")],
        pin()?,
        Some(socket),
    )?;

    let (mut stream, head) = exchange(gateway.address, &get("preview.test")).await?;
    assert!(head.starts_with("http/1.1 200"), "{head}");
    let mut body = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut body)).await??;
    assert_eq!(body, b"tunnelled page");
    assert_eq!(
        seen.lock().map_err(|_| "poisoned")?.first().cloned(),
        Some(("/docs?page=2".to_owned(), Some("localhost".to_owned()))),
        "the target must see an origin-form request for its own loopback"
    );
    gateway.stop().await
}

#[tokio::test]
async fn a_websocket_switch_rides_the_stream() -> TestResult {
    let upstream = plain_upstream(Seen::default()).await?;
    let directory = tempfile::tempdir()?;
    let socket = endpoint_path(&directory);
    endpoint(&socket, vec![("preview", upstream)])?;
    let gateway = gateway(
        &[("preview.test", "supgang+http://solis/preview")],
        pin()?,
        Some(socket),
    )?;
    let request = b"GET /hmr HTTP/1.1\r\nHost: preview.test\r\nConnection: Upgrade\r\n\
Upgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";
    let (mut stream, head) = exchange(gateway.address, request).await?;
    assert!(head.starts_with("http/1.1 101"), "{head}");
    stream.write_all(b"hot update").await?;
    let mut echoed = [0_u8; 10];
    timeout(Duration::from_secs(5), stream.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"hot update");
    gateway.stop().await
}

#[tokio::test]
async fn a_plaintext_service_without_a_tunnel_is_refused() -> TestResult {
    let gateway = gateway(
        &[("preview.test", "supgang+http://solis/preview")],
        pin()?,
        None,
    )?;
    let (_stream, head) = exchange(gateway.address, &get("preview.test")).await?;
    assert!(head.starts_with("http/1.1 502"), "{head}");
    gateway.stop().await
}

#[tokio::test]
async fn a_refused_stream_never_falls_back_to_plaintext_on_the_network() -> TestResult {
    let directory = tempfile::tempdir()?;
    let socket = endpoint_path(&directory);
    endpoint(&socket, Vec::new())?;
    let gateway = gateway(
        &[("preview.test", "supgang+http://solis/preview")],
        pin()?,
        Some(socket),
    )?;
    let (_stream, head) = exchange(gateway.address, &get("preview.test")).await?;
    assert!(head.starts_with("http/1.1 502"), "{head}");
    gateway.stop().await
}

#[tokio::test]
async fn a_pinned_service_is_verified_inside_the_stream() -> TestResult {
    let upstream = tls_upstream().await?;
    let directory = tempfile::tempdir()?;
    let socket = endpoint_path(&directory);
    endpoint(&socket, vec![("pinned", upstream)])?;

    let trusted = gateway(
        &[("hub.test", "supgang://solis/pinned")],
        pin()?,
        Some(socket.clone()),
    )?;
    let (_stream, head) = exchange(trusted.address, &get("hub.test")).await?;
    assert!(
        head.starts_with("http/1.1 200"),
        "a pinned service over the stream failed: {head}"
    );
    trusted.stop().await?;

    // Another key advertised for the same service: the stream opens, and the
    // TLS inside it is refused, with no fallback to a direct dial.
    let mistrusted = gateway(
        &[("hub.test", "supgang://solis/pinned")],
        [0x11; 32],
        Some(socket),
    )?;
    let (_stream, head) = exchange(mistrusted.address, &get("hub.test")).await?;
    assert!(
        head.starts_with("http/1.1 502"),
        "a wrong key was accepted inside the stream: {head}"
    );
    mistrusted.stop().await
}
