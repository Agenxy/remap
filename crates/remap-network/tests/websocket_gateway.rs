// SPDX-License-Identifier: GPL-3.0-or-later
//! WebSocket switches carried through the gateway (ADR-0021): the switch
//! reaches the upstream, bytes flow both ways for longer than an HTTP
//! connection may live, and each of the tunnel bounds closes or refuses one.

use std::convert::Infallible;
use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::header::{CONNECTION, HeaderValue, UPGRADE};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::{GatewayRuntime, GatewayRuntimeConfig, SnapshotStore};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

type TestResult = Result<(), Box<dyn Error>>;
type Seen = Arc<Mutex<Vec<(Option<String>, Option<String>)>>>;

const SWITCH: &[u8] = b"GET /hmr?token=t HTTP/1.1\r\nHost: ws.test\r\n\
Connection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n";

const OTHER_UPGRADE: &[u8] =
    b"GET / HTTP/1.1\r\nHost: ws.test\r\nConnection: Upgrade, HTTP2-Settings\r\n\
Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n";

fn header(request: &Request<Incoming>, name: hyper::header::HeaderName) -> Option<String> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned)
}

/// An upstream that echoes every byte of a WebSocket switch, answers any
/// other request with 200, and records the hop-by-hop headers it received.
async fn echo_upstream(seen: Seen) -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let seen = Arc::clone(&seen);
            let service = service_fn(move |mut request: Request<Incoming>| {
                let upgrade = header(&request, UPGRADE);
                if let Ok(mut seen) = seen.lock() {
                    seen.push((header(&request, CONNECTION), upgrade.clone()));
                }
                let switching = upgrade.is_some_and(|value| value == "websocket");
                if switching {
                    let pending = hyper::upgrade::on(&mut request);
                    tokio::spawn(async move {
                        let Ok(upgraded) = pending.await else { return };
                        let (mut reader, mut writer) = tokio::io::split(TokioIo::new(upgraded));
                        let _copied = tokio::io::copy(&mut reader, &mut writer).await;
                    });
                }
                async move {
                    let mut response = Response::new(Empty::<Bytes>::new());
                    if switching {
                        *response.status_mut() = StatusCode::SWITCHING_PROTOCOLS;
                        response
                            .headers_mut()
                            .insert(UPGRADE, HeaderValue::from_static("websocket"));
                        response
                            .headers_mut()
                            .insert(CONNECTION, HeaderValue::from_static("upgrade"));
                    }
                    Ok::<_, Infallible>(response)
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

struct Gateway {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), remap_network::NetworkError>>,
}

impl Gateway {
    async fn stop(self) -> TestResult {
        self.shutdown.send_replace(true);
        self.task.await??;
        Ok(())
    }
}

fn gateway(
    upstream: SocketAddr,
    configure: impl FnOnce(&mut GatewayRuntimeConfig),
) -> Result<Gateway, Box<dyn Error>> {
    gateway_with_landing(upstream, None, configure)
}

fn gateway_with_landing(
    upstream: SocketAddr,
    landing: Option<&str>,
    configure: impl FnOnce(&mut GatewayRuntimeConfig),
) -> Result<Gateway, Box<dyn Error>> {
    let store = SnapshotStore::empty();
    let target = MappingTarget::parse_with_http_policy(
        &format!("http://{upstream}/"),
        HostHeaderPolicy::UseUpstream,
    )?;
    let mapping = Mapping::new(NamePattern::parse("ws.test")?, target)
        .with_landing(landing.map(remap_core::LandingPath::parse).transpose()?)?;
    assert!(store.publish(RegistrySnapshot::new(1, vec![mapping])?));
    let mut config = GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into());
    configure(&mut config);
    let runtime = GatewayRuntime::bind(config, store)?;
    let address = runtime.local_addr();
    let (shutdown, receiver) = watch::channel(false);
    let task = tokio::spawn(runtime.serve(receiver));
    Ok(Gateway {
        address,
        shutdown,
        task,
    })
}

/// Sends `request` and returns the stream with the response head read.
async fn open(gateway: SocketAddr, request: &[u8]) -> Result<(TcpStream, String), Box<dyn Error>> {
    let mut stream = TcpStream::connect(gateway).await?;
    stream.write_all(request).await?;
    let mut head = Vec::new();
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        let read = timeout(Duration::from_secs(5), stream.read(&mut byte)).await??;
        if read == 0 {
            break;
        }
        head.push(byte[0]);
    }
    Ok((stream, String::from_utf8(head)?.to_ascii_lowercase()))
}

async fn echo(stream: &mut TcpStream, payload: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    stream.write_all(payload).await?;
    let mut answer = vec![0_u8; payload.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut answer)).await??;
    Ok(answer)
}

#[tokio::test]
async fn landing_does_not_redirect_a_root_websocket_switch() -> TestResult {
    let upstream = echo_upstream(Seen::default()).await?;
    let gateway = gateway_with_landing(upstream, Some("/page"), |_| {})?;
    let request = std::str::from_utf8(SWITCH)?.replacen("/hmr", "/", 1);
    let (mut stream, head) = open(gateway.address, request.as_bytes()).await?;
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert_eq!(echo(&mut stream, b"root update").await?, b"root update");
    gateway.stop().await
}

#[tokio::test]
async fn review_landing_redirects_other_upgrades() -> TestResult {
    let seen = Seen::default();
    let upstream = echo_upstream(Arc::clone(&seen)).await?;
    let gateway = gateway_with_landing(upstream, Some("/page"), |_| {})?;
    let (_stream, head) = open(gateway.address, OTHER_UPGRADE).await?;
    assert!(head.starts_with("http/1.1 302"), "{head}");
    assert!(head.contains("location: /page\r\n"), "{head}");
    assert!(seen.lock().map_err(|_| "poisoned")?.is_empty());
    gateway.stop().await
}

#[tokio::test]
async fn a_websocket_switch_outlives_the_http_connection_deadline() -> TestResult {
    let seen = Seen::default();
    let upstream = echo_upstream(Arc::clone(&seen)).await?;
    let gateway = gateway(upstream, |config| {
        config.connection_timeout = Duration::from_millis(300);
    })?;

    let (mut stream, head) = open(gateway.address, SWITCH).await?;
    assert!(
        head.starts_with("http/1.1 101"),
        "the switch was not relayed: {head}"
    );
    assert!(
        head.contains("upgrade: websocket") && head.contains("connection: upgrade"),
        "{head}"
    );
    assert_eq!(
        seen.lock().map_err(|_| "poisoned")?.first().cloned(),
        Some((Some("upgrade".to_owned()), Some("websocket".to_owned()))),
        "the upstream did not receive the switch headers"
    );
    assert_eq!(echo(&mut stream, b"first frame").await?, b"first frame");
    sleep(Duration::from_millis(600)).await;
    assert_eq!(
        echo(&mut stream, b"after the HTTP deadline").await?,
        b"after the HTTP deadline",
        "the tunnel was closed by the HTTP connection lifetime"
    );
    gateway.stop().await
}

#[tokio::test]
async fn an_idle_tunnel_is_closed() -> TestResult {
    let upstream = echo_upstream(Seen::default()).await?;
    let gateway = gateway(upstream, |config| {
        config.tunnel_idle_timeout = Duration::from_millis(200);
    })?;
    let (mut stream, head) = open(gateway.address, SWITCH).await?;
    assert!(head.starts_with("http/1.1 101"), "{head}");
    assert_eq!(echo(&mut stream, b"busy").await?, b"busy");
    let mut rest = Vec::new();
    let closed = timeout(Duration::from_secs(5), stream.read_to_end(&mut rest)).await;
    assert!(
        matches!(closed, Ok(Ok(0))),
        "an idle tunnel stayed open: {closed:?}"
    );
    gateway.stop().await
}

#[tokio::test]
async fn a_switch_past_the_tunnel_limit_is_refused_before_the_upstream() -> TestResult {
    let seen = Seen::default();
    let upstream = echo_upstream(Arc::clone(&seen)).await?;
    let gateway = gateway(upstream, |config| config.tunnel_limit = 1)?;
    let (mut held, admitted) = open(gateway.address, SWITCH).await?;
    assert!(admitted.starts_with("http/1.1 101"), "{admitted}");
    let (_refused, refusal) = open(gateway.address, SWITCH).await?;
    assert!(
        refusal.starts_with("http/1.1 503"),
        "a second tunnel was admitted: {refusal}"
    );
    assert_eq!(seen.lock().map_err(|_| "poisoned")?.len(), 1);
    assert_eq!(echo(&mut held, b"still carried").await?, b"still carried");
    gateway.stop().await
}

#[tokio::test]
async fn another_upgrade_is_forwarded_as_an_ordinary_request() -> TestResult {
    let seen = Seen::default();
    let upstream = echo_upstream(Arc::clone(&seen)).await?;
    let gateway = gateway(upstream, |_| {})?;
    let (_stream, head) = open(gateway.address, OTHER_UPGRADE).await?;
    assert!(head.starts_with("http/1.1 200"), "{head}");
    assert_eq!(
        seen.lock().map_err(|_| "poisoned")?.first().cloned(),
        Some((None, None)),
        "a non-WebSocket upgrade reached the upstream"
    );
    gateway.stop().await
}
