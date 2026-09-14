//! The gateway routing a peer mapping end to end (ADR-0016): a TLS upstream
//! serving the peer's chain, a resolver standing in for Supgang, and the
//! one property the per-key clients exist for: a connection verified under
//! one advertised key never carries a request for another.

use std::convert::Infallible;
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::{
    GatewayRuntime, GatewayRuntimeConfig, PeerResolveError, PeerResolver, ResolvedPeerService,
    SnapshotStore,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

type TestResult = Result<(), Box<dyn Error>>;

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

/// Stands in for Supgang: one peer, whose advertised port and key the test
/// changes between requests, as a re-keyed peer's next record would.
#[derive(Debug)]
struct Advertised {
    port: Mutex<u16>,
    pin: Mutex<[u8; 32]>,
}

impl PeerResolver for Advertised {
    fn resolve<'a>(
        &'a self,
        _peer: &'a str,
        _service: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<ResolvedPeerService, PeerResolveError>>
                + Send
                + 'a,
        >,
    > {
        Box::pin(async move {
            let port = *self
                .port
                .lock()
                .map_err(|_| PeerResolveError::Unavailable("poisoned".into()))?;
            let pin = *self
                .pin
                .lock()
                .map_err(|_| PeerResolveError::Unavailable("poisoned".into()))?;
            Ok(ResolvedPeerService {
                host: IpAddr::V4(Ipv4Addr::LOCALHOST),
                port,
                key_pin: pin,
                expires_at: u64::MAX,
            })
        })
    }
}

/// An HTTPS upstream serving the peer's chain, answering every request on
/// every connection, and counting the connections it accepted.
async fn tls_upstream(accepted: Arc<Mutex<usize>>) -> Result<SocketAddr, Box<dyn Error>> {
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
        loop {
            let Ok((stream, _peer)) = listener.accept().await else {
                return;
            };
            if let Ok(mut count) = accepted.lock() {
                *count += 1;
            }
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let service = service_fn(|_request: Request<Incoming>| async {
                    Ok::<_, Infallible>(Response::new(Full::new(Bytes::from_static(
                        b"pinned upstream",
                    ))))
                });
                let _served = http1::Builder::new()
                    .keep_alive(true)
                    .serve_connection(TokioIo::new(tls), service)
                    .await;
            });
        }
    });
    Ok(address)
}

async fn ask(gateway: SocketAddr) -> Result<String, Box<dyn Error>> {
    let mut browser = TcpStream::connect(gateway).await?;
    browser
        .write_all(b"GET /board HTTP/1.1\r\nHost: hub\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), browser.read_to_end(&mut response)).await??;
    Ok(String::from_utf8(response)?)
}

fn pin_bytes() -> Result<[u8; 32], Box<dyn Error>> {
    fixture("pin")?
        .try_into()
        .map_err(|_| "the pin fixture is not 32 bytes".into())
}

#[tokio::test]
async fn a_peer_mapping_is_routed_only_under_the_key_its_record_advertises() -> TestResult {
    let accepted = Arc::new(Mutex::new(0_usize));
    let upstream = tls_upstream(Arc::clone(&accepted)).await?;
    let plaintext = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let plaintext_port = plaintext.local_addr()?.port();
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = plaintext.accept().await {
            let _sent = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });

    let advertised = Arc::new(Advertised {
        port: Mutex::new(upstream.port()),
        pin: Mutex::new(pin_bytes()?),
    });
    let store = SnapshotStore::empty();
    let target = MappingTarget::parse_with_http_policy(
        "supgang://MacSolis/dibs",
        HostHeaderPolicy::PreserveClient,
    )?;
    let mapping = Mapping::new(NamePattern::parse("hub")?, target);
    assert!(store.publish(RegistrySnapshot::new(1, vec![mapping])?));
    let runtime = GatewayRuntime::bind(
        GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into()),
        store,
    )?
    .with_peer_resolver(Arc::clone(&advertised) as Arc<dyn PeerResolver>);
    let gateway = runtime.local_addr();
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let gateway_task = tokio::spawn(runtime.serve(shutdown_receiver));

    // The record's key is the one the upstream serves: routed, verified.
    let first = ask(gateway).await?;
    assert!(
        first.starts_with("HTTP/1.1 200") && first.ends_with("pinned upstream"),
        "a peer serving its advertised key was not routed: {first}"
    );
    let second = ask(gateway).await?;
    assert!(second.starts_with("HTTP/1.1 200"), "{second}");
    let connections_under_a = *accepted.lock().map_err(|_| "poisoned")?;
    assert!(connections_under_a >= 1);

    // The peer re-keys: its next record advertises another key for the same
    // address and port. A client that reused the connection verified under
    // the old key would answer 200 here; the per-key client refuses.
    if let Ok(mut pin) = advertised.pin.lock() {
        *pin = [0x11; 32];
    }
    let rekeyed = ask(gateway).await?;
    assert!(
        rekeyed.starts_with("HTTP/1.1 502"),
        "a request for a re-keyed peer rode a connection verified under the old key: {rekeyed}"
    );

    // A peer whose advertised port answers in plaintext is refused too: a
    // pinned client speaks HTTPS and nothing else.
    if let Ok(mut pin) = advertised.pin.lock() {
        *pin = pin_bytes()?;
    }
    if let Ok(mut port) = advertised.port.lock() {
        *port = plaintext_port;
    }
    let plain = ask(gateway).await?;
    assert!(
        plain.starts_with("HTTP/1.1 502"),
        "a plaintext upstream was accepted for a peer mapping: {plain}"
    );

    shutdown_sender.send_replace(true);
    gateway_task.await??;
    Ok(())
}
