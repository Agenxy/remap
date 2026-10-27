//! A failed upstream exchange names the mapping and why it failed, and
//! never the upstream's address or port (ADR-0028).

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use remap_core::{HostHeaderPolicy, Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::{GatewayRuntime, GatewayRuntimeConfig, NetworkError, SnapshotStore};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

type TestResult = Result<(), Box<dyn Error>>;

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = match name {
        "ca" => include_str!("fixtures/ca.der.hex"),
        "leaf" => include_str!("fixtures/leaf.der.hex"),
        "leaf-key" => include_str!("fixtures/leaf.key.pkcs8.hex"),
        _ => return Err("unknown fixture".into()),
    }
    .trim();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(Into::into))
        .collect()
}

struct Gateway {
    address: SocketAddr,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), NetworkError>>,
}

impl Gateway {
    /// A gateway with one mapping, `pattern`, routed to `target`.
    fn start(
        pattern: &str,
        target: &str,
        upstream_timeout: Duration,
    ) -> Result<Self, Box<dyn Error>> {
        let store = SnapshotStore::empty();
        let target = MappingTarget::parse_with_http_policy(target, HostHeaderPolicy::UseUpstream)?;
        let mapping = Mapping::new(NamePattern::parse(pattern)?, target);
        assert!(store.publish(RegistrySnapshot::new(1, vec![mapping])?));
        let mut config = GatewayRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into());
        config.upstream_timeout = upstream_timeout;
        let runtime = GatewayRuntime::bind(config, store)?;
        let address = runtime.local_addr();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(runtime.serve(receiver));
        Ok(Self {
            address,
            shutdown,
            task,
        })
    }

    /// The status line and body the gateway answers `host` with.
    async fn ask(&self, host: &str) -> Result<(String, String), Box<dyn Error>> {
        let mut browser = TcpStream::connect(self.address).await?;
        browser
            .write_all(
                format!("GET /app HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), browser.read_to_end(&mut response)).await??;
        let response = String::from_utf8(response)?;
        let (head, body) = response
            .split_once("\r\n\r\n")
            .ok_or("the gateway's answer had no body")?;
        let status = head.lines().next().unwrap_or_default().to_owned();
        Ok((status, body.to_owned()))
    }

    async fn stop(self) -> TestResult {
        self.shutdown.send_replace(true);
        self.task.await??;
        Ok(())
    }
}

/// The body names the code, the matched pattern and the cause, and does not
/// carry the upstream's address or port.
fn assert_diagnosed(status: &str, body: &str, expected: (&str, &str, &str), upstream: SocketAddr) {
    let (status_code, code, cause) = expected;
    assert!(
        status.starts_with(&format!("HTTP/1.1 {status_code}")),
        "{status}\n{body}"
    );
    assert!(body.contains(&format!("{code}: ")), "{body}");
    assert!(body.contains(&format!("\nCause: {cause}\n")), "{body}");
    assert!(
        !body.contains(&upstream.port().to_string()),
        "port leaked: {body}"
    );
    assert!(
        !body.contains(&upstream.ip().to_string()),
        "address leaked: {body}"
    );
}

async fn closed_port() -> Result<SocketAddr, Box<dyn Error>> {
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = reservation.local_addr()?;
    drop(reservation);
    Ok(address)
}

#[tokio::test]
async fn refused_names_the_wildcard_mapping_and_the_refusal() -> TestResult {
    let upstream = closed_port().await?;
    let gateway = Gateway::start(
        "*.api.test",
        &format!("http://{upstream}/"),
        Duration::from_secs(5),
    )?;
    let (status, body) = gateway.ask("web.api.test").await?;
    assert_diagnosed(
        &status,
        &body,
        ("502", "E_GATEWAY_UPSTREAM", "refused"),
        upstream,
    );
    assert!(body.contains("\nMapping: *.api.test\n"), "{body}");
    assert!(body.contains("remap get *.api.test"), "{body}");
    gateway.stop().await
}

#[tokio::test]
async fn timeout_names_the_mapping_and_the_deadline() -> TestResult {
    // Accepts the connection and never answers.
    let silent = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream = silent.local_addr()?;
    let held = tokio::spawn(async move {
        let mut open = Vec::new();
        while let Ok((stream, _peer)) = silent.accept().await {
            open.push(stream);
        }
    });
    let gateway = Gateway::start(
        "slow.test",
        &format!("http://{upstream}/"),
        Duration::from_millis(300),
    )?;
    let (status, body) = gateway.ask("slow.test").await?;
    assert_diagnosed(
        &status,
        &body,
        ("504", "E_GATEWAY_TIMEOUT", "timeout"),
        upstream,
    );
    assert!(body.contains("\nMapping: slow.test\n"), "{body}");
    gateway.stop().await?;
    held.abort();
    Ok(())
}

#[tokio::test]
async fn tls_names_the_mapping_when_the_certificate_is_not_trusted() -> TestResult {
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
    let upstream = listener.local_addr()?;
    let server = tokio::spawn(async move {
        while let Ok((stream, _peer)) = listener.accept().await {
            let _refused = acceptor.accept(stream).await;
        }
    });
    let gateway = Gateway::start(
        "secure.test",
        &format!("https://{upstream}/"),
        Duration::from_secs(5),
    )?;
    let (status, body) = gateway.ask("secure.test").await?;
    assert_diagnosed(
        &status,
        &body,
        ("502", "E_GATEWAY_UPSTREAM", "tls"),
        upstream,
    );
    assert!(body.contains("\nMapping: secure.test\n"), "{body}");
    gateway.stop().await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn tls_names_an_https_target_that_speaks_plain_http() -> TestResult {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream = listener.local_addr()?;
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut hello = [0_u8; 512];
            let _read = stream.read(&mut hello).await;
            let _sent = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
                .await;
        }
    });
    let gateway = Gateway::start(
        "dev.test",
        &format!("https://{upstream}/"),
        Duration::from_secs(5),
    )?;
    let (status, body) = gateway.ask("dev.test").await?;
    assert_diagnosed(
        &status,
        &body,
        ("502", "E_GATEWAY_UPSTREAM", "tls"),
        upstream,
    );
    gateway.stop().await?;
    server.abort();
    Ok(())
}

#[tokio::test]
async fn reset_names_the_mapping_when_the_upstream_hangs_up() -> TestResult {
    // Reads the request head, then closes without a response.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream = listener.local_addr()?;
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let mut head = Vec::new();
            let mut byte = [0_u8];
            while !head.ends_with(b"\r\n\r\n") {
                if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                    break;
                }
                head.push(byte[0]);
            }
            drop(stream);
        }
    });
    let gateway = Gateway::start(
        "flaky.test",
        &format!("http://{upstream}/"),
        Duration::from_secs(5),
    )?;
    let (status, body) = gateway.ask("flaky.test").await?;
    assert_diagnosed(
        &status,
        &body,
        ("502", "E_GATEWAY_UPSTREAM", "reset"),
        upstream,
    );
    assert!(body.contains("\nMapping: flaky.test\n"), "{body}");
    gateway.stop().await?;
    server.abort();
    Ok(())
}
