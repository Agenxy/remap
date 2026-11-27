// SPDX-License-Identifier: GPL-3.0-or-later
//! A real `remapd` in a temporary directory, a bound `remap web`, and a
//! plain HTTP/1.1 client that sends exactly the headers a test chooses.

use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, HeaderValue};
use hyper::{HeaderMap, Method, Request, StatusCode};
use hyper_util::rt::TokioIo;
use remap_protocol::{ControlClient, ControlPaths, Diagnostic, Surface};
use remap_web::{WebOptions, WebServer};
use remapd::DaemonConfig;
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

pub(crate) type TestResult = Result<(), Box<dyn Error>>;

/// A running daemon and web server, stopped by [`Fixture::stop`].
pub(crate) struct Fixture {
    _directory: tempfile::TempDir,
    pub(crate) addr: SocketAddr,
    pub(crate) url: String,
    pub(crate) token: String,
    web_stop: oneshot::Sender<()>,
    web: JoinHandle<Result<(), Diagnostic>>,
    daemon_stop: Option<oneshot::Sender<()>>,
    daemon: Option<JoinHandle<Result<(), Diagnostic>>>,
}

impl Fixture {
    /// Starts a daemon and a web server in front of it.
    pub(crate) async fn start(name: Option<&str>) -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let paths = ControlPaths::under(directory.path().join("data"));
        let (daemon_stop, stopped) = oneshot::channel::<()>();
        let daemon = tokio::spawn(remapd::serve_until(
            DaemonConfig::new(paths.clone()),
            async {
                let _done = stopped.await;
            },
        ));
        wait_for_socket(paths.socket()).await?;
        let mut fixture = Self::serve(directory, paths.socket(), name).await?;
        fixture.daemon_stop = Some(daemon_stop);
        fixture.daemon = Some(daemon);
        Ok(fixture)
    }

    /// A web server whose daemon socket does not exist.
    pub(crate) async fn without_daemon() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let socket = directory.path().join("absent.sock");
        Self::serve(directory, &socket, None).await
    }

    async fn serve(
        directory: tempfile::TempDir,
        socket: &Path,
        name: Option<&str>,
    ) -> Result<Self, Box<dyn Error>> {
        let client = ControlClient::new(socket, Surface::Cli, env!("CARGO_PKG_VERSION"));
        let options = WebOptions {
            port: 0,
            name: name.map(str::to_owned),
        };
        let server = WebServer::bind(client, options).await?;
        let addr = server.local_addr();
        let url = server.url();
        let token = url
            .split_once("#token=")
            .map(|(_, token)| token.to_owned())
            .ok_or_else(|| io::Error::other("the URL carries no token"))?;
        let (web_stop, stopping) = oneshot::channel::<()>();
        let web = tokio::spawn(server.serve_until(async {
            let _done = stopping.await;
        }));
        Ok(Self {
            _directory: directory,
            addr,
            url,
            token,
            web_stop,
            web,
            daemon_stop: None,
            daemon: None,
        })
    }

    /// `Host: 127.0.0.1:<port>`.
    pub(crate) fn host(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    /// A request with the right `Host` and no other header.
    pub(crate) fn request(&self, method: Method, path: &str) -> hyper::http::request::Builder {
        Request::builder()
            .method(method)
            .uri(path)
            .header(HOST, self.host())
    }

    /// A request with the right `Host` and the capability token.
    pub(crate) fn authorized(&self, method: Method, path: &str) -> hyper::http::request::Builder {
        self.request(method, path)
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
    }

    pub(crate) async fn get(&self, path: &str) -> Result<Reply, Box<dyn Error>> {
        send(self.addr, self.authorized(Method::GET, path).body(empty())?).await
    }

    pub(crate) async fn post(&self, path: &str, body: &Value) -> Result<Reply, Box<dyn Error>> {
        let request = self
            .authorized(Method::POST, path)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(serde_json::to_vec(body)?)))?;
        send(self.addr, request).await
    }

    /// Stops the web server, then the daemon, and reports either failure.
    pub(crate) async fn stop(mut self) -> TestResult {
        let _sent = self.web_stop.send(());
        tokio::time::timeout(Duration::from_secs(5), self.web).await???;
        if let Some(stop) = self.daemon_stop.take() {
            let _sent = stop.send(());
        }
        if let Some(daemon) = self.daemon.take() {
            daemon.await??;
        }
        Ok(())
    }
}

pub(crate) fn empty() -> Full<Bytes> {
    Full::new(Bytes::new())
}

/// One complete response.
#[derive(Debug)]
pub(crate) struct Reply {
    pub(crate) status: StatusCode,
    pub(crate) headers: HeaderMap,
    pub(crate) body: Bytes,
}

impl Reply {
    pub(crate) fn json(&self) -> Result<Value, Box<dyn Error>> {
        Ok(serde_json::from_slice(&self.body)?)
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|value| value.to_str().ok())
    }

    /// The diagnostic code of an error body.
    pub(crate) fn code(&self) -> Result<String, Box<dyn Error>> {
        self.json()?["code"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| io::Error::other(format!("no diagnostic code: {self:?}")).into())
    }
}

/// Sends one request over a fresh connection, exactly as built.
pub(crate) async fn send(
    addr: SocketAddr,
    request: Request<Full<Bytes>>,
) -> Result<Reply, Box<dyn Error>> {
    let stream = TcpStream::connect(addr).await?;
    let (mut sender, connection) =
        hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
    let driver = tokio::spawn(connection);
    let response = sender.send_request(request).await?;
    let (parts, body) = response.into_parts();
    let body = body.collect().await?.to_bytes();
    drop(sender);
    let _finished = driver.await?;
    Ok(Reply {
        status: parts.status,
        headers: parts.headers,
        body,
    })
}

/// Writes raw bytes and returns the response's status line.
pub(crate) async fn raw_status_line(
    addr: SocketAddr,
    request: &[u8],
) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request).await?;
    let mut received = Vec::new();
    let mut buffer = [0_u8; 1024];
    while !received.windows(2).any(|pair| pair == b"\r\n") {
        let read = stream.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        received.extend_from_slice(buffer.get(..read).unwrap_or_default());
    }
    let text = String::from_utf8_lossy(&received);
    Ok(text.lines().next().unwrap_or_default().to_owned())
}

/// A random UUID version 4, as the page makes with `crypto.randomUUID()`.
pub(crate) fn uuid_v4() -> Result<String, Box<dyn Error>> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .fold(String::with_capacity(32), |mut hex, byte| {
            use std::fmt::Write as _;
            let _written = write!(hex, "{byte:02x}");
            hex
        });
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[0..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..32]
    ))
}

/// The headers ADR-0041 requires on every response.
pub(crate) fn assert_security_headers(reply: &Reply) {
    for (name, value) in [
        (
            "content-security-policy",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; \
             connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        ),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("cache-control", "no-store"),
        ("cross-origin-opener-policy", "same-origin"),
        ("cross-origin-resource-policy", "same-origin"),
    ] {
        assert_eq!(reply.header(name), Some(value), "{name} on {reply:?}");
    }
    let cors = reply
        .headers
        .keys()
        .filter(|name| name.as_str().starts_with("access-control-"))
        .collect::<Vec<_>>();
    assert!(cors.is_empty(), "CORS headers {cors:?} on {reply:?}");
}

pub(crate) fn bearer(token: &str) -> Result<HeaderValue, Box<dyn Error>> {
    Ok(HeaderValue::from_str(&format!("Bearer {token}"))?)
}

async fn wait_for_socket(path: &Path) -> TestResult {
    for _attempt in 0..400 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(io::Error::other("daemon socket did not appear").into())
}
