// SPDX-License-Identifier: GPL-3.0-or-later
//! The threat model's mitigations, exercised against the bound server.

use std::time::Duration;

use bytes::Bytes;
use http_body_util::Full;
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, HOST, ORIGIN};
use hyper::{Method, Request, StatusCode};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;

use crate::support::{
    Fixture, TestResult, assert_security_headers, bearer, empty, raw_status_line, send,
};

const API_PATHS: [(&str, &str); 8] = [
    ("GET", "/api/status"),
    ("GET", "/api/mappings"),
    ("GET", "/api/mapping?pattern=api.test"),
    ("GET", "/api/resolve?name=api.test"),
    ("GET", "/api/wait?after=0"),
    ("POST", "/api/validate"),
    ("POST", "/api/preview"),
    ("POST", "/api/apply"),
];

#[tokio::test]
async fn the_url_carries_a_fresh_256_bit_token_in_its_fragment() -> TestResult {
    let first = Fixture::start(None).await?;
    let second = Fixture::without_daemon().await?;
    let prefix = format!("http://127.0.0.1:{}/#token=", first.addr.port());
    assert!(first.url.starts_with(&prefix), "{}", first.url);
    assert_eq!(first.url.len(), prefix.len() + 64);
    assert!(
        first
            .token
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_ne!(first.token, second.token);
    assert_eq!(first.get("/api/status").await?.status, StatusCode::OK);
    second.stop().await?;
    first.stop().await
}

#[tokio::test]
async fn binds_loopback_ipv4_only() -> TestResult {
    let fixture = Fixture::without_daemon().await?;
    assert_eq!(fixture.addr.ip().to_string(), "127.0.0.1");
    assert_ne!(fixture.addr.port(), 0);
    let ipv6 = TcpStream::connect(("::1", fixture.addr.port())).await;
    assert!(ipv6.is_err(), "the server answered on ::1");
    fixture.stop().await
}

#[tokio::test]
async fn every_api_request_needs_the_exact_token() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let wrong = "0".repeat(64);
    let mut bodies = Vec::new();
    for (method, path) in API_PATHS {
        let method = Method::from_bytes(method.as_bytes())?;
        for authorization in [
            None,
            Some(bearer(&wrong)?),
            Some(bearer(&fixture.token.to_uppercase())?),
            Some(format!("Basic {}", fixture.token).parse()?),
            Some(fixture.token.parse()?),
        ] {
            let mut request = fixture
                .request(method.clone(), path)
                .header(CONTENT_TYPE, "application/json");
            if let Some(value) = authorization {
                request = request.header(AUTHORIZATION, value);
            }
            let reply = send(fixture.addr, request.body(Full::new(Bytes::from("{}")))?).await?;
            assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{method} {path}");
            assert_eq!(reply.header("www-authenticate"), Some("Bearer"));
            assert_security_headers(&reply);
            bodies.push(reply.body);
        }
    }
    // Every refusal is the same refusal: nothing says which part was wrong.
    assert!(bodies.windows(2).all(|pair| pair[0] == pair[1]));
    // An unknown API path is not revealed before the token is checked.
    let unknown = send(
        fixture.addr,
        fixture.request(Method::GET, "/api/nothing").body(empty())?,
    )
    .await?;
    assert_eq!(unknown.status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        fixture.get("/api/nothing").await?.status,
        StatusCode::NOT_FOUND
    );
    fixture.stop().await
}

#[tokio::test]
async fn a_host_that_is_not_the_listener_is_misdirected() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let port = fixture.addr.port();
    for host in [
        format!("evil.example:{port}"),
        format!("localhost.evil.example:{port}"),
        format!("127.0.0.1:{}", port.wrapping_add(1)),
        "127.0.0.1".to_owned(),
        "remap.lab".to_owned(),
        format!("[::1]:{port}"),
    ] {
        for path in ["/", "/api/status"] {
            let request = Request::builder()
                .uri(path)
                .header(HOST, &host)
                .header(AUTHORIZATION, bearer(&fixture.token)?)
                .body(empty())?;
            let reply = send(fixture.addr, request).await?;
            assert_eq!(
                reply.status,
                StatusCode::MISDIRECTED_REQUEST,
                "{host} {path}"
            );
            assert_eq!(reply.code()?, "web-host-not-allowed");
            assert_security_headers(&reply);
        }
    }
    let missing = Request::builder().uri("/").body(empty())?;
    assert_eq!(
        send(fixture.addr, missing).await?.status,
        StatusCode::MISDIRECTED_REQUEST
    );
    let absolute = fixture
        .authorized(Method::GET, "http://evil.example/api/status")
        .body(empty())?;
    assert_eq!(
        send(fixture.addr, absolute).await?.status,
        StatusCode::MISDIRECTED_REQUEST
    );
    let localhost = Request::builder()
        .uri("/api/status")
        .header(HOST, format!("localhost:{port}"))
        .header(AUTHORIZATION, bearer(&fixture.token)?)
        .body(empty())?;
    assert_eq!(send(fixture.addr, localhost).await?.status, StatusCode::OK);
    fixture.stop().await
}

#[tokio::test]
async fn a_foreign_origin_is_forbidden() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let port = fixture.addr.port();
    for origin in [
        "http://evil.example".to_owned(),
        format!("http://evil.example:{port}"),
        format!("https://127.0.0.1:{port}"),
        "null".to_owned(),
    ] {
        for path in ["/", "/api/status"] {
            let request = fixture
                .authorized(Method::GET, path)
                .header(ORIGIN, &origin)
                .body(empty())?;
            let reply = send(fixture.addr, request).await?;
            assert_eq!(reply.status, StatusCode::FORBIDDEN, "{origin} {path}");
            assert_eq!(reply.code()?, "web-origin-not-allowed");
            assert_security_headers(&reply);
        }
    }
    let own = fixture
        .authorized(Method::GET, "/api/status")
        .header(ORIGIN, format!("http://127.0.0.1:{port}"))
        .body(empty())?;
    assert_eq!(send(fixture.addr, own).await?.status, StatusCode::OK);
    fixture.stop().await
}

#[tokio::test]
async fn a_name_allows_its_own_host_and_origins_only() -> TestResult {
    let fixture = Fixture::start(Some("Remap.Lab")).await?;
    for (host, origin) in [
        ("remap.lab", "http://remap.lab"),
        ("remap.lab", "https://remap.lab"),
        (fixture.host().as_str(), "https://remap.lab"),
    ] {
        let request = Request::builder()
            .uri("/api/status")
            .header(HOST, host)
            .header(ORIGIN, origin)
            .header(AUTHORIZATION, bearer(&fixture.token)?)
            .body(empty())?;
        assert_eq!(
            send(fixture.addr, request).await?.status,
            StatusCode::OK,
            "{origin}"
        );
    }
    for origin in ["http://other.lab", "https://remap.lab.evil.example"] {
        let request = fixture
            .authorized(Method::GET, "/api/status")
            .header(ORIGIN, origin)
            .body(empty())?;
        assert_eq!(
            send(fixture.addr, request).await?.status,
            StatusCode::FORBIDDEN
        );
    }
    fixture.stop().await
}

#[tokio::test]
async fn writes_must_be_json() -> TestResult {
    let fixture = Fixture::start(None).await?;
    for content_type in [
        None,
        Some("text/plain"),
        Some("application/x-www-form-urlencoded"),
        Some("multipart/form-data; boundary=x"),
    ] {
        let mut request = fixture.authorized(Method::POST, "/api/preview");
        if let Some(value) = content_type {
            request = request.header(CONTENT_TYPE, value);
        }
        let body = Full::new(Bytes::from(r#"{"changes":[]}"#));
        let reply = send(fixture.addr, request.body(body)?).await?;
        assert_eq!(
            reply.status,
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "{content_type:?}"
        );
        assert_eq!(reply.code()?, "web-unsupported-media-type");
        assert_security_headers(&reply);
    }
    let charset = fixture
        .authorized(Method::POST, "/api/preview")
        .header(CONTENT_TYPE, "application/json; charset=utf-8")
        .body(Full::new(Bytes::from(r#"{"changes":[]}"#)))?;
    let reply = send(fixture.addr, charset).await?;
    assert_eq!(reply.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(reply.code()?, "E_EMPTY_CHANGE_SET");
    fixture.stop().await
}

#[tokio::test]
async fn bodies_over_64_kib_are_refused() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let limit = 64 * 1024;
    let padded = |length: usize| {
        let mut body = br#"{"changes":[]}"#.to_vec();
        body.resize(length, b' ');
        Full::new(Bytes::from(body))
    };
    let at_limit = fixture
        .authorized(Method::POST, "/api/preview")
        .header(CONTENT_TYPE, "application/json")
        .body(padded(limit))?;
    assert_eq!(
        send(fixture.addr, at_limit).await?.code()?,
        "E_EMPTY_CHANGE_SET"
    );
    let over = fixture
        .authorized(Method::POST, "/api/preview")
        .header(CONTENT_TYPE, "application/json")
        .body(padded(limit + 1))?;
    let reply = send(fixture.addr, over).await?;
    assert_eq!(reply.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(reply.code()?, "web-body-too-large");
    assert_security_headers(&reply);
    // Without a declared length the limit holds while the body streams in.
    let mut chunked = format!(
        "POST /api/preview HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n",
        fixture.host(),
        fixture.token
    )
    .into_bytes();
    for _chunk in 0..17 {
        chunked.extend_from_slice(format!("{:x}\r\n", 4096).as_bytes());
        chunked.extend(std::iter::repeat_n(b' ', 4096));
        chunked.extend_from_slice(b"\r\n");
    }
    chunked.extend_from_slice(b"0\r\n\r\n");
    let status = raw_status_line(fixture.addr, &chunked).await?;
    assert_eq!(status, "HTTP/1.1 413 Payload Too Large");
    fixture.stop().await
}

#[tokio::test]
async fn preflights_and_wrong_methods_are_refused() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let port = fixture.addr.port();
    for path in ["/", "/api/apply", "/api/status"] {
        let preflight = fixture
            .request(Method::OPTIONS, path)
            .header(ORIGIN, format!("http://127.0.0.1:{port}"))
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization, content-type",
            )
            .body(empty())?;
        let reply = send(fixture.addr, preflight).await?;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
        assert_security_headers(&reply);
    }
    for (method, path, allow) in [
        (Method::GET, "/api/apply", "POST"),
        (Method::PUT, "/api/preview", "POST"),
        (Method::DELETE, "/api/status", "GET"),
        (Method::POST, "/", "GET"),
    ] {
        let request = fixture
            .authorized(method.clone(), path)
            .header(CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from("{}")))?;
        let reply = send(fixture.addr, request).await?;
        assert_eq!(
            reply.status,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} {path}"
        );
        assert_eq!(reply.header("allow"), Some(allow));
    }
    fixture.stop().await
}

#[tokio::test]
async fn static_assets_are_embedded_with_their_types_and_headers() -> TestResult {
    let fixture = Fixture::without_daemon().await?;
    for (path, content_type, needle) in [
        ("/", "text/html; charset=utf-8", &b"/app.js"[..]),
        ("/app.js", "text/javascript; charset=utf-8", b"token"),
        (
            "/app.css",
            "text/css; charset=utf-8",
            b"prefers-color-scheme",
        ),
        ("/remap-mark.svg", "image/svg+xml", b"<svg"),
    ] {
        let reply = send(
            fixture.addr,
            fixture.request(Method::GET, path).body(empty())?,
        )
        .await?;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.header("content-type"), Some(content_type));
        assert!(
            reply
                .body
                .windows(needle.len())
                .any(|window| window == needle)
        );
        assert_security_headers(&reply);
    }
    for path in [
        "/index.html",
        "/app.ts",
        "/main.ts",
        "/api",
        "/../Cargo.toml",
    ] {
        let reply = send(
            fixture.addr,
            fixture.request(Method::GET, path).body(empty())?,
        )
        .await?;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_security_headers(&reply);
    }
    fixture.stop().await
}

#[tokio::test]
async fn an_unreachable_daemon_is_503_with_its_hint() -> TestResult {
    let fixture = Fixture::without_daemon().await?;
    for path in ["/api/status", "/api/mappings"] {
        let reply = fixture.get(path).await?;
        assert_eq!(reply.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let diagnostic = reply.json()?;
        assert_eq!(diagnostic["code"], "E_DAEMON_UNAVAILABLE");
        assert!(
            diagnostic["hint"]
                .as_str()
                .is_some_and(|hint| hint.contains("remap doctor"))
        );
        assert_security_headers(&reply);
    }
    fixture.stop().await
}

#[tokio::test]
async fn connections_beyond_32_wait_for_a_free_slot() -> TestResult {
    let fixture = Fixture::without_daemon().await?;
    let mut idle = Vec::new();
    for _connection in 0..32 {
        let mut stream = TcpStream::connect(fixture.addr).await?;
        // A partial request holds the connection open in hyper's reader.
        stream.write_all(b"GET / HTTP/1.1\r\n").await?;
        idle.push(stream);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let request = || fixture.request(Method::GET, "/app.css").body(empty());
    let waiting =
        tokio::time::timeout(Duration::from_millis(400), send(fixture.addr, request()?)).await;
    assert!(waiting.is_err(), "a 33rd connection was served at once");
    drop(idle.pop());
    let served =
        tokio::time::timeout(Duration::from_secs(3), send(fixture.addr, request()?)).await??;
    assert_eq!(served.status, StatusCode::OK);
    drop(idle);
    fixture.stop().await
}

#[tokio::test]
async fn slow_headers_and_bodies_are_cut_off() -> TestResult {
    let fixture = Fixture::start(None).await?;
    let headers = async {
        let mut stream = TcpStream::connect(fixture.addr).await?;
        stream.write_all(b"GET / HTTP/1.1\r\nHost: ").await?;
        let started = tokio::time::Instant::now();
        let mut buffer = [0_u8; 256];
        let _read = tokio::io::AsyncReadExt::read(&mut stream, &mut buffer).await;
        Ok::<_, Box<dyn std::error::Error>>(started.elapsed())
    };
    let partial = format!(
        "POST /api/preview HTTP/1.1\r\nHost: {}\r\nAuthorization: Bearer {}\r\n\
         Content-Type: application/json\r\nContent-Length: 20\r\n\r\n{{",
        fixture.host(),
        fixture.token
    );
    let body = raw_status_line(fixture.addr, partial.as_bytes());
    let (headers, body) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(headers, body)
    })
    .await?;
    let waited = headers?;
    assert!(waited >= Duration::from_secs(9), "closed after {waited:?}");
    assert_eq!(body?, "HTTP/1.1 408 Request Timeout");
    fixture.stop().await
}

#[tokio::test]
async fn shutdown_stops_listening() -> TestResult {
    let fixture = Fixture::without_daemon().await?;
    let addr = fixture.addr;
    fixture.stop().await?;
    assert!(TcpStream::connect(addr).await.is_err());
    Ok(())
}
