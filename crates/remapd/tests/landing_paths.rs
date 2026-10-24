//! Landing paths preserve the origin root through the real daemon gateway.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use remap_network::GatewayRuntimeConfig;
use remap_protocol::{Command, ControlClient, ControlPaths, Surface};
use remapd::DaemonConfig;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};

type TestResult = Result<(), Box<dyn Error>>;

async fn ask(
    address: SocketAddr,
    method: &str,
    path: &str,
    name: &str,
) -> Result<String, Box<dyn Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream
        .write_all(
            format!("{method} {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut bytes = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes)).await??;
    Ok(String::from_utf8(bytes)?)
}

async fn origin() -> Result<(SocketAddr, tokio::task::JoinHandle<()>), Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut head = Vec::new();
                let mut byte = [0_u8];
                while head.len() < 16_384 && !head.ends_with(b"\r\n\r\n") {
                    if stream.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8_lossy(&head);
                let path = head.split_whitespace().nth(1).unwrap_or("bad-request");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{path}",
                    path.len()
                );
                let _sent = stream.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok((address, task))
}

async fn exercise(requests: &[(&str, &str, &str)]) -> TestResult {
    exercise_mapping(requests, None, Some("/ops/scorecard/")).await
}

async fn exercise_mapping(
    requests: &[(&str, &str, &str)],
    target: Option<&str>,
    landing: Option<&str>,
) -> TestResult {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let (upstream, origin_task) = origin().await?;
    let reservation = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let gateway = reservation.local_addr()?;
    drop(reservation);
    let mut config = DaemonConfig::new(paths.clone());
    config.gateway = Some(GatewayRuntimeConfig::new(gateway));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(remapd::serve_until(config, async {
        let _done = stopped.await;
    }));
    for _ in 0..100 {
        if paths.socket().exists() {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let command: Command = serde_json::from_value(json!({
        "kind": "apply", "expected_revision": 0,
        "operation_id": "c4d1f8c7-bd38-4a5a-a8ee-bb1f36cd2851",
        "changes": [{"kind": "set", "pattern": "landing.test",
            "target": target.map_or_else(|| format!("http://{upstream}/"), str::to_owned), "host_policy": "use-upstream",
            "enabled": null, "landing": landing},
            {"kind":"set", "pattern":"ready.test", "target":format!("http://{upstream}/"),
             "host_policy":"use-upstream", "enabled":null}]
    }))?;
    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.2.0");
    client.execute(command).await?;
    // The daemon publishes complete snapshots asynchronously after committing.
    // The second mapping proves this revision is visible even when the expired
    // mapping under test must itself return 404.
    let mut published = false;
    for _ in 0..100 {
        if ask(gateway, "GET", "/", "ready.test")
            .await?
            .starts_with("HTTP/1.1 200")
        {
            published = true;
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert!(published, "the committed snapshot was not published");
    for (method, path, expected) in requests {
        let response = ask(gateway, method, path, "landing.test").await?;
        if let Some(location) = expected.strip_prefix("location: ") {
            let actual = response
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("location"))
                .map(|(_, value)| value.trim_start());
            assert_eq!(
                actual,
                Some(location.trim_end()),
                "{method} {path}: {response}"
            );
        } else {
            assert!(
                response.contains(expected) || response.to_ascii_lowercase().starts_with(expected),
                "{method} {path}: {response}"
            );
        }
        if *method == "HEAD" {
            assert!(response.ends_with("\r\n\r\n"), "HEAD redirect had a body");
        }
    }
    let _sent = stop.send(());
    daemon.await??;
    origin_task.abort();
    Ok(())
}

#[tokio::test]
async fn moved_redirects_every_method_with_original_path_and_query() -> TestResult {
    exercise_mapping(
        &[
            (
                "GET",
                "/old/path?q=a%2fb",
                "location: http://renamed.test/old/path?q=a%2fb\r\n",
            ),
            ("HEAD", "/", "http/1.1 301"),
            (
                "POST",
                "/submit?x=1",
                "location: http://renamed.test/submit?x=1\r\n",
            ),
        ],
        Some("moved://renamed.test"),
        None,
    )
    .await
}

#[tokio::test]
async fn moved_expired_mapping_is_unmatched() -> TestResult {
    exercise_mapping(
        &[("GET", "/", "http/1.1 404")],
        Some("moved://renamed.test?until=2000-01-01T00:00:00Z"),
        None,
    )
    .await
}

#[tokio::test]
async fn review_moved_options_star_uses_root_url() -> TestResult {
    exercise_mapping(
        &[("OPTIONS", "*", "location: http://renamed.test/\r\n")],
        Some("moved://renamed.test"),
        None,
    )
    .await
}

#[tokio::test]
async fn landing_root_absolute_assets_keep_their_origin_path() -> TestResult {
    exercise(&[("GET", "/bar.css", "\r\n\r\n/bar.css")]).await
}

#[tokio::test]
async fn landing_redirects_only_root_get_and_head() -> TestResult {
    exercise(&[
        ("GET", "/", "http/1.1 302"),
        ("HEAD", "/", "location: /ops/scorecard/\r\n"),
        ("POST", "/", "http/1.1 200"),
        ("GET", "/nested/page?x=y", "\r\n\r\n/nested/page?x=y"),
    ])
    .await
}

#[tokio::test]
async fn landing_preserves_the_root_query() -> TestResult {
    exercise(&[(
        "GET",
        "/?token=A%2Fb&x=1",
        "location: /ops/scorecard/?token=A%2Fb&x=1\r\n",
    )])
    .await
}
