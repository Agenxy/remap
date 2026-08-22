//! Live DNS/runtime proofs against one authoritative daemon.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use remap_network::DnsRuntimeConfig;
use remap_network::GatewayRuntimeConfig;
use remap_protocol::{
    Change, Command, CommandResult, ControlClient, ControlPaths, HealthChallengeResult, HostPolicy,
    Surface,
};
use remapd::DaemonConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const OP_CREATE: &str = "74e0ef2f-5644-4546-a75d-0c8f74618740";
const OP_UPDATE: &str = "2161ae04-c18b-498e-ac11-6554356be7bb";
const OP_GATEWAY: &str = "027d311f-ac7e-45d8-84bd-75d996288215";
const HEALTH_NONCE: &str = "00112233445566778899aabbccddeeff";

#[tokio::test]
async fn daemon_publishes_atomic_dns_updates_and_forwards_unmapped_names()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_address = upstream.local_addr()?;
    let upstream_task = tokio::spawn(serve_upstream(upstream, 256));
    let dns_address = unused_dns_address().await?;
    let mut config = DaemonConfig::new(paths.clone());
    config.dns = Some(DnsRuntimeConfig::new(dns_address, vec![upstream_address]));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(config, async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;

    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.1.0");
    client
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: OP_CREATE.to_owned(),
            changes: vec![Change::Set {
                pattern: "safari.test".to_owned(),
                target: "10.0.0.8".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
            }],
        })
        .await?;
    wait_for_answer(dns_address, "safari.test", Ipv4Addr::new(10, 0, 0, 8)).await?;

    client
        .execute(Command::Apply {
            expected_revision: 1,
            operation_id: OP_UPDATE.to_owned(),
            changes: vec![Change::Set {
                pattern: "safari.test".to_owned(),
                target: "10.0.0.9".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
            }],
        })
        .await?;
    wait_for_answer(dns_address, "safari.test", Ipv4Addr::new(10, 0, 0, 9)).await?;
    let forwarded = query_a(dns_address, "public.example").await?;
    assert_eq!(first_ipv4(&forwarded), Some(Ipv4Addr::new(203, 0, 113, 7)));

    let _sent = stop_sender.send(());
    daemon.await??;
    upstream_task.abort();
    assert!(!paths.socket().exists());
    let rebound = UdpSocket::bind(dns_address).await?;
    drop(rebound);
    Ok(())
}

#[tokio::test]
async fn dns_bind_failure_releases_control_authority() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let occupied = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let occupied_address = occupied.local_addr()?;
    let upstream = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53_053);
    let mut config = DaemonConfig::new(paths.clone());
    config.dns = Some(DnsRuntimeConfig::new(occupied_address, vec![upstream]));

    let error = remapd::serve_until(config, async {})
        .await
        .err()
        .ok_or_else(|| std::io::Error::other("an occupied DNS listener was accepted"))?;
    assert_eq!(error.code, "E_DNS_IO");
    assert!(!paths.socket().exists());

    drop(occupied);
    remapd::serve_until(DaemonConfig::new(paths.clone()), async {}).await?;
    assert!(!paths.socket().exists());
    Ok(())
}

#[tokio::test]
async fn an_idle_tcp_client_cannot_starve_udp_dns_capacity()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_address = upstream.local_addr()?;
    let upstream_task = tokio::spawn(serve_upstream(upstream, 8));
    let dns_address = unused_dns_address().await?;
    let mut dns = DnsRuntimeConfig::new(dns_address, vec![upstream_address]);
    dns.request_limit = 1;
    let mut config = DaemonConfig::new(paths.clone());
    config.dns = Some(dns);
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(config, async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.2.0");
    client
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: OP_CREATE.to_owned(),
            changes: vec![Change::Set {
                pattern: "capacity.test".to_owned(),
                target: "10.0.0.8".to_owned(),
                host_policy: HostPolicy::PreserveClient,
                enabled: None,
            }],
        })
        .await?;

    let idle_tcp = TcpStream::connect(dns_address).await?;
    wait_for_answer(dns_address, "capacity.test", Ipv4Addr::new(10, 0, 0, 8)).await?;
    drop(idle_tcp);

    let _sent = stop_sender.send(());
    daemon.await??;
    upstream_task.abort();
    Ok(())
}

#[tokio::test]
async fn daemon_routes_a_mapped_http_name_to_its_upstream() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let upstream = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_address = upstream.local_addr()?;
    let upstream_task = tokio::spawn(async move {
        let Ok((mut stream, _peer)) = upstream.accept().await else {
            return;
        };
        let mut request = vec![0_u8; 4_096];
        let Ok(size) = stream.read(&mut request).await else {
            return;
        };
        if !String::from_utf8_lossy(&request[..size]).starts_with("GET /status HTTP/1.1") {
            return;
        }
        let _written = stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nRemap is live",
            )
            .await;
    });
    let gateway_address = unused_tcp_address().await?;
    let mut config = DaemonConfig::new(paths.clone());
    config.gateway = Some(GatewayRuntimeConfig::new(gateway_address));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(config, async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.1.0");
    client
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: OP_GATEWAY.to_owned(),
            changes: vec![Change::Set {
                pattern: "remap.test".to_owned(),
                target: format!("http://{upstream_address}"),
                host_policy: HostPolicy::UseUpstream,
                enabled: None,
            }],
        })
        .await?;

    let response = wait_for_gateway(gateway_address).await?;
    assert!(response.starts_with("HTTP/1.1 200"));
    assert!(response.ends_with("Remap is live"));

    let _sent = stop_sender.send(());
    daemon.await??;
    upstream_task.await?;
    assert!(!paths.socket().exists());
    Ok(())
}

#[tokio::test]
async fn one_control_identity_authenticates_udp_tcp_dns_and_http()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_address = upstream.local_addr()?;
    let upstream_task = tokio::spawn(serve_upstream(upstream, 32));
    let dns_address = unused_dns_address().await?;
    let gateway_address = unused_tcp_address().await?;
    let mut config = DaemonConfig::new(paths.clone());
    config.dns = Some(DnsRuntimeConfig::new(dns_address, vec![upstream_address]));
    config.gateway = Some(GatewayRuntimeConfig::new(gateway_address));
    let (stop_sender, stop_receiver) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(async move {
        remapd::serve_until(config, async {
            let _result = stop_receiver.await;
        })
        .await
    });
    wait_for_socket(paths.socket()).await?;
    let client = ControlClient::new(paths.socket(), Surface::Probe, env!("CARGO_PKG_VERSION"));
    let challenge = health_challenge(&client).await?;
    assert_eq!(challenge.daemon_version, env!("CARGO_PKG_VERSION"));
    assert_ne!(challenge.dns_proof, challenge.http_proof);
    assert_eq!(
        query_txt_udp(dns_address, HEALTH_NONCE).await?,
        challenge.dns_proof
    );
    assert_eq!(
        query_txt_tcp(dns_address, HEALTH_NONCE).await?,
        challenge.dns_proof
    );

    let response = query_health_http(gateway_address, HEALTH_NONCE).await?;
    assert!(response.starts_with("HTTP/1.1 200 OK\r\n"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("cache-control: no-store\r\n")
    );
    assert!(response.ends_with(&challenge.http_proof));
    let unrelated = query_raw_http(
        gateway_address,
        b"GET /.well-known/remap/health/00112233445566778899aabbccddeeff HTTP/1.1\r\nHost: unrelated.invalid\r\nConnection: close\r\n\r\n",
    )
    .await?;
    assert!(unrelated.starts_with("HTTP/1.1 404"));

    let malformed = client
        .execute(Command::HealthChallenge {
            nonce: "00112233445566778899AABBCCDDEEFF".to_owned(),
        })
        .await
        .err()
        .ok_or("uppercase health nonce was accepted")?;
    assert_eq!(malformed.code, "E_HEALTH_CHALLENGE");

    let _sent = stop_sender.send(());
    daemon.await??;
    upstream_task.abort();
    Ok(())
}

async fn health_challenge(
    client: &ControlClient,
) -> Result<HealthChallengeResult, Box<dyn std::error::Error>> {
    let result = client
        .execute(Command::HealthChallenge {
            nonce: HEALTH_NONCE.to_owned(),
        })
        .await?;
    let CommandResult::HealthChallenge(challenge) = result else {
        return Err("health challenge returned the wrong result".into());
    };
    Ok(challenge)
}

async fn serve_upstream(socket: UdpSocket, request_limit: usize) {
    let mut buffer = vec![0_u8; 65_535];
    for _request in 0..request_limit {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let Ok(request) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        let mut response = Message::response(request.id, request.op_code);
        response.metadata.recursion_available = true;
        response.add_queries(request.queries.iter().cloned());
        if let Some(query) = request.queries.first() {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
            ));
        }
        let Ok(encoded) = response.to_vec() else {
            continue;
        };
        let _written = socket.send_to(&encoded, peer).await;
    }
}

async fn wait_for_answer(
    server: SocketAddr,
    name: &str,
    expected: Ipv4Addr,
) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        if first_ipv4(&query_a(server, name).await?) == Some(expected) {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err(format!("DNS never published {name} -> {expected}").into())
}

async fn query_a(server: SocketAddr, name: &str) -> Result<Message, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut request = Message::new(7, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    socket.send_to(&request.to_vec()?, server).await?;
    let mut buffer = vec![0_u8; 65_535];
    let (size, _peer) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await??;
    Ok(Message::from_vec(&buffer[..size])?)
}

async fn query_txt_udp(
    server: SocketAddr,
    nonce: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = health_dns_query(nonce)?;
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    socket.send_to(&request, server).await?;
    let mut buffer = vec![0_u8; 4_096];
    let (size, peer) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await??;
    assert_eq!(peer, server);
    txt_proof(&Message::from_vec(&buffer[..size])?)
}

async fn query_txt_tcp(
    server: SocketAddr,
    nonce: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    let request = health_dns_query(nonce)?;
    let mut stream = TcpStream::connect(server).await?;
    let length = u16::try_from(request.len())?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(&request).await?;
    let response_length = stream.read_u16().await?;
    let mut response = vec![0_u8; usize::from(response_length)];
    stream.read_exact(&mut response).await?;
    txt_proof(&Message::from_vec(&response)?)
}

fn health_dns_query(nonce: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut request = Message::new(0x524d, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(
        Name::from_ascii(format!("r{nonce}._health.remap.invalid."))?,
        RecordType::TXT,
    ));
    Ok(request.to_vec()?)
}

fn txt_proof(message: &Message) -> Result<String, Box<dyn std::error::Error>> {
    let Some(record) = message.answers.first() else {
        return Err("health DNS response had no answer".into());
    };
    let RData::TXT(value) = &record.data else {
        return Err("health DNS response was not TXT".into());
    };
    if value.txt_data.len() != 1 {
        return Err("health DNS response was not one TXT string".into());
    }
    Ok(String::from_utf8(value.txt_data[0].to_vec())?)
}

fn first_ipv4(message: &Message) -> Option<Ipv4Addr> {
    message
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(A(address)) => Some(*address),
            _ => None,
        })
}

async fn unused_dns_address() -> Result<SocketAddr, std::io::Error> {
    for _attempt in 0..32 {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        if let Ok(udp) = UdpSocket::bind(address).await {
            drop(udp);
            drop(tcp);
            return Ok(address);
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "no shared UDP/TCP test port was available",
    ))
}

async fn unused_tcp_address() -> Result<SocketAddr, std::io::Error> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    drop(listener);
    Ok(address)
}

async fn wait_for_gateway(address: SocketAddr) -> Result<String, Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        let mut browser = TcpStream::connect(address).await?;
        browser
            .write_all(b"GET /status HTTP/1.1\r\nHost: remap.test\r\nConnection: close\r\n\r\n")
            .await?;
        let mut response = Vec::new();
        tokio::time::timeout(Duration::from_secs(2), browser.read_to_end(&mut response)).await??;
        let response = String::from_utf8(response)?;
        if response.starts_with("HTTP/1.1 200") {
            return Ok(response);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("the gateway never published remap.test".into())
}

async fn query_health_http(
    address: SocketAddr,
    nonce: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    query_raw_http(
        address,
        format!(
            "GET /.well-known/remap/health/{nonce} HTTP/1.1\r\nHost: _health.remap.invalid\r\nConnection: close\r\n\r\n"
        )
        .as_bytes(),
    )
    .await
}

async fn query_raw_http(
    address: SocketAddr,
    request: &[u8],
) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(address).await?;
    stream.write_all(request).await?;
    let mut response = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response)).await??;
    Ok(String::from_utf8(response)?)
}

async fn wait_for_socket(path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    for _attempt in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("daemon socket did not appear within one second".into())
}
