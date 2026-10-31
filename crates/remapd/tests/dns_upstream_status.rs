// SPDX-License-Identifier: GPL-3.0-or-later
//! `remap status`, `remap doctor`, and MCP read the daemon's status, which
//! says "upstream DNS not answering" with a cause while every upstream
//! resolver has stopped answering real UDP queries, and stops saying it once
//! one answers again (ADR-0036).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use remap_network::{DnsRuntimeConfig, UpstreamLivenessPolicy};
use remap_protocol::{
    Command, CommandResult, ControlClient, ControlPaths, RegistryStatus, Surface,
};
use remapd::DaemonConfig;
use tokio::net::{TcpListener, UdpSocket};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[tokio::test]
async fn status_says_upstream_dns_is_not_answering_until_an_upstream_answers() -> TestResult {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    let upstream = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let upstream_address = upstream.local_addr()?;
    let silent = Arc::new(AtomicBool::new(true));
    let upstream_task = tokio::spawn(serve_upstream(upstream, Arc::clone(&silent)));
    let dns_address = unused_dns_address().await?;
    let mut dns = DnsRuntimeConfig::new(dns_address, vec![upstream_address]);
    dns.io_timeout = Duration::from_millis(50);
    dns.upstream_liveness = UpstreamLivenessPolicy {
        min_unanswered: 3,
        min_span: Duration::from_millis(100),
        evidence_window: Duration::from_secs(30),
        probe_interval: Duration::from_millis(50),
    };
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
    assert_eq!(status(&client).await?.dns_upstream, None);

    for index in 0..4 {
        let _unanswered = query_a(dns_address, &format!("n{index}.public.example.")).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let reported = status(&client)
        .await?
        .dns_upstream
        .ok_or("status never said upstream DNS stopped answering")?;
    assert_eq!(reported.code, "E_DNS_UPSTREAM_UNANSWERED");
    assert!(reported.message.starts_with("upstream DNS not answering"));
    assert!(reported.message.contains("timed out"));
    assert_eq!(
        reported.context.get("cause").map(String::as_str),
        Some("timed_out")
    );
    assert!(!format!("{reported:?}").contains(&upstream_address.port().to_string()));

    silent.store(false, Ordering::SeqCst);
    let mut cleared = false;
    for _attempt in 0..200 {
        if status(&client).await?.dns_upstream.is_none() {
            cleared = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(cleared, "an answering upstream never cleared the status");
    let answered = query_a(dns_address, "after.public.example.").await?;
    assert_eq!(answered.answers.len(), 1);

    let _sent = stop_sender.send(());
    daemon.await??;
    upstream_task.abort();
    Ok(())
}

async fn status(client: &ControlClient) -> Result<RegistryStatus, Box<dyn std::error::Error>> {
    match client.execute(Command::Status).await? {
        CommandResult::Status(status) => Ok(status),
        _ => Err("status returned another result".into()),
    }
}

async fn serve_upstream(socket: UdpSocket, silent: Arc<AtomicBool>) {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        if silent.load(Ordering::SeqCst) {
            continue;
        }
        let Ok(request) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        let mut response = Message::response(request.id, request.op_code);
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

async fn query_a(server: SocketAddr, name: &str) -> Result<Message, Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut request = Message::new(9, MessageType::Query, OpCode::Query);
    request.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    socket.send_to(&request.to_vec()?, server).await?;
    let mut buffer = vec![0_u8; 65_535];
    let (size, _peer) =
        tokio::time::timeout(Duration::from_secs(1), socket.recv_from(&mut buffer)).await??;
    Ok(Message::from_vec(&buffer[..size])?)
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

async fn wait_for_socket(path: &std::path::Path) -> TestResult {
    for _attempt in 0..100 {
        if path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("daemon socket did not appear within one second".into())
}
