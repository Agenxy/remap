// SPDX-License-Identifier: GPL-3.0-or-later
//! A peer-machine mapping through a live daemon (ADR-0033): its allocated
//! address reaches the DNS answer through the runtime snapshot, and status
//! reports its listener, which binds only the reserved address.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, Query};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use remap_network::{DnsRuntimeConfig, GatewayRuntimeConfig};
use remap_protocol::{
    Change, Command, CommandResult, ControlClient, ControlPaths, HostPolicy, PeerMachineListeners,
    Surface,
};
use remapd::DaemonConfig;
use tokio::net::{TcpListener, UdpSocket};

type TestResult = Result<(), Box<dyn Error>>;

async fn unused_address() -> Result<SocketAddr, Box<dyn Error>> {
    for _attempt in 0..32 {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = tcp.local_addr()?;
        if let Ok(udp) = UdpSocket::bind(address).await {
            drop(udp);
            drop(tcp);
            return Ok(address);
        }
    }
    Err("no shared UDP/TCP test port was available".into())
}

async fn answer(dns: SocketAddr, name: &str, kind: RecordType) -> Result<Message, Box<dyn Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii(name)?, kind));
    socket.send_to(&query.to_vec()?, dns).await?;
    let mut buffer = [0_u8; 4096];
    let (length, _from) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;
    Ok(Message::from_vec(&buffer[..length])?)
}

async fn listeners(client: &ControlClient) -> Result<PeerMachineListeners, Box<dyn Error>> {
    for _attempt in 0..200 {
        if let CommandResult::Status(status) = client.execute(Command::Status).await?
            && let Some(listeners) = status.peer_machine_listeners
        {
            return Ok(listeners);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    Err("status never reported the peer-machine listener".into())
}

#[tokio::test]
async fn the_daemon_answers_the_address_and_reports_the_listener() -> TestResult {
    let directory = tempfile::tempdir()?;
    let paths = ControlPaths::under(directory.path().join("data"));
    // The upstream is never asked: only the mapped name is queried.
    let silent = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let dns = unused_address().await?;
    let mut config = DaemonConfig::new(paths.clone());
    config.dns = Some(DnsRuntimeConfig::new(dns, vec![silent.local_addr()?]));
    config.gateway = Some(GatewayRuntimeConfig::new(unused_address().await?));
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let daemon = tokio::spawn(remapd::serve_until(config, async {
        let _done = stopped.await;
    }));
    for _attempt in 0..200 {
        if paths.socket().exists() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let client = ControlClient::new(paths.socket(), Surface::Probe, "0.2.0");
    let address = Ipv4Addr::new(127, 77, 0, 1);
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await?
        .local_addr()?
        .port();
    let bindable = std::net::TcpListener::bind((address, port)).is_ok();
    client
        .execute(Command::Apply {
            expected_revision: 0,
            operation_id: "8d1f6c62-3b0e-4f2a-9c47-5e8a1b2d3c4f".to_owned(),
            changes: vec![Change::Set {
                pattern: "pro.test".to_owned(),
                target: format!("supgang://a8a37e32?ssh={port}"),
                host_policy: HostPolicy::UseUpstream,
                enabled: None,
                landing: None,
            }],
        })
        .await?;

    let mut answered = None;
    for _attempt in 0..200 {
        let message = answer(dns, "pro.test.", RecordType::A).await?;
        if let Some(RData::A(A(found))) = message.answers.first().map(|record| &record.data) {
            answered = Some(*found);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(answered, Some(address));
    assert_eq!(
        answer(dns, "pro.test.", RecordType::AAAA).await?.answers,
        Vec::new()
    );

    let listeners = listeners(&client).await?;
    assert_eq!(listeners.listening + listeners.not_listening, 1);
    if bindable {
        assert_eq!(listeners.listening, 1, "{listeners:?}");
    } else {
        let [failure] = listeners.failures.as_slice() else {
            return Err(format!("expected one failure: {listeners:?}").into());
        };
        assert_eq!(failure.pattern, "pro.test");
        assert_eq!(failure.service, "ssh");
        assert_eq!(failure.address, "127.77.0.1");
        assert_eq!(failure.port, port);
        assert_eq!(failure.cause, "address-not-reserved");
    }

    let _sent = stop.send(());
    daemon.await??;
    Ok(())
}
