// SPDX-License-Identifier: GPL-3.0-or-later
//! Over real UDP sockets, the DNS runtime notices when every upstream stops
//! answering, never on one lost packet, and clears the verdict as soon as an
//! upstream answers again, with or without client traffic (ADR-0036).

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use remap_network::{
    DnsRuntime, DnsRuntimeConfig, NetworkError, ResolverPlanStore, SnapshotStore,
    UpstreamFailureCause, UpstreamLivenessPolicy,
};
use tokio::net::UdpSocket;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::timeout;

type TestResult = Result<(), Box<dyn Error>>;

const ANSWER: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);

/// Thresholds scaled down so a test takes well under a second: three
/// unanswered queries spread over at least 150 ms.
const POLICY: UpstreamLivenessPolicy = UpstreamLivenessPolicy {
    min_unanswered: 3,
    min_span: Duration::from_millis(150),
    evidence_window: Duration::from_secs(30),
    probe_interval: Duration::from_millis(50),
};

struct Resolver {
    address: SocketAddr,
    plans: ResolverPlanStore,
    shutdown: watch::Sender<bool>,
    task: JoinHandle<Result<(), NetworkError>>,
}

impl Resolver {
    fn start(upstreams: Vec<SocketAddr>) -> Result<Self, Box<dyn Error>> {
        let mut config = DnsRuntimeConfig::new((Ipv4Addr::LOCALHOST, 0).into(), upstreams);
        config.io_timeout = Duration::from_millis(60);
        config.upstream_liveness = POLICY;
        let runtime = DnsRuntime::bind(&config, SnapshotStore::empty())?;
        let address = runtime.local_addr();
        let plans = runtime.resolver_plans();
        let (shutdown, receiver) = watch::channel(false);
        let task = tokio::spawn(runtime.serve(receiver));
        Ok(Self {
            address,
            plans,
            shutdown,
            task,
        })
    }

    async fn stop(self) -> TestResult {
        self.shutdown.send(true)?;
        timeout(Duration::from_secs(5), self.task).await???;
        Ok(())
    }

    /// Asks for one name nobody mapped, as a browser would, spaced so the
    /// unanswered queries span the policy's minimum.
    async fn ask_spaced(&self, count: usize) -> Result<Vec<ResponseCode>, Box<dyn Error>> {
        let mut codes = Vec::new();
        for index in 0..count {
            codes.push(query(self.address, &format!("n{index}.public.example.")).await?);
            tokio::time::sleep(Duration::from_millis(60)).await;
        }
        Ok(codes)
    }
}

/// An upstream that answers every query, or drops while `silent` is set,
/// or answers the first `refuse_first` queries with REFUSED.
struct Upstream {
    address: SocketAddr,
    silent: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}

impl Upstream {
    async fn start(silent: bool, drop_first: usize, refuse: bool) -> Result<Self, Box<dyn Error>> {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let address = socket.local_addr()?;
        let silent = Arc::new(AtomicBool::new(silent));
        let received = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve(
            socket,
            Arc::clone(&silent),
            Arc::clone(&received),
            drop_first,
            refuse,
        ));
        Ok(Self {
            address,
            silent,
            received,
            task,
        })
    }
}

impl Drop for Upstream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(
    socket: UdpSocket,
    silent: Arc<AtomicBool>,
    received: Arc<AtomicUsize>,
    drop_first: usize,
    refuse: bool,
) {
    let mut buffer = vec![0_u8; 65_535];
    loop {
        let Ok((size, peer)) = socket.recv_from(&mut buffer).await else {
            return;
        };
        let seen = received.fetch_add(1, Ordering::SeqCst);
        if silent.load(Ordering::SeqCst) || seen < drop_first {
            continue;
        }
        let Ok(request) = Message::from_vec(&buffer[..size]) else {
            continue;
        };
        let mut response = if refuse {
            Message::error_msg(request.id, request.op_code, ResponseCode::Refused)
        } else {
            Message::response(request.id, request.op_code)
        };
        response.add_queries(request.queries.iter().cloned());
        if let (false, Some(query)) = (refuse, request.queries.first()) {
            response.add_answer(Record::from_rdata(
                query.name().clone(),
                60,
                RData::A(A(ANSWER)),
            ));
        }
        let Ok(encoded) = response.to_vec() else {
            continue;
        };
        let _written = socket.send_to(&encoded, peer).await;
    }
}

async fn query(server: SocketAddr, name: &str) -> Result<ResponseCode, Box<dyn Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let mut request = Message::new(0x4c56, MessageType::Query, OpCode::Query);
    request.metadata.recursion_desired = true;
    request.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    socket.send_to(&request.to_vec()?, server).await?;
    let mut buffer = vec![0_u8; 65_535];
    let (size, _peer) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer)).await??;
    Ok(Message::from_vec(&buffer[..size])?.response_code)
}

/// A port nothing listens on, so the kernel refuses each datagram.
async fn closed_port() -> Result<SocketAddr, Box<dyn Error>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = socket.local_addr()?;
    drop(socket);
    Ok(address)
}

async fn eventually(condition: impl Fn() -> bool) -> bool {
    for _attempt in 0..200 {
        if condition() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    condition()
}

#[tokio::test]
async fn silent_upstreams_trip_the_verdict_and_an_answer_clears_it_without_clients() -> TestResult {
    let first = Upstream::start(true, 0, false).await?;
    let second = Upstream::start(true, 0, false).await?;
    let resolver = Resolver::start(vec![first.address, second.address])?;

    let codes = resolver.ask_spaced(4).await?;

    assert!(codes.iter().all(|code| *code == ResponseCode::ServFail));
    let verdict = resolver
        .plans
        .upstream_failure()
        .ok_or("silent upstreams were never judged unanswered")?;
    assert_eq!(verdict.cause, UpstreamFailureCause::TimedOut);
    assert!(verdict.unanswered_queries >= 3);
    assert!(verdict.unanswered_for >= POLICY.min_span);

    // The second upstream answers again. No client asks anything; the
    // runtime's own probe finds it and clears the verdict.
    second.silent.store(false, Ordering::SeqCst);
    assert!(eventually(|| resolver.plans.upstream_failure().is_none()).await);
    assert_eq!(
        query(resolver.address, "after.public.example.").await?,
        ResponseCode::NoError
    );
    resolver.stop().await
}

#[tokio::test]
async fn one_lost_packet_never_trips_the_verdict() -> TestResult {
    // The first datagram is lost; every later one is answered.
    let upstream = Upstream::start(false, 1, false).await?;
    let resolver = Resolver::start(vec![upstream.address])?;

    let codes = resolver.ask_spaced(5).await?;

    assert_eq!(codes[0], ResponseCode::ServFail);
    assert!(codes[1..].iter().all(|code| *code == ResponseCode::NoError));
    assert!(resolver.plans.upstream_failure().is_none());
    resolver.stop().await
}

#[tokio::test]
async fn upstreams_that_refuse_are_judged_unanswered_with_that_cause() -> TestResult {
    let refusing = Upstream::start(false, 0, true).await?;
    let closed = closed_port().await?;
    let resolver = Resolver::start(vec![refusing.address, closed])?;

    let codes = resolver.ask_spaced(4).await?;

    // The refusal itself is relayed rather than a bare failure.
    assert!(codes.iter().all(|code| *code == ResponseCode::Refused));
    let verdict = resolver
        .plans
        .upstream_failure()
        .ok_or("refusing upstreams were never judged unanswered")?;
    assert_eq!(verdict.cause, UpstreamFailureCause::Refused);
    resolver.stop().await
}

#[tokio::test]
async fn a_refusing_upstream_falls_through_to_the_next_one() -> TestResult {
    let refusing = Upstream::start(false, 0, true).await?;
    let answering = Upstream::start(false, 0, false).await?;
    let resolver = Resolver::start(vec![refusing.address, answering.address])?;

    let codes = resolver.ask_spaced(4).await?;

    assert!(codes.iter().all(|code| *code == ResponseCode::NoError));
    assert!(answering.received.load(Ordering::SeqCst) >= 4);
    assert!(resolver.plans.upstream_failure().is_none());
    resolver.stop().await
}

#[tokio::test]
async fn publishing_a_different_upstream_set_starts_without_a_verdict() -> TestResult {
    let silent = Upstream::start(true, 0, false).await?;
    let resolver = Resolver::start(vec![silent.address])?;
    let _codes = resolver.ask_spaced(4).await?;
    assert!(resolver.plans.upstream_failure().is_some());

    // The same set republished, as a re-arm does, keeps the verdict; a VPN's
    // resolver, a different set, starts clean and answers.
    resolver.plans.publish(2, vec![silent.address])?;
    assert!(resolver.plans.upstream_failure().is_some());
    let vpn = Upstream::start(false, 0, false).await?;
    resolver.plans.publish(3, vec![vpn.address])?;
    assert!(resolver.plans.upstream_failure().is_none());
    assert_eq!(
        query(resolver.address, "via.vpn.example.").await?,
        ResponseCode::NoError
    );
    resolver.stop().await
}
