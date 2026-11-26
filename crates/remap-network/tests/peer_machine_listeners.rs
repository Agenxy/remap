// SPDX-License-Identifier: GPL-3.0-or-later
//! A peer machine's listeners carry each TCP connection through a stand-in
//! for Supgang's version-1 stream endpoint (ADR-0033), follow registry
//! changes without a restart, name every refusal, and never bind anything
//! but the mapping's own address.
//!
//! The reserved alias cannot exist on a test machine, so most tests bind
//! 127.0.0.1 on an ephemeral port through the runtime's substitute address.

use std::error::Error;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use remap_core::{Mapping, MappingTarget, NamePattern, RegistrySnapshot};
use remap_network::{
    DnsDecision, DnsEngine, DnsPolicy, ListenerCause, ListenerReport, ListenerSource,
    ListenerState, PeerMachineAdoptError, PeerMachineListeners, PeerMachineStatus,
    PeerResolveError, PeerResolver, ResolvedPeerService, SnapshotStore, SupgangStreams,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener};
use tokio::sync::watch;
use tokio::time::{sleep, timeout};

type TestResult = Result<(), Box<dyn Error>>;
type Lines = Arc<Mutex<Vec<String>>>;

const NODE: [u8; 32] = [0x42; 32];
const FINGERPRINT: &str = "a8a37e32";
const WAIT: Duration = Duration::from_secs(5);

fn node_id() -> String {
    "42".repeat(32)
}

/// Resolves the one fingerprint `a8a37e32` to `NODE`, and nothing else.
#[derive(Debug)]
struct Fleet;

impl PeerResolver for Fleet {
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
        Box::pin(async { Err(PeerResolveError::NoService) })
    }

    fn resolve_node<'a>(
        &'a self,
        peer: &'a str,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<[u8; 32], PeerResolveError>> + Send + 'a>,
    > {
        Box::pin(async move {
            if peer == FINGERPRINT {
                Ok(NODE)
            } else {
                Err(PeerResolveError::Refused("unknown peer".into()))
            }
        })
    }
}

/// A stand-in version-1 endpoint: it checks each frame and pipes a stream
/// for an exposed service of `NODE` to its upstream, or refuses it.
fn endpoint(socket: &Path, exposed: Vec<(&'static str, SocketAddr)>) -> Result<(), Box<dyn Error>> {
    let listener = UnixListener::bind(socket)?;
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            let exposed = exposed.clone();
            tokio::spawn(async move {
                let mut frame = [0_u8; 61];
                if stream.read_exact(&mut frame).await.is_err() {
                    return;
                }
                let valid = frame[..4] == 57_u32.to_be_bytes()
                    && &frame[4..12] == b"SUPGIPC1"
                    && frame[12] == 0x07
                    && frame[13..45] == NODE;
                let name: String = frame[45..]
                    .iter()
                    .take_while(|byte| **byte != 0)
                    .map(|byte| char::from(*byte))
                    .collect();
                let target = exposed
                    .iter()
                    .find(|(service, _)| *service == name)
                    .map(|(_, address)| *address);
                let (Some(target), true) = (target, valid) else {
                    let _sent = reply(&mut stream, br#"{"response":"error","message":"no"}"#).await;
                    return;
                };
                let Ok(mut upstream) = TcpStream::connect(target).await else {
                    return;
                };
                if reply(&mut stream, br#"{"response":"connected"}"#)
                    .await
                    .is_ok()
                {
                    let _copied = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                }
            });
        }
    });
    Ok(())
}

async fn reply(stream: &mut tokio::net::UnixStream, body: &[u8]) -> std::io::Result<()> {
    let length = u32::try_from(body.len()).map_err(std::io::Error::other)?;
    stream.write_all(&length.to_be_bytes()).await?;
    stream.write_all(body).await
}

/// An SSH-like upstream: it speaks first with a banner, then echoes.
async fn banner_upstream() -> Result<SocketAddr, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        while let Ok((mut stream, _peer)) = listener.accept().await {
            tokio::spawn(async move {
                if stream.write_all(b"SSH-2.0-Stand-in\r\n").await.is_err() {
                    return;
                }
                let mut buffer = [0_u8; 256];
                while let Ok(read) = stream.read(&mut buffer).await {
                    if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    Ok(address)
}

fn machine(pattern: &str, target: &str, address: Ipv4Addr) -> Result<Mapping, Box<dyn Error>> {
    Ok(Mapping::new(
        NamePattern::parse(pattern)?,
        target.parse::<MappingTarget>()?,
    )
    .with_peer_address(Some(address)))
}

struct Running {
    snapshots: SnapshotStore,
    status: PeerMachineStatus,
    runtime: PeerMachineListeners,
    socket: std::path::PathBuf,
    lines: Lines,
    _shutdown: watch::Sender<bool>,
    _directory: tempfile::TempDir,
}

impl Running {
    fn publish(&self, revision: u64, mappings: Vec<Mapping>) -> TestResult {
        assert!(
            self.snapshots
                .publish(RegistrySnapshot::new(revision, mappings)?)
        );
        Ok(())
    }

    async fn reports_where(
        &self,
        accept: impl Fn(&[ListenerReport]) -> bool,
    ) -> Result<Vec<ListenerReport>, Box<dyn Error>> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let reports = self.status.reports();
            if accept(&reports) {
                return Ok(reports);
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("listeners never settled: {reports:?}").into());
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn listening(&self, count: usize) -> Result<Vec<SocketAddr>, Box<dyn Error>> {
        let reports = self
            .reports_where(|reports| {
                reports.len() == count
                    && reports
                        .iter()
                        .all(|report| matches!(report.state, ListenerState::Listening(_)))
            })
            .await?;
        Ok(reports
            .iter()
            .filter_map(|report| match report.state {
                ListenerState::Listening(local) => Some(local),
                ListenerState::NotListening(_) => None,
            })
            .collect())
    }

    async fn logged(&self, fragment: &str) -> Result<String, Box<dyn Error>> {
        let deadline = tokio::time::Instant::now() + WAIT;
        loop {
            let found = self
                .lines
                .lock()
                .map_err(|_| "log poisoned")?
                .iter()
                .find(|line| line.contains(fragment))
                .cloned();
            if let Some(line) = found {
                return Ok(line);
            }
            if tokio::time::Instant::now() > deadline {
                return Err(format!("nothing logged {fragment}").into());
            }
            sleep(Duration::from_millis(10)).await;
        }
    }
}

struct Setup {
    exposed: Vec<(&'static str, SocketAddr)>,
    with_endpoint: bool,
    resolver: Option<Arc<dyn PeerResolver>>,
    substitute: bool,
    source: ListenerSource,
    idle: Option<Duration>,
    /// Look the endpoint up for every connection and start it later.
    lookup: bool,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            exposed: Vec::new(),
            with_endpoint: true,
            resolver: None,
            substitute: true,
            source: ListenerSource::Bind,
            idle: None,
            lookup: false,
        }
    }
}

fn start(setup: Setup) -> Result<Running, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let socket = directory.path().join("control.sock");
    if !setup.lookup {
        endpoint(&socket, setup.exposed)?;
    }
    let snapshots = SnapshotStore::empty();
    let status = PeerMachineStatus::default();
    let lines: Lines = Arc::default();
    let sink = Arc::clone(&lines);
    let mut runtime = PeerMachineListeners::new(snapshots.clone(), status.clone())
        .with_supgang_streams(
            setup
                .with_endpoint
                .then(|| SupgangStreams::at(socket.clone())),
        )
        .with_listener_source(setup.source)
        .with_peer_resolver(setup.resolver)
        .with_log(Arc::new(move |line| {
            if let Ok(mut lines) = sink.lock() {
                lines.push(line.to_owned());
            }
        }));
    if setup.substitute {
        runtime = runtime.with_substitute_address(Ipv4Addr::LOCALHOST)?;
    }
    if let Some(idle) = setup.idle {
        runtime = runtime.with_idle_timeout(idle);
    }
    if setup.lookup {
        runtime = runtime.with_supgang_socket(socket.clone());
    }
    let (shutdown, receiver) = watch::channel(false);
    tokio::spawn(runtime.clone().serve(receiver));
    Ok(Running {
        snapshots,
        status,
        runtime,
        socket,
        lines,
        _shutdown: shutdown,
        _directory: directory,
    })
}

async fn standard() -> Result<(Running, SocketAddr), Box<dyn Error>> {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        with_endpoint: true,
        resolver: Some(Arc::new(Fleet)),
        substitute: true,
        ..Setup::default()
    })?;
    Ok((running, upstream))
}

async fn round_trip(local: SocketAddr) -> Result<(), Box<dyn Error>> {
    let mut client = TcpStream::connect(local).await?;
    let mut banner = [0_u8; 18];
    timeout(WAIT, client.read_exact(&mut banner)).await??;
    assert_eq!(&banner, b"SSH-2.0-Stand-in\r\n");
    client.write_all(b"hello peer").await?;
    let mut echoed = [0_u8; 10];
    timeout(WAIT, client.read_exact(&mut echoed)).await??;
    assert_eq!(&echoed, b"hello peer");
    Ok(())
}

/// Reads until the gateway closes the connection, which it does at once
/// when no stream opens.
async fn closed_without_bytes(local: SocketAddr) -> TestResult {
    let mut client = TcpStream::connect(local).await?;
    let mut buffer = Vec::new();
    timeout(WAIT, client.read_to_end(&mut buffer)).await??;
    assert_eq!(buffer, Vec::<u8>::new());
    Ok(())
}

#[tokio::test]
async fn a_connection_rides_the_stream_both_ways() -> TestResult {
    let (running, _upstream) = standard().await?;
    let address = Ipv4Addr::new(127, 77, 0, 1);
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            address,
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    let report = &running.status.reports()[0];
    assert_eq!(
        (report.pattern.as_str(), report.service.as_str()),
        ("pro.test", "ssh")
    );
    assert_eq!((report.address, report.port), (address, 22));
    round_trip(local).await?;
    // Each connection opens its own stream.
    round_trip(local).await
}

#[tokio::test]
async fn a_fingerprint_is_resolved_for_each_connection() -> TestResult {
    let (running, _upstream) = standard().await?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{FINGERPRINT}?ssh=22"),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    round_trip(local).await
}

#[tokio::test]
async fn refusals_close_the_connection_log_service_and_cause_and_count() -> TestResult {
    let (running, upstream) = standard().await?;
    let address = Ipv4Addr::new(127, 77, 0, 1);
    running.publish(
        1,
        vec![
            // `web` is not exposed by the peer.
            machine(
                "pro.test",
                &format!("supgang://{}?web=8080", node_id()),
                address,
            )?,
            // Supgang knows no peer by this fingerprint.
            machine(
                "gone.test",
                "supgang://0badf00d?ssh=22",
                Ipv4Addr::new(127, 77, 0, 2),
            )?,
        ],
    )?;
    let locals = running.listening(2).await?;
    for local in &locals {
        closed_without_bytes(*local).await?;
    }
    let refused = running.logged("Service: web").await?;
    assert!(refused.contains("Cause: refused"), "{refused}");
    let unknown = running.logged("Cause: unknown-peer").await?;
    assert!(unknown.contains("Service: ssh"), "{unknown}");
    // The owner reads which causes occurred from status, not the log.
    assert_eq!(
        running.status.refusals(),
        vec![("refused", 1), ("unknown-peer", 1)]
    );
    for line in running.lines.lock().map_err(|_| "log poisoned")?.iter() {
        assert!(!line.contains(".test"), "a mapped name was logged: {line}");
        assert!(!line.contains("127.0.0.1"), "an address was logged: {line}");
        assert!(!line.contains(&upstream.port().to_string()), "{line}");
        assert!(
            !line.contains("0badf00d"),
            "the selector was logged: {line}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn without_supgang_the_connection_closes_naming_it_missing() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        with_endpoint: false,
        resolver: None,
        substitute: true,
        ..Setup::default()
    })?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    closed_without_bytes(local).await?;
    let line = running.logged("Service: ssh").await?;
    assert!(line.contains("Cause: no-supgang"), "{line}");
    assert!(
        !line.contains("pro.test"),
        "a mapped name was logged: {line}"
    );
    assert_eq!(running.status.refusals(), vec![("no-supgang", 1)]);
    Ok(())
}

#[tokio::test]
async fn listeners_follow_add_disable_enable_and_remove() -> TestResult {
    let (running, _upstream) = standard().await?;
    let address = Ipv4Addr::new(127, 77, 0, 1);
    let target = format!("supgang://{}?ssh=22", node_id());
    running.publish(1, vec![machine("pro.test", &target, address)?])?;
    let [first] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };

    running.publish(
        2,
        vec![machine("pro.test", &target, address)?.with_enabled(false)],
    )?;
    running.reports_where(<[ListenerReport]>::is_empty).await?;
    assert!(
        TcpStream::connect(first).await.is_err(),
        "a disabled mapping still listens"
    );

    let two = format!("supgang://{}?ssh=22,web=8080", node_id());
    running.publish(3, vec![machine("pro.test", &two, address)?])?;
    let locals = running.listening(2).await?;
    let ports: Vec<u16> = running
        .status
        .reports()
        .iter()
        .map(|report| report.port)
        .collect();
    assert_eq!(ports, vec![22, 8080]);
    round_trip(locals[0]).await?;

    running.publish(4, Vec::new())?;
    running.reports_where(<[ListenerReport]>::is_empty).await?;
    for local in locals {
        assert!(
            TcpStream::connect(local).await.is_err(),
            "a removed mapping still listens"
        );
    }
    Ok(())
}

/// Without a substitute the runtime binds exactly the reserved address. On
/// a machine where that address is not an interface address (macOS without
/// the helper's alias) the listener reports the named cause; where the
/// platform routes it (Linux routes all of 127/8) it listens there and
/// nowhere else.
#[tokio::test]
async fn the_reserved_address_is_bound_exactly_or_reported() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        with_endpoint: true,
        resolver: None,
        substitute: false,
        ..Setup::default()
    })?;
    let address = Ipv4Addr::new(127, 77, 254, 201);
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await?
        .local_addr()?
        .port();
    let bindable = std::net::TcpListener::bind((address, port)).is_ok();
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh={port}", node_id()),
            address,
        )?],
    )?;
    let reports = running.reports_where(|reports| reports.len() == 1).await?;
    if bindable {
        assert_eq!(
            reports[0].state,
            ListenerState::Listening(SocketAddr::from((address, port)))
        );
        round_trip(SocketAddr::from((address, port))).await?;
    } else {
        assert_eq!(
            reports[0].state,
            ListenerState::NotListening(ListenerCause::AddressNotReserved)
        );
        assert!(
            TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                .await
                .is_err(),
            "the runtime fell back to 127.0.0.1"
        );
    }
    Ok(())
}

#[test]
fn a_substitute_address_off_loopback_is_refused() {
    let runtime = PeerMachineListeners::new(SnapshotStore::empty(), PeerMachineStatus::default())
        .with_substitute_address(Ipv4Addr::new(192, 0, 2, 1));
    assert!(runtime.is_err());
}

/// The response code and first A answer DNS gives `name` now.
fn dns(
    snapshots: &SnapshotStore,
    name: &str,
) -> Result<(hickory_proto::op::ResponseCode, Option<Ipv4Addr>), Box<dyn Error>> {
    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    let mut query = Message::query();
    query.add_query(Query::query(Name::from_ascii(name)?, RecordType::A));
    let engine = DnsEngine::new(snapshots.clone(), DnsPolicy::default());
    let DnsDecision::Respond(bytes) = engine.decide(&query.to_vec()?)? else {
        return Err("a mapped name was forwarded".into());
    };
    let response = Message::from_vec(&bytes)?;
    let address = response
        .answers
        .iter()
        .find_map(|record| match &record.data {
            RData::A(address) => Some(address.0),
            _ => None,
        });
    Ok((response.response_code, address))
}

fn adopted(port: u16) -> Result<std::net::TcpListener, Box<dyn Error>> {
    Ok(std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))?)
}

#[tokio::test]
async fn an_adopted_socket_is_held_carries_and_lets_the_name_answer() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        resolver: Some(Arc::new(Fleet)),
        source: ListenerSource::Adopt,
        ..Setup::default()
    })?;
    let address = Ipv4Addr::new(127, 77, 0, 1);
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            address,
        )?],
    )?;
    let reports = running.reports_where(|reports| reports.len() == 1).await?;
    assert_eq!(
        reports[0].state,
        ListenerState::NotListening(ListenerCause::AwaitingSocket)
    );
    assert!(!running.runtime.is_held(address, 22));
    assert_eq!(
        dns(&running.snapshots, "pro.test.")?.0,
        hickory_proto::op::ResponseCode::ServFail
    );

    let first = adopted(0)?;
    let first_local = first.local_addr()?;
    running.runtime.adopt(address, 22, first)?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    assert_eq!(local, first_local);
    assert!(running.runtime.is_held(address, 22));
    assert!(!running.runtime.is_held(address, 23));
    assert_eq!(
        dns(&running.snapshots, "pro.test.")?,
        (hickory_proto::op::ResponseCode::NoError, Some(address))
    );
    round_trip(local).await?;

    // A second hand-over replaces the held listener.
    let second = adopted(0)?;
    let second_local = second.local_addr()?;
    running.runtime.adopt(address, 22, second)?;
    running
        .reports_where(|reports| {
            reports.len() == 1 && reports[0].state == ListenerState::Listening(second_local)
        })
        .await?;
    round_trip(second_local).await?;
    assert!(
        TcpStream::connect(first_local).await.is_err(),
        "the replaced socket still listens"
    );
    Ok(())
}

#[tokio::test]
async fn a_socket_on_any_other_endpoint_is_refused() -> TestResult {
    let runtime = PeerMachineListeners::new(SnapshotStore::empty(), PeerMachineStatus::default())
        .with_listener_source(ListenerSource::Adopt);
    let address = Ipv4Addr::new(127, 77, 0, 1);
    assert_eq!(
        runtime.adopt(address, 22, adopted(0)?),
        Err(PeerMachineAdoptError::WrongEndpoint)
    );
    assert_eq!(
        runtime.adopt(Ipv4Addr::LOCALHOST, 22, adopted(0)?),
        Err(PeerMachineAdoptError::NotPeerMachineEndpoint)
    );
    assert!(!runtime.is_held(address, 22));
    Ok(())
}

/// A port that cannot be held keeps the whole name from answering, so a
/// connection can never reach whatever else listens there.
#[tokio::test]
async fn a_bind_failure_makes_the_name_fail_instead_of_answer() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        substitute: false,
        ..Setup::default()
    })?;
    let address = Ipv4Addr::new(127, 77, 254, 202);
    let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await?
        .local_addr()?
        .port();
    // Where the platform routes the address, something else holds the port
    // first; elsewhere the address itself is not there.
    let _occupant = std::net::TcpListener::bind((address, port)).ok();
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh={port}", node_id()),
            address,
        )?],
    )?;
    let reports = running.reports_where(|reports| reports.len() == 1).await?;
    assert!(
        matches!(
            reports[0].state,
            ListenerState::NotListening(
                ListenerCause::AddressNotReserved | ListenerCause::PortInUse
            )
        ),
        "{reports:?}"
    );
    assert_eq!(
        dns(&running.snapshots, "pro.test.")?,
        (hickory_proto::op::ResponseCode::ServFail, None)
    );
    Ok(())
}

#[tokio::test]
async fn a_silent_connection_is_closed_after_the_idle_deadline() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        idle: Some(Duration::from_millis(200)),
        ..Setup::default()
    })?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    let mut client = TcpStream::connect(local).await?;
    let mut banner = [0_u8; 18];
    timeout(WAIT, client.read_exact(&mut banner)).await??;
    let began = tokio::time::Instant::now();
    let mut rest = Vec::new();
    timeout(WAIT, client.read_to_end(&mut rest)).await??;
    assert!(began.elapsed() >= Duration::from_millis(150));
    assert_eq!(rest, Vec::<u8>::new());
    Ok(())
}

#[tokio::test]
async fn one_listener_carries_at_most_its_own_share() -> TestResult {
    let (running, _upstream) = standard().await?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    let mut carried = Vec::new();
    for _connection in 0..remap_network::PEER_MACHINE_LISTENER_CONNECTION_LIMIT {
        let mut client = TcpStream::connect(local).await?;
        let mut banner = [0_u8; 18];
        timeout(WAIT, client.read_exact(&mut banner)).await??;
        carried.push(client);
    }
    closed_without_bytes(local).await?;
    drop(carried.pop());
    // A slot frees once the carried connection's close is seen.
    let deadline = tokio::time::Instant::now() + WAIT;
    loop {
        let mut client = TcpStream::connect(local).await?;
        let mut banner = [0_u8; 18];
        if timeout(Duration::from_millis(500), client.read_exact(&mut banner))
            .await
            .is_ok_and(|read| read.is_ok())
        {
            return Ok(());
        }
        if tokio::time::Instant::now() > deadline {
            return Err("no slot freed after a connection closed".into());
        }
    }
}

#[tokio::test]
async fn refusals_are_logged_once_per_interval_and_all_counted() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        exposed: vec![("ssh", upstream)],
        with_endpoint: false,
        ..Setup::default()
    })?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    for _attempt in 0..3 {
        closed_without_bytes(local).await?;
    }
    running.logged("Cause: no-supgang").await?;
    let deadline = tokio::time::Instant::now() + WAIT;
    while running.status.refusals() != vec![("no-supgang", 3)] {
        if tokio::time::Instant::now() > deadline {
            return Err(format!("counted {:?}", running.status.refusals()).into());
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(running.lines.lock().map_err(|_| "log poisoned")?.len(), 1);
    Ok(())
}

#[tokio::test]
async fn supgang_started_after_the_runtime_is_found_on_the_next_connection() -> TestResult {
    let upstream = banner_upstream().await?;
    let running = start(Setup {
        lookup: true,
        ..Setup::default()
    })?;
    running.publish(
        1,
        vec![machine(
            "pro.test",
            &format!("supgang://{}?ssh=22", node_id()),
            Ipv4Addr::new(127, 77, 0, 1),
        )?],
    )?;
    let [local] = running.listening(1).await?[..] else {
        return Err("expected one listener".into());
    };
    closed_without_bytes(local).await?;
    running.logged("Cause: no-supgang").await?;
    endpoint(&running.socket, vec![("ssh", upstream)])?;
    round_trip(local).await
}
