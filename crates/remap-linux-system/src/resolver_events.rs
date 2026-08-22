use std::io;
use std::time::Duration;

use futures::{FutureExt, Stream, StreamExt};
use remap_linux::{LinkIndex, ResolverLinkManager};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use zbus::message::Type;
use zbus::{MatchRule, MessageStream};

const EVENT_DEBOUNCE: Duration = Duration::from_millis(10);
const EVENT_MIN_INTERVAL: Duration = Duration::from_millis(250);
const EVENT_METHOD_TIMEOUT: Duration = Duration::from_millis(100);
const SIGNAL_QUEUE: usize = 1;
const MAX_COALESCED_SIGNALS: usize = 64;
const PROPERTIES_INTERFACE: &str = "org.freedesktop.DBus.Properties";
const PROPERTIES_MEMBER: &str = "PropertiesChanged";
const DBUS_SERVICE: &str = "org.freedesktop.DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
const OWNER_MEMBER: &str = "NameOwnerChanged";
const RESOLVED_SERVICE: &str = "org.freedesktop.resolve1";
const NETWORKD_SERVICE: &str = "org.freedesktop.network1";
const NETWORK_MANAGER_SERVICE: &str = "org.freedesktop.NetworkManager";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) enum ResolverEvent {
    Changed,
    StreamUnavailable,
}

pub(crate) struct ResolverEventMonitor {
    receiver: mpsc::Receiver<ResolverEvent>,
    tasks: Vec<JoinHandle<()>>,
    throttle: EventThrottle,
}

#[derive(Debug, Default)]
struct EventThrottle {
    last_change: Option<tokio::time::Instant>,
}

impl EventThrottle {
    fn deadline(&self, now: tokio::time::Instant) -> tokio::time::Instant {
        let debounced = now + EVENT_DEBOUNCE;
        self.last_change
            .map_or(debounced, |last| debounced.max(last + EVENT_MIN_INTERVAL))
    }

    fn record(&mut self, observed: tokio::time::Instant) {
        self.last_change = Some(observed);
    }
}

impl ResolverEventMonitor {
    pub(crate) async fn connect(
        link: LinkIndex,
        manager: Option<ResolverLinkManager>,
    ) -> io::Result<Self> {
        let connection =
            zbus::connection::Builder::system().map_err(|_error| monitor_unavailable())?;
        let connection = connection
            .method_timeout(EVENT_METHOD_TIMEOUT)
            .build()
            .await
            .map_err(|_error| monitor_unavailable())?;
        let rules = event_rules(link, manager)?;
        let mut subscriptions = Vec::with_capacity(rules.len());
        for rule in rules {
            let stream =
                MessageStream::for_match_rule(rule.clone(), &connection, Some(SIGNAL_QUEUE))
                    .await
                    .map_err(|_error| monitor_unavailable())?;
            subscriptions.push(stream);
        }
        let (sender, receiver) = mpsc::channel(SIGNAL_QUEUE);
        let tasks = subscriptions
            .into_iter()
            .map(|stream| tokio::spawn(supervise_stream(stream, sender.clone())))
            .collect();
        drop(sender);
        Ok(Self {
            receiver,
            tasks,
            throttle: EventThrottle::default(),
        })
    }

    pub(crate) async fn changed(&mut self) -> io::Result<ResolverEvent> {
        let event = self.receiver.recv().await.ok_or_else(monitor_unavailable)?;
        if event == ResolverEvent::StreamUnavailable {
            return Ok(event);
        }
        let now = tokio::time::Instant::now();
        tokio::time::sleep_until(self.throttle.deadline(now)).await;
        self.throttle.record(tokio::time::Instant::now());
        Ok(ResolverEvent::Changed)
    }
}

pub(crate) async fn connect_monitor(
    link: LinkIndex,
    manager: Option<ResolverLinkManager>,
) -> Option<ResolverEventMonitor> {
    match ResolverEventMonitor::connect(link, manager).await {
        Ok(monitor) => Some(monitor),
        Err(_error) => {
            eprintln!(
                "the native resolver event monitor is unavailable; periodic reconciliation remains active"
            );
            None
        }
    }
}

pub(crate) async fn next_event(
    events: &mut Option<ResolverEventMonitor>,
) -> io::Result<ResolverEvent> {
    match events {
        Some(events) => events.changed().await,
        None => std::future::pending().await,
    }
}

impl Drop for ResolverEventMonitor {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

async fn supervise_stream(mut stream: MessageStream, sender: mpsc::Sender<ResolverEvent>) {
    let _forwarded = forward_until_unavailable(&mut stream, &sender).await;
}

async fn forward_until_unavailable<S, T, E>(
    stream: &mut S,
    sender: &mpsc::Sender<ResolverEvent>,
) -> bool
where
    S: Stream<Item = Result<T, E>> + Unpin,
{
    loop {
        let Some(event) = stream.next().await else {
            let Ok(permit) = sender.reserve().await else {
                return false;
            };
            permit.send(ResolverEvent::StreamUnavailable);
            return true;
        };
        if event.is_err() {
            let Ok(permit) = sender.reserve().await else {
                return false;
            };
            permit.send(ResolverEvent::StreamUnavailable);
            return true;
        }
        let Ok(permit) = sender.reserve().await else {
            return false;
        };
        let mut unavailable = false;
        for _index in 1..MAX_COALESCED_SIGNALS {
            match stream.next().now_or_never() {
                Some(Some(Ok(_message))) => {}
                Some(Some(Err(_)) | None) => {
                    unavailable = true;
                    break;
                }
                None => break,
            }
        }
        if unavailable {
            permit.send(ResolverEvent::StreamUnavailable);
            return true;
        }
        permit.send(ResolverEvent::Changed);
    }
}

fn event_rules(
    link: LinkIndex,
    manager: Option<ResolverLinkManager>,
) -> io::Result<Vec<MatchRule<'static>>> {
    let link_path = zbus::zvariant::OwnedObjectPath::try_from(format!(
        "/org/freedesktop/resolve1/link/_{}",
        link.get()
    ))
    .map_err(|_error| invalid_rule())?;
    let mut rules = vec![
        MatchRule::builder()
            .msg_type(Type::Signal)
            .sender(RESOLVED_SERVICE)
            .and_then(|builder| builder.interface(PROPERTIES_INTERFACE))
            .and_then(|builder| builder.member(PROPERTIES_MEMBER))
            .and_then(|builder| builder.path(link_path))
            .map_err(|_error| invalid_rule())?
            .build(),
        owner_rule(RESOLVED_SERVICE)?,
    ];
    if let Some(service) = manager_service(manager)
        && service != RESOLVED_SERVICE
    {
        rules.push(owner_rule(service)?);
    }
    Ok(rules)
}

fn owner_rule(service: &'static str) -> io::Result<MatchRule<'static>> {
    let builder = MatchRule::builder()
        .msg_type(Type::Signal)
        .sender(DBUS_SERVICE)
        .and_then(|builder| builder.interface(DBUS_INTERFACE))
        .and_then(|builder| builder.member(OWNER_MEMBER))
        .and_then(|builder| builder.add_arg(service))
        .map_err(|_error| invalid_rule())?;
    Ok(builder.build())
}

const fn manager_service(manager: Option<ResolverLinkManager>) -> Option<&'static str> {
    match manager {
        Some(ResolverLinkManager::SystemdResolved) => Some(RESOLVED_SERVICE),
        Some(ResolverLinkManager::SystemdNetworkd) => Some(NETWORKD_SERVICE),
        Some(ResolverLinkManager::NetworkManager) => Some(NETWORK_MANAGER_SERVICE),
        None => None,
    }
}

fn invalid_rule() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "the native resolver event rules are invalid",
    )
}

fn monitor_unavailable() -> io::Error {
    io::Error::other("the native resolver change monitor is unavailable")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll};

    use futures::{Stream, StreamExt};
    use remap_linux::{LinkIndex, ResolverLinkManager};

    use super::{
        EVENT_DEBOUNCE, EVENT_MIN_INTERVAL, EventThrottle, MAX_COALESCED_SIGNALS,
        NETWORK_MANAGER_SERVICE, NETWORKD_SERVICE, RESOLVED_SERVICE, ResolverEvent, event_rules,
        forward_until_unavailable,
    };

    #[test]
    fn event_rules_are_scoped_to_the_exact_link_and_selected_manager() -> std::io::Result<()> {
        let link = LinkIndex::new(23).map_err(std::io::Error::other)?;
        for (manager, selected, excluded) in [
            (
                ResolverLinkManager::SystemdResolved,
                RESOLVED_SERVICE,
                [NETWORKD_SERVICE, NETWORK_MANAGER_SERVICE],
            ),
            (
                ResolverLinkManager::SystemdNetworkd,
                NETWORKD_SERVICE,
                [NETWORK_MANAGER_SERVICE, "org.example.unused"],
            ),
            (
                ResolverLinkManager::NetworkManager,
                NETWORK_MANAGER_SERVICE,
                [NETWORKD_SERVICE, "org.example.unused"],
            ),
        ] {
            let encoded = event_rules(link, Some(manager))?
                .iter()
                .map(ToString::to_string)
                .collect::<BTreeSet<_>>();
            let expected_count = usize::from(selected != RESOLVED_SERVICE) + 2;
            assert_eq!(encoded.len(), expected_count);
            assert!(encoded.iter().any(|rule| {
                rule.contains(RESOLVED_SERVICE)
                    && rule.contains("/org/freedesktop/resolve1/link/_23")
            }));
            assert!(encoded.iter().any(|rule| rule.contains(selected)));
            for service in excluded {
                assert!(!encoded.iter().any(|rule| rule.contains(service)));
            }
        }
        Ok(())
    }

    #[test]
    fn sustained_signal_flood_is_bounded_to_four_full_scans_per_second() {
        let start = tokio::time::Instant::now();
        let mut throttle = EventThrottle::default();
        assert_eq!(throttle.deadline(start), start + EVENT_DEBOUNCE);
        throttle.record(start + EVENT_DEBOUNCE);
        for offset in 1_u64..=100 {
            let event = start + std::time::Duration::from_millis(offset);
            assert!(
                throttle.deadline(event) >= start + EVENT_DEBOUNCE + EVENT_MIN_INTERVAL,
                "event {offset} bypassed the reconciliation rate limit"
            );
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_individual_stream_closure_is_visible_and_floods_coalesce() -> std::io::Result<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let mut stream = futures::stream::iter((0_u8..100).map(Ok::<_, ()>));
        let forward =
            tokio::spawn(async move { forward_until_unavailable(&mut stream, &sender).await });
        assert_eq!(receiver.recv().await, Some(ResolverEvent::Changed));
        assert_eq!(
            receiver.recv().await,
            Some(ResolverEvent::StreamUnavailable)
        );
        assert!(forward.await.map_err(std::io::Error::other)?);
        assert!(receiver.try_recv().is_err());
        Ok(())
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_quiet_first_stream_cannot_starve_a_later_event_or_closure() -> std::io::Result<()> {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
        let quiet_sender = sender.clone();
        let quiet = tokio::spawn(async move {
            let mut stream = futures::stream::pending::<Result<(), ()>>();
            forward_until_unavailable(&mut stream, &quiet_sender).await
        });
        tokio::task::yield_now().await;

        let event_sender = sender.clone();
        let event = tokio::spawn(async move {
            let mut stream =
                futures::stream::iter([Ok(())]).chain(futures::stream::pending::<Result<(), ()>>());
            forward_until_unavailable(&mut stream, &event_sender).await
        });
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receiver.recv())
                .await
                .map_err(std::io::Error::other)?,
            Some(ResolverEvent::Changed)
        );
        event.abort();

        let closed_sender = sender.clone();
        let closed = tokio::spawn(async move {
            let mut stream = futures::stream::empty::<Result<(), ()>>();
            forward_until_unavailable(&mut stream, &closed_sender).await
        });
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(20), receiver.recv())
                .await
                .map_err(std::io::Error::other)?,
            Some(ResolverEvent::StreamUnavailable)
        );
        assert!(closed.await.map_err(std::io::Error::other)?);
        quiet.abort();
        Ok(())
    }

    struct AlwaysReady {
        polls: Arc<AtomicUsize>,
    }

    impl Stream for AlwaysReady {
        type Item = Result<(), ()>;

        fn poll_next(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            self.polls.fetch_add(1, Ordering::SeqCst);
            Poll::Ready(Some(Ok(())))
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn an_always_ready_signal_stream_cannot_starve_the_runtime_or_spin() {
        let polls = Arc::new(AtomicUsize::new(0));
        let (sender, _receiver) = tokio::sync::mpsc::channel(1);
        let stream_polls = Arc::clone(&polls);
        let task = tokio::spawn(async move {
            let mut stream = AlwaysReady {
                polls: stream_polls,
            };
            forward_until_unavailable(&mut stream, &sender).await
        });
        let timer = tokio::time::timeout(
            std::time::Duration::from_millis(20),
            tokio::time::sleep(std::time::Duration::from_millis(1)),
        )
        .await;
        assert!(timer.is_ok());
        assert!(polls.load(Ordering::SeqCst) <= MAX_COALESCED_SIGNALS + 1);
        task.abort();
    }
}
