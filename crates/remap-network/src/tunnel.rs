//! WebSocket upgrades carried through the gateway under their own bounds
//! (ADR-0021). An upgraded connection stops being HTTP: it is counted apart
//! from HTTP connections, closed when it carries nothing for the idle limit,
//! and closed at its lifetime regardless.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use hyper::HeaderMap;
use hyper::header::{CONNECTION, HeaderValue, UPGRADE};
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf, copy_bidirectional};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::{Instant, sleep, sleep_until, timeout};

use crate::gateway::shutdown_requested;

/// The one protocol the gateway switches to. Any other `Upgrade` request is
/// forwarded as an ordinary request with its hop-by-hop headers removed.
const WEBSOCKET: &str = "websocket";

/// The shared bounds every tunnel on one gateway runs under.
#[derive(Debug, Clone)]
pub(crate) struct Tunnels {
    permits: Arc<Semaphore>,
    idle: Duration,
    lifetime: Duration,
    shutdown: watch::Receiver<bool>,
}

impl Tunnels {
    pub(crate) fn new(
        limit: usize,
        idle: Duration,
        lifetime: Duration,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            permits: Arc::new(Semaphore::new(limit)),
            idle,
            lifetime,
            shutdown,
        }
    }

    /// A slot for one more tunnel, or `None` when the limit is reached. A
    /// slot is taken before the upstream is asked, so a refused upgrade
    /// never reaches it.
    pub(crate) fn admit(&self) -> Option<OwnedSemaphorePermit> {
        Arc::clone(&self.permits).try_acquire_owned().ok()
    }

    /// Joins the two upgraded connections once both sides have switched.
    pub(crate) fn spawn(
        &self,
        permit: OwnedSemaphorePermit,
        client: OnUpgrade,
        upstream: OnUpgrade,
    ) {
        let tunnel = self.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let switched = timeout(tunnel.lifetime, async { tokio::join!(client, upstream) }).await;
            let Ok((Ok(client), Ok(upstream))) = switched else {
                return;
            };
            tunnel
                .carry(TokioIo::new(client), TokioIo::new(upstream))
                .await;
        });
    }

    async fn carry<C, U>(mut self, client: C, upstream: U)
    where
        C: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let clock = Clock::new();
        let mut client = Touched::new(client, &clock);
        let mut upstream = Touched::new(upstream, &clock);
        tokio::select! {
            _copied = copy_bidirectional(&mut client, &mut upstream) => {}
            () = idle_expired(&clock, self.idle) => {}
            () = sleep(self.lifetime) => {}
            () = shutdown_requested(&mut self.shutdown) => {}
        }
    }
}

/// Whether a request asks to switch to WebSocket: `Connection` names the
/// `upgrade` token and there is exactly one `Upgrade`, naming `websocket`.
pub(crate) fn requests_websocket(headers: &HeaderMap) -> bool {
    let connection_upgrade = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"));
    connection_upgrade && upgrades_to_websocket(headers)
}

/// Whether the only `Upgrade` header names `websocket`.
pub(crate) fn upgrades_to_websocket(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(UPGRADE).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value
            .to_str()
            .is_ok_and(|value| value.trim().eq_ignore_ascii_case(WEBSOCKET)),
        _ => false,
    }
}

/// Puts back the two hop-by-hop headers a WebSocket switch needs, after
/// every other hop-by-hop header was removed.
pub(crate) fn mark_websocket(headers: &mut HeaderMap) {
    headers.insert(CONNECTION, HeaderValue::from_static("upgrade"));
    headers.insert(UPGRADE, HeaderValue::from_static(WEBSOCKET));
}

/// When either side of a tunnel last delivered a byte.
#[derive(Debug)]
struct Clock {
    start: Instant,
    last_millis: AtomicU64,
}

impl Clock {
    fn new() -> Self {
        Self {
            start: Instant::now(),
            last_millis: AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let elapsed = u64::try_from(self.start.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.last_millis.store(elapsed, Ordering::Relaxed);
    }

    fn last(&self) -> Instant {
        self.start + Duration::from_millis(self.last_millis.load(Ordering::Relaxed))
    }
}

async fn idle_expired(clock: &Clock, idle: Duration) {
    loop {
        let deadline = clock.last() + idle;
        if Instant::now() >= deadline {
            return;
        }
        sleep_until(deadline).await;
    }
}

/// A stream that marks the clock whenever it delivers bytes. Every byte a
/// tunnel moves is read from one side first, so reads alone measure idleness.
struct Touched<'a, T> {
    inner: T,
    clock: &'a Clock,
}

impl<'a, T> Touched<'a, T> {
    const fn new(inner: T, clock: &'a Clock) -> Self {
        Self { inner, clock }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for Touched<'_, T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        let polled = Pin::new(&mut self.inner).poll_read(context, buffer);
        if matches!(polled, Poll::Ready(Ok(()))) && buffer.filled().len() > before {
            self.clock.touch();
        }
        polled
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for Touched<'_, T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(context, buffer)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(context)
    }
}

#[cfg(test)]
mod tests {
    use hyper::HeaderMap;
    use hyper::header::{CONNECTION, HeaderValue, UPGRADE};

    use super::{mark_websocket, requests_websocket};

    fn headers(pairs: &[(&'static str, &'static str)]) -> HeaderMap {
        let mut headers = HeaderMap::new();
        for (name, value) in pairs {
            headers.append(*name, HeaderValue::from_static(value));
        }
        headers
    }

    #[test]
    fn only_a_websocket_switch_named_by_connection_is_an_upgrade() {
        assert!(requests_websocket(&headers(&[
            ("connection", "keep-alive, Upgrade"),
            ("upgrade", "WebSocket"),
        ])));
        assert!(!requests_websocket(&headers(&[("upgrade", "websocket")])));
        assert!(!requests_websocket(&headers(&[
            ("connection", "upgrade"),
            ("upgrade", "h2c"),
        ])));
        assert!(!requests_websocket(&headers(&[
            ("connection", "upgrade"),
            ("upgrade", "websocket"),
            ("upgrade", "websocket"),
        ])));
    }

    #[test]
    fn marking_replaces_whatever_hop_by_hop_values_remained() {
        let mut marked = headers(&[("connection", "close"), ("upgrade", "h2c")]);
        mark_websocket(&mut marked);
        assert_eq!(marked.get_all(CONNECTION).iter().count(), 1);
        assert_eq!(
            marked.get(CONNECTION),
            Some(&HeaderValue::from_static("upgrade"))
        );
        assert_eq!(
            marked.get(UPGRADE),
            Some(&HeaderValue::from_static("websocket"))
        );
    }
}
