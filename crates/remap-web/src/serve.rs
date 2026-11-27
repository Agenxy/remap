// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded HTTP/1.1 serving, after the gateway's pattern: a connection
//! permit before each accept, a header deadline, and a short drain.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use remap_protocol::Diagnostic;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::{State, route};

/// Most connections served at once; more wait in the listen backlog.
pub(crate) const MAX_CONNECTIONS: usize = 32;

/// Longest a client may take to send one request's headers, including
/// while an idle keep-alive connection waits for its next request.
pub(crate) const HEADER_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest one connection is kept; it then closes after its current request.
const CONNECTION_LIFETIME: Duration = Duration::from_mins(5);

/// Longest in-flight requests are given to finish at shutdown.
const DRAIN_GRACE: Duration = Duration::from_secs(2);

/// Longest a retired connection's last request may take: the control
/// client's own 15-second bound, plus margin.
const RETIRE_GRACE: Duration = Duration::from_secs(20);

/// Pause after a failed accept, such as running out of descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

pub(crate) async fn serve(
    listener: TcpListener,
    state: Arc<State>,
    shutdown: impl Future<Output = ()> + Send,
) -> Result<(), Diagnostic> {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let (stop, stopping) = watch::channel(false);
    let mut connections = JoinSet::new();
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            _completed = connections.join_next(), if !connections.is_empty() => continue,
            permit = Arc::clone(&permits).acquire_owned() => permit.map_err(|_| {
                Diagnostic::new(
                    "web-serve-failed",
                    "the connection limiter closed",
                    Some("restart remap web".to_owned()),
                    true,
                )
            })?,
        };
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _peer)) = accepted else {
            drop(permit);
            sleep(ACCEPT_BACKOFF).await;
            continue;
        };
        let state = Arc::clone(&state);
        let stopping = stopping.clone();
        connections.spawn(async move {
            let _permit = permit;
            serve_connection(stream, state, stopping).await;
        });
    }
    drop(listener);
    let _sent = stop.send(true);
    let drained = timeout(DRAIN_GRACE + Duration::from_millis(500), async {
        while connections.join_next().await.is_some() {}
    })
    .await;
    if drained.is_err() {
        connections.shutdown().await;
    }
    Ok(())
}

async fn serve_connection(
    stream: TcpStream,
    state: Arc<State>,
    mut stopping: watch::Receiver<bool>,
) {
    let service = service_fn(move |request| {
        let state = Arc::clone(&state);
        async move { route::handle(&state, request).await }
    });
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HEADER_TIMEOUT))
        .max_headers(64)
        .keep_alive(true);
    let connection = builder.serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    let grace = tokio::select! {
        _result = &mut connection => return,
        () = sleep(CONNECTION_LIFETIME) => RETIRE_GRACE,
        _changed = stopping.wait_for(|stop| *stop) => DRAIN_GRACE,
    };
    connection.as_mut().graceful_shutdown();
    let _finished = timeout(grace, &mut connection).await;
}
