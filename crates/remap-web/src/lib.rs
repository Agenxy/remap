// SPDX-License-Identifier: GPL-3.0-or-later
//! Loopback web interface for Remap (ADR-0041).
//!
//! `remap web` serves one browser page and a small JSON API on
//! `127.0.0.1` for as long as the command runs. Every API request relays one
//! control command to `remapd` through [`ControlClient`]; nothing here reads
//! or writes the registry directly.
//!
//! The server trusts no name it was not given. The `Host` header must name
//! the loopback listener or the owner's `--name`, a request that carries
//! `Origin` must come from one of those same origins, and every `/api`
//! request carries the per-run capability token from the printed URL.

use std::fmt;
use std::future::Future;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use remap_protocol::{ControlClient, Diagnostic};
use tokio::net::TcpListener;

mod api;
mod assets;
mod guard;
mod mappings;
mod query;
mod reply;
mod route;
mod serve;
mod status;
mod token;

use guard::Allowed;
use token::Token;

/// How `remap web` listens.
#[derive(Debug, Clone, Default, Eq, PartialEq)]
pub struct WebOptions {
    /// Loopback port to bind; `0` asks the operating system for a free one.
    pub port: u16,
    /// One extra hostname the owner reaches the page by, from `--name`. Its
    /// `Host` and `http`/`https` origins are accepted besides the loopback
    /// ones.
    pub name: Option<String>,
}

/// A bound, not yet serving, loopback web interface.
pub struct WebServer {
    listener: TcpListener,
    local_addr: SocketAddr,
    state: Arc<State>,
}

/// What every request handler shares.
pub(crate) struct State {
    pub(crate) client: ControlClient,
    pub(crate) token: Token,
    pub(crate) allowed: Allowed,
}

impl WebServer {
    /// Binds 127.0.0.1:port and generates the per-run capability token.
    ///
    /// # Errors
    ///
    /// Returns `web-name-invalid` when `--name` is not a hostname,
    /// `web-port-in-use` or `web-port-denied` when the port cannot be bound,
    /// `web-bind-failed` for any other listener failure, and
    /// `web-random-unavailable` when the operating system's random source
    /// fails.
    pub async fn bind(client: ControlClient, options: WebOptions) -> Result<Self, Diagnostic> {
        let name = options
            .name
            .as_deref()
            .map(guard::validate_name)
            .transpose()?;
        let token = Token::generate()?;
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, options.port))
            .await
            .map_err(|error| status::bind_failure(options.port, &error))?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| status::bind_failure(options.port, &error))?;
        let allowed = Allowed::new(local_addr.port(), name);
        Ok(Self {
            listener,
            local_addr,
            state: Arc::new(State {
                client,
                token,
                allowed,
            }),
        })
    }

    /// The bound loopback address.
    #[must_use]
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// `http://127.0.0.1:<port>/#token=<64 hex chars>`.
    ///
    /// The token rides in the fragment, which a browser never sends to the
    /// server, puts in a `Referer`, or writes to a server log.
    #[must_use]
    pub fn url(&self) -> String {
        format!(
            "http://127.0.0.1:{}/#token={}",
            self.local_addr.port(),
            self.state.token.as_str()
        )
    }

    /// Serves until `shutdown` resolves, then drains in-flight requests
    /// briefly.
    ///
    /// # Errors
    ///
    /// Returns `web-serve-failed` when the connection limiter closes, which
    /// does not happen in normal operation.
    pub async fn serve_until(
        self,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), Diagnostic> {
        serve::serve(self.listener, self.state, shutdown).await
    }
}

impl fmt::Debug for WebServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The token is a credential: it is never formatted.
        formatter
            .debug_struct("WebServer")
            .field("local_addr", &self.local_addr)
            .finish_non_exhaustive()
    }
}
