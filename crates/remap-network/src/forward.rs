// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::NetworkError;
use crate::liveness::{ExchangeOutcome, UpstreamFailureCause};
use crate::resolver::{ResolverPlan, ResolverPlanStore};

const MAX_DNS_MESSAGE_BYTES: usize = 65_535;

#[derive(Debug, Clone)]
pub(crate) struct Forwarder {
    plans: ResolverPlanStore,
    io_timeout: Duration,
}

impl Forwarder {
    pub(crate) const fn new(plans: ResolverPlanStore, io_timeout: Duration) -> Self {
        Self { plans, io_timeout }
    }

    /// Forwards one query through the active plan, trying each upstream in
    /// order, and records whether any of them answered (ADR-0036).
    pub(crate) async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let plan = self
            .plans
            .capture()
            .ok_or(NetworkError::UpstreamUnavailable)?;
        let request = Message::from_vec(packet).ok();
        let mut failures = UpstreamFailures::default();
        for upstream in plan.upstreams().iter().copied() {
            match self
                .exchange_one(&plan, upstream, packet, request.as_ref())
                .await
            {
                Attempt::Answered(response) => {
                    self.plans.record_exchange(&plan, ExchangeOutcome::Answered);
                    return Ok(response);
                }
                Attempt::AnsweredIncompletely => failures.answered = true,
                Attempt::Refused(response) => {
                    failures.note(UpstreamFailureCause::Refused);
                    failures.refused.get_or_insert(response);
                }
                Attempt::Failed(cause) => failures.note(cause),
                Attempt::Cancelled => return Err(NetworkError::UpstreamUnavailable),
            }
        }
        self.plans.record_exchange(&plan, failures.outcome());
        failures.refused.ok_or(NetworkError::UpstreamUnavailable)
    }

    /// Sends one root `NS` query through the active plan while every
    /// upstream is judged unanswered, so the verdict clears once one of them
    /// answers again even when no client is asking. It carries no name a
    /// person chose, and runs at most once per probe interval.
    pub(crate) async fn probe(&self) {
        if !self.plans.upstreams_unanswered() {
            return;
        }
        let Some(query) = probe_query() else {
            return;
        };
        let _outcome = self.exchange(&query).await;
    }

    pub(crate) fn probe_interval(&self) -> Duration {
        self.plans.liveness_policy().probe_interval
    }

    async fn exchange_one(
        &self,
        plan: &ResolverPlan,
        upstream: SocketAddr,
        packet: &[u8],
        request: Option<&Message>,
    ) -> Attempt {
        let response = match self.exchange_udp(plan, upstream, packet).await {
            Ok(response) => response,
            Err(error) => return Attempt::from_error(&error, plan),
        };
        let Some(message) = related_response(request, &response) else {
            return Attempt::Failed(UpstreamFailureCause::TimedOut);
        };
        if message.response_code == ResponseCode::Refused {
            return Attempt::Refused(response);
        }
        if !message.truncation {
            return Attempt::Answered(response);
        }
        match self.exchange_tcp(plan, upstream, packet).await {
            Ok(response) if related_response(request, &response).is_some() => {
                Attempt::Answered(response)
            }
            Ok(_) | Err(_) if plan.cancellation().is_cancelled() => Attempt::Cancelled,
            Ok(_) | Err(_) => Attempt::AnsweredIncompletely,
        }
    }

    async fn exchange_udp(
        &self,
        plan: &ResolverPlan,
        upstream: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let bind = match upstream.ip() {
            IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
        };
        let socket = UdpSocket::bind(bind)
            .await
            .map_err(|error| NetworkError::io("upstream UDP bind", error))?;
        plan_io(
            plan,
            self.io_timeout,
            "upstream UDP connect",
            socket.connect(upstream),
        )
        .await?;
        plan_io(
            plan,
            self.io_timeout,
            "upstream UDP write",
            socket.send(packet),
        )
        .await?;
        let mut buffer = vec![0_u8; MAX_DNS_MESSAGE_BYTES];
        let size = plan_io(
            plan,
            self.io_timeout,
            "upstream UDP read",
            socket.recv(&mut buffer),
        )
        .await?;
        buffer.truncate(size);
        Ok(buffer)
    }

    async fn exchange_tcp(
        &self,
        plan: &ResolverPlan,
        upstream: SocketAddr,
        packet: &[u8],
    ) -> Result<Vec<u8>, NetworkError> {
        let size = u16::try_from(packet.len()).map_err(|_| {
            NetworkError::Configuration("a DNS query exceeds the TCP framing limit")
        })?;
        let mut stream = plan_io(
            plan,
            self.io_timeout,
            "upstream TCP connect",
            TcpStream::connect(upstream),
        )
        .await?;
        plan_io(
            plan,
            self.io_timeout,
            "upstream TCP write",
            stream.write_all(&size.to_be_bytes()),
        )
        .await?;
        plan_io(
            plan,
            self.io_timeout,
            "upstream TCP write",
            stream.write_all(packet),
        )
        .await?;
        let mut length = [0_u8; 2];
        plan_io(
            plan,
            self.io_timeout,
            "upstream TCP read",
            stream.read_exact(&mut length),
        )
        .await?;
        let mut response = vec![0_u8; usize::from(u16::from_be_bytes(length))];
        plan_io(
            plan,
            self.io_timeout,
            "upstream TCP read",
            stream.read_exact(&mut response),
        )
        .await?;
        Ok(response)
    }
}

async fn plan_io<T>(
    plan: &ResolverPlan,
    io_timeout: Duration,
    operation: &'static str,
    future: impl std::future::Future<Output = io::Result<T>>,
) -> Result<T, NetworkError> {
    let result = tokio::select! {
        () = plan.cancellation().cancelled() => {
            return Err(NetworkError::UpstreamUnavailable);
        }
        result = timeout(io_timeout, future) => result,
    };
    let value = result
        .map_err(|_| NetworkError::io(operation, io::Error::from(io::ErrorKind::TimedOut)))?
        .map_err(|error| NetworkError::io(operation, error))?;
    if plan.cancellation().is_cancelled() {
        return Err(NetworkError::UpstreamUnavailable);
    }
    Ok(value)
}

/// How one upstream handled one query.
enum Attempt {
    Answered(Vec<u8>),
    /// A truncated UDP answer whose TCP retry failed: the upstream is alive.
    AnsweredIncompletely,
    Refused(Vec<u8>),
    Failed(UpstreamFailureCause),
    /// A newer plan replaced this one; the result says nothing about liveness.
    Cancelled,
}

impl Attempt {
    fn from_error(error: &NetworkError, plan: &ResolverPlan) -> Self {
        if plan.cancellation().is_cancelled() {
            return Self::Cancelled;
        }
        match error {
            NetworkError::Io { source, .. } => Self::Failed(failure_cause(source.kind())),
            NetworkError::Configuration(_)
            | NetworkError::Encoding
            | NetworkError::UpstreamUnavailable => Self::Failed(UpstreamFailureCause::Unreachable),
        }
    }
}

#[derive(Default)]
struct UpstreamFailures {
    answered: bool,
    causes: Vec<UpstreamFailureCause>,
    refused: Option<Vec<u8>>,
}

impl UpstreamFailures {
    fn note(&mut self, cause: UpstreamFailureCause) {
        self.causes.push(cause);
    }

    /// One exchange has one cause: a timeout when any upstream timed out,
    /// since a filtering firewall is the failure that cause names, then a
    /// refusal, then an unreachable network.
    fn outcome(&self) -> ExchangeOutcome {
        if self.answered {
            return ExchangeOutcome::Answered;
        }
        let cause = [
            UpstreamFailureCause::TimedOut,
            UpstreamFailureCause::Refused,
            UpstreamFailureCause::Unreachable,
        ]
        .into_iter()
        .find(|cause| self.causes.contains(cause))
        .unwrap_or(UpstreamFailureCause::Unreachable);
        ExchangeOutcome::Unanswered(cause)
    }
}

const fn failure_cause(kind: io::ErrorKind) -> UpstreamFailureCause {
    match kind {
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => UpstreamFailureCause::TimedOut,
        io::ErrorKind::ConnectionRefused | io::ErrorKind::ConnectionReset => {
            UpstreamFailureCause::Refused
        }
        _ => UpstreamFailureCause::Unreachable,
    }
}

fn probe_query() -> Option<Vec<u8>> {
    let mut id = [0_u8; 2];
    getrandom::fill(&mut id).ok()?;
    let mut message = Message::new(u16::from_be_bytes(id), MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::root(), RecordType::NS));
    message.to_vec().ok()
}

fn related_response(request: Option<&Message>, packet: &[u8]) -> Option<Message> {
    let (Some(request), Ok(response)) = (request, Message::from_vec(packet)) else {
        return None;
    };
    (response.message_type == MessageType::Response
        && response.id == request.id
        && response.op_code == request.op_code
        && response.queries == request.queries)
        .then_some(response)
}

pub(crate) fn eof(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}
