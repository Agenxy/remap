use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::NetworkError;
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

    pub(crate) async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>, NetworkError> {
        let plan = self
            .plans
            .capture()
            .ok_or(NetworkError::UpstreamUnavailable)?;
        let request = Message::from_vec(packet).ok();
        for upstream in plan.upstreams().iter().copied() {
            let Ok(response) = self.exchange_udp(&plan, upstream, packet).await else {
                continue;
            };
            if !related_response(request.as_ref(), &response) {
                continue;
            }
            let truncated = Message::from_vec(&response).is_ok_and(|message| message.truncation);
            if !truncated {
                return Ok(response);
            }
            if let Ok(response) = self.exchange_tcp(&plan, upstream, packet).await
                && related_response(request.as_ref(), &response)
            {
                return Ok(response);
            }
        }
        Err(NetworkError::UpstreamUnavailable)
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
        .map_err(|_| NetworkError::UpstreamUnavailable)?
        .map_err(|error| NetworkError::io(operation, error))?;
    if plan.cancellation().is_cancelled() {
        return Err(NetworkError::UpstreamUnavailable);
    }
    Ok(value)
}

fn related_response(request: Option<&Message>, packet: &[u8]) -> bool {
    let (Some(request), Ok(response)) = (request, Message::from_vec(packet)) else {
        return false;
    };
    response.message_type == MessageType::Response
        && response.id == request.id
        && response.op_code == request.op_code
        && response.queries == request.queries
}

pub(crate) fn eof(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
    )
}
