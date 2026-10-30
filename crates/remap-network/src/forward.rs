// SPDX-License-Identifier: GPL-3.0-or-later
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType};
use hickory_proto::rr::RData;
use remap_core::PEER_MACHINE_LOOPBACK;
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
                return refuse_rebinding(response);
            }
            if let Ok(response) = self.exchange_tcp(&plan, upstream, packet).await
                && related_response(request.as_ref(), &response)
            {
                return refuse_rebinding(response);
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

/// Refuses an upstream answer that points into the peer-machine network
/// (ADR-0033), so a remote name cannot be made to reach a reserved port
/// through Remap's resolver.
///
/// The whole response fails as SERVFAIL rather than losing the record.
/// Dropping only the address would hand the client a different answer than
/// the upstream gave, which it would cache as true, and a `NOERROR` with no
/// data is cached as the name having no address. SERVFAIL says only that
/// this resolution failed, is barely cached, and keeps the forwarder from
/// rewriting answers.
fn refuse_rebinding(response: Vec<u8>) -> Result<Vec<u8>, NetworkError> {
    let Ok(message) = Message::from_vec(&response) else {
        return Ok(response);
    };
    let rebinding = message
        .answers
        .iter()
        .chain(message.additionals.iter())
        .any(|record| match &record.data {
            RData::A(address) => in_peer_machine_network(address.0),
            RData::AAAA(address) => address
                .0
                .to_ipv4_mapped()
                .is_some_and(in_peer_machine_network),
            _ => false,
        });
    if rebinding {
        return Err(NetworkError::UpstreamUnavailable);
    }
    Ok(response)
}

fn in_peer_machine_network(address: Ipv4Addr) -> bool {
    let (network, prefix) = PEER_MACHINE_LOOPBACK;
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(address) & mask == u32::from(network)
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use hickory_proto::op::{Message, OpCode, Query};
    use hickory_proto::rr::rdata::{A, AAAA};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    use super::refuse_rebinding;

    fn answer(data: RData) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let name = Name::from_ascii("evil.example.")?;
        let mut message = Message::response(7, OpCode::Query);
        message.add_query(Query::query(name.clone(), RecordType::A));
        message.add_answer(Record::from_rdata(name, 60, data));
        Ok(message.to_vec()?)
    }

    #[test]
    fn an_upstream_answer_inside_the_peer_machine_network_fails()
    -> Result<(), Box<dyn std::error::Error>> {
        for inside in [
            RData::A(A(Ipv4Addr::new(127, 77, 0, 1))),
            RData::A(A(Ipv4Addr::new(127, 77, 255, 255))),
            RData::AAAA(AAAA(Ipv4Addr::new(127, 77, 0, 9).to_ipv6_mapped())),
        ] {
            assert!(refuse_rebinding(answer(inside)?).is_err());
        }
        for outside in [
            RData::A(A(Ipv4Addr::LOCALHOST)),
            RData::A(A(Ipv4Addr::new(127, 78, 0, 1))),
            RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ] {
            let packet = answer(outside)?;
            assert_eq!(refuse_rebinding(packet.clone()).ok(), Some(packet));
        }
        let _parsed = Message::from_vec(&answer(RData::A(A(Ipv4Addr::LOCALHOST)))?)?;
        Ok(())
    }
}
