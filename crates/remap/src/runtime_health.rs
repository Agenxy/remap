use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};
use remap_network::{HEALTH_PROOF_BYTES, MAX_INSTANCE_ID_BYTES, MAX_RUNTIME_VERSION_BYTES};
use remap_protocol::HealthChallengeResult;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

const PROBE_TIMEOUT: Duration = Duration::from_millis(750);
const MAX_DNS_RESPONSE_BYTES: usize = 4_096;
const MAX_HTTP_RESPONSE_BYTES: u64 = 4_096;
const HEALTH_HOST: &str = "_health.remap.invalid";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct RuntimeHealth {
    pub(crate) dns: bool,
    pub(crate) forwarding: bool,
    pub(crate) http: bool,
}

pub(crate) fn valid_challenge(challenge: &HealthChallengeResult, expected_version: &str) -> bool {
    valid_metadata(&challenge.instance_id, MAX_INSTANCE_ID_BYTES)
        && valid_metadata(&challenge.daemon_version, MAX_RUNTIME_VERSION_BYTES)
        && challenge.daemon_version == expected_version
        && valid_proof(&challenge.dns_proof)
        && valid_proof(&challenge.http_proof)
        && challenge.dns_proof != challenge.http_proof
}

pub(crate) async fn verify(
    nonce: &str,
    challenge: &HealthChallengeResult,
    dns_address: SocketAddr,
    http_address: SocketAddr,
) -> RuntimeHealth {
    let dns = async {
        let query = dns_query(nonce)?;
        let (udp, tcp) = tokio::join!(
            query_dns_udp(dns_address, &query),
            query_dns_tcp(dns_address, &query)
        );
        Some(
            valid_dns_response(&udp?, nonce, &challenge.dns_proof)
                && valid_dns_response(&tcp?, nonce, &challenge.dns_proof),
        )
    };
    let forwarding = async {
        let query = forwarding_query(nonce)?;
        let (udp, tcp) = tokio::join!(
            query_dns_udp(dns_address, &query),
            query_dns_tcp(dns_address, &query)
        );
        Some(valid_forwarding_response(&udp?, nonce) && valid_forwarding_response(&tcp?, nonce))
    };
    let (dns, forwarding, http) = tokio::join!(
        timeout(PROBE_TIMEOUT, dns),
        timeout(PROBE_TIMEOUT, forwarding),
        timeout(
            PROBE_TIMEOUT,
            query_http(http_address, nonce, &challenge.http_proof)
        )
    );
    RuntimeHealth {
        dns: matches!(dns, Ok(Some(true))),
        forwarding: matches!(forwarding, Ok(Some(true))),
        http: matches!(http, Ok(true)),
    }
}

pub(crate) const fn installation_ready(authority: bool, health: &RuntimeHealth) -> bool {
    authority && health.dns && health.forwarding && health.http
}

fn valid_metadata(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

fn valid_proof(value: &str) -> bool {
    value.len() == HEALTH_PROOF_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn dns_query(nonce: &str) -> Option<Vec<u8>> {
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let name = Name::from_ascii(format!("r{nonce}._health.remap.invalid.")).ok()?;
    let identifier = u16::from_str_radix(nonce.get(..4)?, 16).ok()?;
    let mut message = Message::new(identifier, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(name, RecordType::TXT));
    message.to_vec().ok()
}

fn forwarding_query(nonce: &str) -> Option<Vec<u8>> {
    if nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    let name = Name::from_ascii(format!("r{nonce}._forwarding.remap.invalid.")).ok()?;
    let identifier = u16::from_str_radix(nonce.get(28..32)?, 16).ok()?;
    let mut message = Message::new(identifier, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name, RecordType::A));
    message.to_vec().ok()
}

async fn query_dns_udp(address: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.ok()?;
    timeout(PROBE_TIMEOUT, socket.send_to(query, address))
        .await
        .ok()?
        .ok()?;
    let mut response = vec![0_u8; MAX_DNS_RESPONSE_BYTES];
    let (size, peer) = timeout(PROBE_TIMEOUT, socket.recv_from(&mut response))
        .await
        .ok()?
        .ok()?;
    if peer != address {
        return None;
    }
    response.truncate(size);
    Some(response)
}

async fn query_dns_tcp(address: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let mut stream = timeout(PROBE_TIMEOUT, TcpStream::connect(address))
        .await
        .ok()?
        .ok()?;
    let length = u16::try_from(query.len()).ok()?.to_be_bytes();
    timeout(PROBE_TIMEOUT, stream.write_all(&length))
        .await
        .ok()?
        .ok()?;
    timeout(PROBE_TIMEOUT, stream.write_all(query))
        .await
        .ok()?
        .ok()?;
    let mut prefix = [0_u8; 2];
    timeout(PROBE_TIMEOUT, stream.read_exact(&mut prefix))
        .await
        .ok()?
        .ok()?;
    let size = usize::from(u16::from_be_bytes(prefix));
    if size > MAX_DNS_RESPONSE_BYTES {
        return None;
    }
    let mut response = vec![0_u8; size];
    timeout(PROBE_TIMEOUT, stream.read_exact(&mut response))
        .await
        .ok()?
        .ok()?;
    Some(response)
}

fn valid_dns_response(response: &[u8], nonce: &str, expected: &str) -> bool {
    let Ok(message) = Message::from_vec(response) else {
        return false;
    };
    let expected_name = format!("r{nonce}._health.remap.invalid.");
    let Some(expected_identifier) = nonce
        .get(..4)
        .and_then(|value| u16::from_str_radix(value, 16).ok())
    else {
        return false;
    };
    valid_dns_header(&message, expected_identifier)
        && valid_dns_sections(&message)
        && valid_dns_question(&message, &expected_name)
        && valid_dns_answer(&message, &expected_name, expected)
}

fn valid_dns_header(message: &Message, expected_identifier: u16) -> bool {
    message.id == expected_identifier
        && message.message_type == MessageType::Response
        && message.op_code == OpCode::Query
        && !message.metadata.truncation
        && message.response_code == ResponseCode::NoError
}

fn valid_dns_sections(message: &Message) -> bool {
    message.queries.len() == 1
        && message.answers.len() == 1
        && message.authorities.is_empty()
        && message.additionals.is_empty()
        && message.edns.is_none()
}

fn valid_dns_question(message: &Message, expected_name: &str) -> bool {
    message.queries.first().is_some_and(|query| {
        query.name().to_ascii() == expected_name
            && query.query_type() == RecordType::TXT
            && query.query_class() == DNSClass::IN
    })
}

fn valid_dns_answer(message: &Message, expected_name: &str, expected: &str) -> bool {
    message.answers.first().is_some_and(|record| {
        record.name.to_ascii() == expected_name
            && record.record_type() == RecordType::TXT
            && record.dns_class == DNSClass::IN
            && record.ttl == 0
            && matches!(&record.data, RData::TXT(value) if value.txt_data.len() == 1
                && value.txt_data[0].as_ref() == expected.as_bytes())
    })
}

fn valid_forwarding_response(response: &[u8], nonce: &str) -> bool {
    let Ok(message) = Message::from_vec(response) else {
        return false;
    };
    let expected_name = format!("r{nonce}._forwarding.remap.invalid.");
    let Some(expected_identifier) = nonce
        .get(28..32)
        .and_then(|value| u16::from_str_radix(value, 16).ok())
    else {
        return false;
    };
    message.id == expected_identifier
        && message.message_type == MessageType::Response
        && message.op_code == OpCode::Query
        && !message.metadata.truncation
        && message.response_code == ResponseCode::NXDomain
        && message.queries.len() == 1
        && message.queries[0].name().to_ascii() == expected_name
        && message.queries[0].query_type() == RecordType::A
        && message.queries[0].query_class() == DNSClass::IN
}

async fn query_http(address: SocketAddr, nonce: &str, expected: &str) -> bool {
    let Some(request) = http_request(nonce) else {
        return false;
    };
    let Ok(Ok(mut stream)) = timeout(PROBE_TIMEOUT, TcpStream::connect(address)).await else {
        return false;
    };
    if !matches!(
        timeout(PROBE_TIMEOUT, stream.write_all(&request)).await,
        Ok(Ok(()))
    ) {
        return false;
    }
    let mut response = Vec::new();
    let mut limited = stream.take(MAX_HTTP_RESPONSE_BYTES + 1);
    let read = limited.read_to_end(&mut response);
    if !matches!(timeout(PROBE_TIMEOUT, read).await, Ok(Ok(_)))
        || u64::try_from(response.len()).unwrap_or(u64::MAX) > MAX_HTTP_RESPONSE_BYTES
    {
        return false;
    }
    valid_http_response(&response, expected)
}

fn http_request(nonce: &str) -> Option<Vec<u8>> {
    dns_query(nonce)?;
    Some(
        format!(
            "GET /.well-known/remap/health/{nonce} HTTP/1.1\r\nHost: {HEALTH_HOST}\r\nConnection: close\r\n\r\n"
        )
        .into_bytes(),
    )
}

fn valid_http_response(response: &[u8], expected: &str) -> bool {
    let Some(split) = response.windows(4).position(|value| value == b"\r\n\r\n") else {
        return false;
    };
    let Ok(headers) = std::str::from_utf8(&response[..split]) else {
        return false;
    };
    let mut lines = headers.split("\r\n");
    if lines.next() != Some("HTTP/1.1 200 OK") {
        return false;
    }
    let mut no_store = None;
    let mut plain = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            return false;
        };
        if name.eq_ignore_ascii_case("cache-control")
            && no_store.replace(value.trim() == "no-store").is_some()
        {
            return false;
        }
        if name.eq_ignore_ascii_case("content-type")
            && plain
                .replace(value.trim() == "text/plain; charset=utf-8")
                .is_some()
        {
            return false;
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return false;
        }
    }
    no_store == Some(true)
        && plain == Some(true)
        && response.get(split + 4..) == Some(expected.as_bytes())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Duration;

    use hickory_proto::op::{Message, Query, ResponseCode};
    use hickory_proto::rr::rdata::TXT;
    use hickory_proto::rr::{Name, RData, Record, RecordType};
    use remap_protocol::HealthChallengeResult;
    use tokio::net::{TcpListener, UdpSocket};
    use tokio::time::Instant;

    use super::{
        RuntimeHealth, dns_query, forwarding_query, installation_ready, valid_challenge,
        valid_dns_response, valid_forwarding_response, valid_http_response, verify,
    };

    const NONCE: &str = "00112233445566778899aabbccddeeff";

    fn challenge() -> HealthChallengeResult {
        HealthChallengeResult {
            instance_id: "30edced7-44fe-459a-846f-c780a97f6dde".to_owned(),
            daemon_version: "0.1.0".to_owned(),
            dns_proof: "a".repeat(64),
            http_proof: "b".repeat(64),
        }
    }

    #[test]
    fn challenge_rejects_wrong_version_and_malformed_proofs() {
        let mut value = challenge();
        assert!(valid_challenge(&value, "0.1.0"));
        assert!(!valid_challenge(&value, "0.2.0"));
        value.http_proof = value.dns_proof.clone();
        assert!(!valid_challenge(&value, "0.1.0"));
        value.http_proof = "A".repeat(64);
        assert!(!valid_challenge(&value, "0.1.0"));
    }

    #[test]
    fn stale_install_metadata_cannot_report_runtime_readiness() {
        let unavailable = RuntimeHealth {
            dns: false,
            forwarding: false,
            http: false,
        };
        assert!(!installation_ready(false, &unavailable));
        assert!(!installation_ready(true, &unavailable));
    }

    #[test]
    fn unrelated_http_responses_are_not_authenticated() {
        let response = b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx";
        assert!(!valid_http_response(response, &"b".repeat(64)));
    }

    #[test]
    fn ambiguous_http_health_headers_are_rejected() {
        let proof = "b".repeat(64);
        let duplicate = format!(
            "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nCache-Control: private\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n{proof}"
        );
        assert!(!valid_http_response(duplicate.as_bytes(), &proof));
        let encoded = format!(
            "HTTP/1.1 200 OK\r\nCache-Control: no-store\r\nContent-Type: text/plain; charset=utf-8\r\nTransfer-Encoding: identity\r\n\r\n{proof}"
        );
        assert!(!valid_http_response(encoded.as_bytes(), &proof));
    }

    #[test]
    fn dns_health_response_requires_the_exact_query_envelope()
    -> Result<(), Box<dyn std::error::Error>> {
        let proof = "a".repeat(64);
        let request = Message::from_vec(&dns_query(NONCE).ok_or("query rejected")?)?;
        let mut response = Message::response(request.id, request.op_code);
        response.add_query(request.queries[0].clone());
        response.add_answer(Record::from_rdata(
            request.queries[0].name().clone(),
            0,
            RData::TXT(TXT::new(vec![proof.clone()])),
        ));
        assert!(valid_dns_response(&response.to_vec()?, NONCE, &proof));

        response.add_query(Query::query(
            Name::from_ascii("unrelated.invalid.")?,
            RecordType::TXT,
        ));
        assert!(!valid_dns_response(&response.to_vec()?, NONCE, &proof));
        Ok(())
    }

    #[test]
    fn forwarding_probe_requires_an_exact_upstream_nxdomain()
    -> Result<(), Box<dyn std::error::Error>> {
        let request = Message::from_vec(&forwarding_query(NONCE).ok_or("query rejected")?)?;
        assert!(request.recursion_desired);
        let mut response = Message::error_msg(request.id, request.op_code, ResponseCode::NXDomain);
        response.add_query(request.queries[0].clone());
        assert!(valid_forwarding_response(&response.to_vec()?, NONCE));
        let mut response = Message::error_msg(request.id, request.op_code, ResponseCode::ServFail);
        response.add_query(request.queries[0].clone());
        assert!(!valid_forwarding_response(&response.to_vec()?, NONCE));
        Ok(())
    }

    #[tokio::test]
    async fn hostile_local_listeners_cannot_extend_the_overall_probe_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let udp = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let dns_address = udp.local_addr()?;
        let _tcp = TcpListener::bind(dns_address).await?;
        let http = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let started = Instant::now();

        let health = verify(NONCE, &challenge(), dns_address, http.local_addr()?).await;

        assert!(!health.dns);
        assert!(!health.forwarding);
        assert!(!health.http);
        assert!(started.elapsed() < Duration::from_secs(1));
        Ok(())
    }
}
