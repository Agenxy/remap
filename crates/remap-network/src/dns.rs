use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::{Message, MessageType, Metadata, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME, TXT};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use remap_core::{MappingTarget, RemapName};

use crate::{NetworkError, RuntimeIdentity, SnapshotStore};

/// A complete decision for one validated DNS wire message.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DnsDecision {
    /// Remap owns the queried name and produced the complete response.
    Respond(Vec<u8>),
    /// Remap does not own the queried name; forward the original bytes.
    Forward,
}

/// Bounded synthesis policy shared by platform DNS adapters.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct DnsPolicy {
    /// TTL applied to locally synthesized answers.
    pub answer_ttl: u32,
    /// IPv4 address returned for routed HTTP services.
    pub routed_ipv4: Option<Ipv4Addr>,
    /// IPv6 address returned for routed HTTP services.
    pub routed_ipv6: Option<Ipv6Addr>,
}

impl Default for DnsPolicy {
    fn default() -> Self {
        Self {
            answer_ttl: 1,
            routed_ipv4: Some(Ipv4Addr::LOCALHOST),
            routed_ipv6: Some(Ipv6Addr::LOCALHOST),
        }
    }
}

/// Pure mapped-name DNS decision engine over atomically published snapshots.
#[derive(Debug, Clone)]
pub struct DnsEngine {
    snapshots: SnapshotStore,
    policy: DnsPolicy,
    identity: Option<RuntimeIdentity>,
}

impl DnsEngine {
    /// Creates an engine over one shared immutable-snapshot store.
    #[must_use]
    pub const fn new(snapshots: SnapshotStore, policy: DnsPolicy) -> Self {
        Self {
            snapshots,
            policy,
            identity: None,
        }
    }

    /// Creates an engine with authenticated runtime-health responses enabled.
    #[must_use]
    pub const fn with_identity(
        snapshots: SnapshotStore,
        policy: DnsPolicy,
        identity: RuntimeIdentity,
    ) -> Self {
        Self {
            snapshots,
            policy,
            identity: Some(identity),
        }
    }

    /// Synthesizes a mapped answer or asks the caller to forward the original.
    ///
    /// Malformed DNS receives a bounded `FORMERR` response when its identifier
    /// can be recovered. Unsupported but well-formed unmapped names are forwarded.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkError::Encoding`] only if a locally constructed response
    /// cannot be encoded.
    pub fn decide(&self, packet: &[u8]) -> Result<DnsDecision, NetworkError> {
        let Ok(request) = Message::from_vec(packet) else {
            return encode(&error_response(packet, ResponseCode::FormErr));
        };
        if !valid_query_envelope(&request) {
            return encode(&response_error(&request, ResponseCode::FormErr));
        }
        let query = &request.queries[0];
        if let Some(response) = self.health_response(&request) {
            return response;
        }
        let Ok(name) = RemapName::parse(&query.name().to_ascii()) else {
            return Ok(DnsDecision::Forward);
        };
        let snapshot = self.snapshots.load();
        let Some(mapping) = snapshot.resolve(&name) else {
            return Ok(DnsDecision::Forward);
        };

        let mut response = base_response(&request);
        add_mapping_answers(
            &mut response,
            query.name(),
            query.query_type(),
            mapping.target(),
            self.policy,
        )?;
        encode(&response)
    }

    fn health_response(&self, request: &Message) -> Option<Result<DnsDecision, NetworkError>> {
        let identity = self.identity.as_ref()?;
        let query = &request.queries[0];
        if !matches!(query.query_type(), RecordType::TXT | RecordType::ANY) {
            return None;
        }
        let name = query.name().to_ascii();
        let nonce = name
            .strip_suffix("._health.remap.invalid.")?
            .strip_prefix('r')?;
        if nonce.contains('.') {
            return None;
        }
        let proofs = identity.proofs(nonce)?;
        let mut response = base_response(request);
        response.add_answer(Record::from_rdata(
            query.name().clone(),
            0,
            RData::TXT(TXT::new(vec![proofs.dns().to_owned()])),
        ));
        Some(encode(&response))
    }
}

fn valid_query_envelope(request: &Message) -> bool {
    request.message_type == MessageType::Query
        && request.op_code == OpCode::Query
        && request.queries.len() == 1
        && request.queries[0].query_class() == DNSClass::IN
}

fn base_response(request: &Message) -> Message {
    let mut response = Message::response(request.id, request.op_code);
    response.metadata = Metadata::response_from_request(&request.metadata);
    response.metadata.authoritative = true;
    response.metadata.recursion_available = true;
    response.add_query(request.queries[0].clone());
    if let Some(edns) = &request.edns {
        response.set_edns(edns.clone());
    }
    response
}

fn response_error(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::error_msg(request.id, request.op_code, code);
    response.metadata.recursion_desired = request.recursion_desired;
    response.metadata.checking_disabled = request.checking_disabled;
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.iter().cloned());
    response
}

fn error_response(packet: &[u8], code: ResponseCode) -> Message {
    let id = packet
        .get(..2)
        .and_then(|bytes| <[u8; 2]>::try_from(bytes).ok())
        .map_or(0, u16::from_be_bytes);
    Message::error_msg(id, OpCode::Query, code)
}

pub(crate) fn encoded_error(packet: &[u8], code: ResponseCode) -> Result<Vec<u8>, NetworkError> {
    let response = Message::from_vec(packet).map_or_else(
        |_| error_response(packet, code),
        |request| response_error(&request, code),
    );
    response.to_vec().map_err(|_| NetworkError::Encoding)
}

fn encode(message: &Message) -> Result<DnsDecision, NetworkError> {
    message
        .to_vec()
        .map(DnsDecision::Respond)
        .map_err(|_| NetworkError::Encoding)
}

fn add_mapping_answers(
    response: &mut Message,
    owner: &Name,
    query_type: RecordType,
    target: &MappingTarget,
    policy: DnsPolicy,
) -> Result<(), NetworkError> {
    match target {
        MappingTarget::DnsAddress(address) => {
            add_address(response, owner, query_type, *address, policy.answer_ttl);
        }
        MappingTarget::DnsAlias(alias) => {
            let target = Name::from_ascii(format!("{}.", alias.as_str()))
                .map_err(|_| NetworkError::Encoding)?;
            response.add_answer(Record::from_rdata(
                owner.clone(),
                policy.answer_ttl,
                RData::CNAME(CNAME(target)),
            ));
        }
        MappingTarget::Http(_) | MappingTarget::Peer(_) => {
            if let Some(address) = policy.routed_ipv4 {
                add_address(
                    response,
                    owner,
                    query_type,
                    IpAddr::V4(address),
                    policy.answer_ttl,
                );
            }
            if let Some(address) = policy.routed_ipv6 {
                add_address(
                    response,
                    owner,
                    query_type,
                    IpAddr::V6(address),
                    policy.answer_ttl,
                );
            }
        }
    }
    Ok(())
}

fn add_address(
    response: &mut Message,
    owner: &Name,
    query_type: RecordType,
    address: IpAddr,
    ttl: u32,
) {
    let data = match (address, query_type) {
        (IpAddr::V4(value), RecordType::A | RecordType::ANY) => Some(RData::A(A(value))),
        (IpAddr::V6(value), RecordType::AAAA | RecordType::ANY) => Some(RData::AAAA(AAAA(value))),
        _ => None,
    };
    if let Some(data) = data {
        response.add_answer(Record::from_rdata(owner.clone(), ttl, data));
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hickory_proto::op::{Message, Query};
    use hickory_proto::rr::{Name, RData, RecordType};
    use remap_core::{Mapping, MappingTarget, NamePattern, RegistrySnapshot};

    use super::{DnsDecision, DnsEngine, DnsPolicy};
    use crate::{RuntimeIdentity, SnapshotStore};

    fn query(name: &str, query_type: RecordType) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut message = Message::query();
        message.add_query(Query::query(Name::from_ascii(name)?, query_type));
        Ok(message.to_vec()?)
    }

    fn engine(
        pattern: &str,
        target: MappingTarget,
    ) -> Result<DnsEngine, Box<dyn std::error::Error>> {
        let store = SnapshotStore::empty();
        let mapping = Mapping::new(NamePattern::parse(pattern)?, target);
        assert!(store.publish(RegistrySnapshot::new(4, vec![mapping])?));
        Ok(DnsEngine::new(store, DnsPolicy::default()))
    }

    #[test]
    fn direct_ipv4_answers_only_a_and_any() -> Result<(), Box<dyn std::error::Error>> {
        let engine = engine(
            "atlas.test",
            MappingTarget::DnsAddress(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        )?;
        let DnsDecision::Respond(bytes) = engine.decide(&query("atlas.test.", RecordType::A)?)?
        else {
            return Err("mapped query was forwarded".into());
        };
        let response = Message::from_vec(&bytes)?;
        assert_eq!(response.answers.len(), 1);
        assert!(matches!(response.answers[0].data, RData::A(_)));

        let DnsDecision::Respond(bytes) =
            engine.decide(&query("atlas.test.", RecordType::AAAA)?)?
        else {
            return Err("mapped query was forwarded".into());
        };
        assert!(Message::from_vec(&bytes)?.answers.is_empty());
        Ok(())
    }

    #[test]
    fn routed_http_returns_both_loopback_families() -> Result<(), Box<dyn std::error::Error>> {
        let engine = engine(
            "remap.test",
            MappingTarget::parse_with_http_policy(
                "http://127.0.0.1:4270",
                remap_core::HostHeaderPolicy::UseUpstream,
            )?,
        )?;
        for query_type in [RecordType::A, RecordType::AAAA] {
            let DnsDecision::Respond(bytes) = engine.decide(&query("remap.test.", query_type)?)?
            else {
                return Err("mapped query was forwarded".into());
            };
            assert_eq!(Message::from_vec(&bytes)?.answers.len(), 1);
        }
        Ok(())
    }

    // A peer mapping is routed by the gateway exactly as an HTTP one, so DNS
    // sends the browser to the gateway: nothing about the peer's address
    // reaches a DNS answer, then or ever.
    #[test]
    fn routed_peer_returns_the_gateway_like_http() -> Result<(), Box<dyn std::error::Error>> {
        let engine = engine(
            "hub",
            MappingTarget::parse_with_http_policy(
                "supgang://MacSolis/dibs",
                remap_core::HostHeaderPolicy::PreserveClient,
            )?,
        )?;
        let DnsDecision::Respond(bytes) = engine.decide(&query("hub.", RecordType::A)?)? else {
            return Err("peer mapping was forwarded".into());
        };
        let answers = Message::from_vec(&bytes)?.answers;
        assert_eq!(answers.len(), 1);
        assert!(answers[0].to_string().contains("127.0.0.1"));
        Ok(())
    }

    #[test]
    fn wildcard_alias_is_a_cname_and_unmapped_is_forwarded()
    -> Result<(), Box<dyn std::error::Error>> {
        let engine = engine(
            "*.lab.test",
            MappingTarget::DnsAlias(remap_core::RemapName::parse("upstream.test")?),
        )?;
        let DnsDecision::Respond(bytes) = engine.decide(&query("api.lab.test.", RecordType::A)?)?
        else {
            return Err("wildcard query was forwarded".into());
        };
        assert!(matches!(
            Message::from_vec(&bytes)?.answers[0].data,
            RData::CNAME(_)
        ));
        assert_eq!(
            engine.decide(&query("outside.test.", RecordType::A)?)?,
            DnsDecision::Forward
        );
        Ok(())
    }

    #[test]
    fn malformed_packet_receives_form_error() -> Result<(), Box<dyn std::error::Error>> {
        let engine = DnsEngine::new(SnapshotStore::empty(), DnsPolicy::default());
        let DnsDecision::Respond(bytes) = engine.decide(&[0x12, 0x34, 0x80])? else {
            return Err("malformed packet was forwarded".into());
        };
        let response = Message::from_vec(&bytes)?;
        assert_eq!(response.id, 0x1234);
        assert_eq!(
            response.response_code,
            hickory_proto::op::ResponseCode::FormErr
        );
        Ok(())
    }

    #[test]
    fn health_identity_answers_only_exact_txt_and_any_queries()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity = RuntimeIdentity::generate(
            "42aa9f3d-6260-44e3-ab39-c4a1aac6256d".to_owned(),
            "0.1.0".to_owned(),
        )?;
        let nonce = "00112233445566778899aabbccddeeff";
        let expected = identity.proofs(nonce).ok_or("valid nonce rejected")?;
        let engine =
            DnsEngine::with_identity(SnapshotStore::empty(), DnsPolicy::default(), identity);
        let name = format!("r{nonce}._health.remap.invalid.");
        for query_type in [RecordType::TXT, RecordType::ANY] {
            let DnsDecision::Respond(bytes) = engine.decide(&query(&name, query_type)?)? else {
                return Err("health query was forwarded".into());
            };
            let response = Message::from_vec(&bytes)?;
            assert_eq!(response.answers.len(), 1);
            assert!(matches!(&response.answers[0].data, RData::TXT(value)
                if value.txt_data.len() == 1
                    && value.txt_data[0].as_ref() == expected.dns().as_bytes()));
        }
        assert_eq!(
            engine.decide(&query(&name, RecordType::A)?)?,
            DnsDecision::Forward
        );
        assert_eq!(
            engine.decide(&query(
                "r00112233445566778899aabbccddeefg._health.remap.invalid.",
                RecordType::TXT,
            )?)?,
            DnsDecision::Forward
        );
        Ok(())
    }
}
