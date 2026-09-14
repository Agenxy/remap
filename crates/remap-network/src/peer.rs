//! Supgang peers as routed destinations (ADR-0016).
//!
//! A `supgang://<peer>/<service>` mapping is resolved when a request is
//! routed: Supgang says where the peer is now and which key its service
//! presents, this module remembers the answer for as long as it is signed
//! for, and the gateway's TLS client for that key verifies the upstream
//! against it rather than the system roots. Remap never learns an address
//! at `set` time and never trusts one it did not get from a signed record.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::client::WebPkiServerVerifier;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, RootCertStore, SignatureScheme};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;
use tokio::process::Command;

/// The longest a resolved peer is remembered, however long its record lasts.
pub const PEER_CACHE_LIMIT: Duration = Duration::from_secs(300);
/// The longest one `supgang resolve` may take.
pub const RESOLVE_TIMEOUT: Duration = Duration::from_secs(5);
/// The most output read back from Supgang.
const MAX_RESOLVE_OUTPUT: usize = 1 << 20;
/// The schema this resolver reads: the first that carries service rows.
const RESOLVE_SCHEMA: &str = "supgang.resolve/v5";

/// Where a peer's service is right now, from its signed record.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ResolvedPeerService {
    /// The address Supgang prefers from this machine.
    pub host: IpAddr,
    /// The port the service advertises.
    pub port: u16,
    /// SHA-256 of the service's TLS `SubjectPublicKeyInfo`.
    pub key_pin: [u8; 32],
    /// UNIX time after which the record is stale.
    pub expires_at: u64,
}

/// Why a peer could not be turned into a destination.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PeerResolveError {
    /// No `supgang` binary on this machine.
    NotInstalled,
    /// Supgang refused or could not answer, in its own words.
    Refused(String),
    /// Supgang answered with a schema this build does not read.
    Schema(String),
    /// The peer has no route-compatible address right now.
    NoAddress,
    /// The peer advertises no service by that name.
    NoService,
    /// The answer was not the shape a signed record has.
    Malformed(String),
    /// The peer's record has expired: nothing signed says where it is now.
    Expired,
    /// Supgang took too long or could not be run.
    Unavailable(String),
}

impl fmt::Display for PeerResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotInstalled => formatter.write_str("Supgang is not installed on this machine"),
            Self::Refused(message) => write!(formatter, "Supgang refused: {message}"),
            Self::Schema(schema) => write!(
                formatter,
                "Supgang answered with schema {schema}; this Remap reads {RESOLVE_SCHEMA}"
            ),
            Self::NoAddress => formatter.write_str("the peer has no route-compatible address now"),
            Self::NoService => formatter.write_str("the peer does not advertise that service"),
            Self::Malformed(detail) => {
                write!(formatter, "Supgang's answer was not a record: {detail}")
            }
            Self::Expired => formatter.write_str("the peer's signed record has expired"),
            Self::Unavailable(detail) => {
                write!(formatter, "Supgang could not be asked: {detail}")
            }
        }
    }
}

impl std::error::Error for PeerResolveError {}

type ResolveFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ResolvedPeerService, PeerResolveError>> + Send + 'a>>;

/// Answers where a peer's service is. The gateway holds one; tests hold a
/// stand-in.
pub trait PeerResolver: Send + Sync + fmt::Debug {
    /// Resolves one peer's advertised service.
    fn resolve<'a>(&'a self, peer: &'a str, service: &'a str) -> ResolveFuture<'a>;
}

/// The resolver that asks the `supgang` binary, remembering each answer
/// until its record expires or [`PEER_CACHE_LIMIT`], whichever is sooner.
pub struct SupgangResolver {
    command: PathBuf,
    cache: Mutex<HashMap<(String, String), (ResolvedPeerService, Instant)>>,
}

impl fmt::Debug for SupgangResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SupgangResolver")
            .field("command", &self.command)
            .finish_non_exhaustive()
    }
}

impl SupgangResolver {
    /// Finds `supgang` on PATH or where the Agenxy installers put it, which
    /// a daemon's PATH does not list. `None` when it is nowhere.
    #[must_use]
    pub fn discover() -> Option<Self> {
        let mut candidates: Vec<PathBuf> = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect())
            .unwrap_or_default();
        if let Some(home) = std::env::var_os("HOME") {
            let home = PathBuf::from(home);
            candidates.push(home.join(".local").join("bin"));
            candidates.push(home.join(".cargo").join("bin"));
        }
        candidates.push(PathBuf::from("/usr/local/bin"));
        candidates.push(PathBuf::from("/opt/homebrew/bin"));
        candidates
            .into_iter()
            .map(|directory| directory.join("supgang"))
            .find(|path| path.is_file())
            .map(Self::at)
    }

    /// A resolver for an explicit binary.
    #[must_use]
    pub fn at(command: PathBuf) -> Self {
        Self {
            command,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, key: &(String, String)) -> Option<ResolvedPeerService> {
        self.cached_at(key, Instant::now(), unix_now())
    }

    /// A remembered answer is good only while BOTH clocks say so: the
    /// monotonic deadline bounds how long an answer is reused, and the
    /// record's own expiry is checked again on every hit, because a system
    /// clock that jumps, or a monotonic clock that paused in sleep, would
    /// otherwise keep an expired record and its key in service.
    fn cached_at(
        &self,
        key: &(String, String),
        now: Instant,
        unix: u64,
    ) -> Option<ResolvedPeerService> {
        let mut cache = self.cache.lock().ok()?;
        let (resolved, until) = cache.get(key)?;
        if now < *until && resolved.expires_at > unix {
            return Some(resolved.clone());
        }
        cache.remove(key);
        None
    }

    fn remember(&self, key: (String, String), resolved: &ResolvedPeerService) {
        let signed_for = Duration::from_secs(resolved.expires_at.saturating_sub(unix_now()));
        let until = Instant::now() + signed_for.min(PEER_CACHE_LIMIT);
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(key, (resolved.clone(), until));
        }
    }

    async fn ask(&self, peer: &str) -> Result<Vec<u8>, PeerResolveError> {
        // The peer is the one caller-supplied word on this argv; the target
        // parser refused a flag-shaped one, and it is refused again here.
        if peer.is_empty() || peer.starts_with('-') {
            return Err(PeerResolveError::Malformed(
                "a peer selector cannot start with '-'".into(),
            ));
        }
        let mut child = Command::new(&self.command)
            .args(["--json", "resolve", peer])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|error| PeerResolveError::Unavailable(error.kind().to_string()))?;
        let mut stdout = child
            .stdout
            .take()
            .ok_or_else(|| PeerResolveError::Unavailable("no output pipe".into()))?;
        let read = async {
            let mut output = Vec::new();
            let mut limited = (&mut stdout).take(MAX_RESOLVE_OUTPUT as u64 + 1);
            limited
                .read_to_end(&mut output)
                .await
                .map_err(|error| PeerResolveError::Unavailable(error.kind().to_string()))?;
            let status = child
                .wait()
                .await
                .map_err(|error| PeerResolveError::Unavailable(error.kind().to_string()))?;
            Ok::<_, PeerResolveError>((output, status))
        };
        let (output, status) = tokio::time::timeout(RESOLVE_TIMEOUT, read)
            .await
            .map_err(|_elapsed| PeerResolveError::Unavailable("timed out".into()))??;
        if output.len() > MAX_RESOLVE_OUTPUT {
            return Err(PeerResolveError::Malformed(
                "the answer was too large".into(),
            ));
        }
        if !status.success() && !looks_like_envelope(&output) {
            return Err(PeerResolveError::Unavailable(format!(
                "exit status {status}"
            )));
        }
        Ok(output)
    }
}

fn looks_like_envelope(output: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(output)
        .is_ok_and(|value| value.get("schema").is_some())
}

impl PeerResolver for SupgangResolver {
    fn resolve<'a>(&'a self, peer: &'a str, service: &'a str) -> ResolveFuture<'a> {
        Box::pin(async move {
            let key = (peer.to_owned(), service.to_owned());
            if let Some(resolved) = self.cached(&key) {
                return Ok(resolved);
            }
            let output = self.ask(peer).await?;
            let resolved = parse_resolution(&output, service, unix_now())?;
            self.remember(key, &resolved);
            Ok(resolved)
        })
    }
}

#[derive(Deserialize)]
struct ResolveEnvelope {
    schema: String,
    status: String,
    #[serde(default)]
    error: String,
    expires_at: Option<u64>,
    #[serde(default)]
    candidates: Vec<Candidate>,
    #[serde(default)]
    services: Vec<ServiceRow>,
}

#[derive(Deserialize)]
struct Candidate {
    address: String,
    #[serde(default)]
    route_compatible: bool,
    #[serde(default)]
    preferred: bool,
}

#[derive(Deserialize)]
struct ServiceRow {
    name: String,
    port: u16,
    key_pin: String,
}

/// Reads one `supgang resolve` answer into the destination for `service`,
/// as of `now` (UNIX seconds): a record that has expired names nothing, and
/// one without an expiry is not a record.
///
/// # Errors
///
/// Returns why the answer names no destination: a refusal, an unknown
/// schema, an expired or unbounded record, no route-compatible address, no
/// such service, or a malformed pin.
pub fn parse_resolution(
    output: &[u8],
    service: &str,
    now: u64,
) -> Result<ResolvedPeerService, PeerResolveError> {
    let envelope: ResolveEnvelope = serde_json::from_slice(output)
        .map_err(|error| PeerResolveError::Malformed(error.to_string()))?;
    if envelope.status == "error" {
        return Err(PeerResolveError::Refused(envelope.error));
    }
    if envelope.schema != RESOLVE_SCHEMA {
        return Err(PeerResolveError::Schema(envelope.schema));
    }
    if envelope.status != "ok" {
        return Err(PeerResolveError::Malformed(format!(
            "status {}",
            envelope.status
        )));
    }
    let expires_at = envelope
        .expires_at
        .ok_or_else(|| PeerResolveError::Malformed("no expiry on the record".into()))?;
    if expires_at <= now {
        return Err(PeerResolveError::Expired);
    }
    let host = envelope
        .candidates
        .iter()
        .filter(|candidate| candidate.route_compatible)
        .max_by_key(|candidate| candidate.preferred)
        .and_then(|candidate| host_of(&candidate.address))
        .ok_or(PeerResolveError::NoAddress)?;
    let row = envelope
        .services
        .iter()
        .find(|row| row.name == service)
        .ok_or(PeerResolveError::NoService)?;
    if row.port == 0 {
        return Err(PeerResolveError::Malformed("service port zero".into()));
    }
    let key_pin = decode_pin(&row.key_pin)
        .ok_or_else(|| PeerResolveError::Malformed("the key pin is not 64 hex digits".into()))?;
    Ok(ResolvedPeerService {
        host,
        port: row.port,
        key_pin,
        expires_at,
    })
}

/// The host of a Supgang candidate `host:port`; the port is Supgang's own.
fn host_of(address: &str) -> Option<IpAddr> {
    let host = address
        .rsplit_once(':')
        .map_or(address, |(host, _port)| host)
        .trim_start_matches('[')
        .trim_end_matches(']');
    host.parse().ok()
}

fn decode_pin(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut pin = [0_u8; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        let pair = text.get(index * 2..index * 2 + 2)?;
        *byte = u8::from_str_radix(pair, 16).ok()?;
    }
    Some(pin)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

/// Verifies an upstream against exactly one advertised key.
///
/// One verifier, and one TLS client, per key (ADR-0016): every connection
/// the client holds, pooled or new, was verified against this key, so a
/// pin can never be reused for another peer, and a peer whose key changes
/// gets a fresh client. The certificate at the top of the presented chain
/// must carry the key, and the leaf must be issued under it for this host:
/// a chain with the peer's public CA appended to a stranger's leaf matches
/// the key and is still refused. No system root is consulted.
#[derive(Debug)]
pub struct PinnedVerifier {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl PinnedVerifier {
    /// A verifier for one advertised key.
    #[must_use]
    pub const fn for_pin(pin: [u8; 32], provider: Arc<CryptoProvider>) -> Self {
        Self { pin, provider }
    }
}

impl ServerCertVerifier for PinnedVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let top = intermediates.last().unwrap_or(end_entity);
        let spki = subject_public_key_info(top.as_ref()).ok_or_else(|| {
            rustls::Error::General("the upstream certificate is not X.509".into())
        })?;
        let digest: [u8; 32] = Sha256::digest(spki).into();
        if digest != self.pin {
            return Err(rustls::Error::General(
                "the upstream presents a key its peer did not advertise".into(),
            ));
        }
        let mut roots = RootCertStore::empty();
        roots
            .add(top.clone().into_owned())
            .map_err(|error| rustls::Error::General(error.to_string()))?;
        let verifier = WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::clone(&self.provider),
        )
        .build()
        .map_err(|error| rustls::Error::General(error.to_string()))?;
        let chain: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .take(intermediates.len().saturating_sub(1))
            .cloned()
            .collect();
        verifier.verify_server_cert(end_entity, &chain, server_name, &[], now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// The DER bytes of a certificate's `SubjectPublicKeyInfo`, the value whose
/// SHA-256 is the pin (RFC 7469). A bounded walk of the outer structure:
/// `Certificate { TBSCertificate { [0] version?, serial, signature, issuer,
/// validity, subject, subjectPublicKeyInfo, ... } ... }`.
#[must_use]
pub fn subject_public_key_info(certificate: &[u8]) -> Option<&[u8]> {
    let (certificate_contents, _signature) = der_element(certificate, 0x30)?;
    let (tbs, _) = der_element(certificate_contents, 0x30)?;
    let mut rest = tbs;
    if rest.first() == Some(&0xA0) {
        rest = der_skip(rest)?;
    }
    for _field in 0..5 {
        rest = der_skip(rest)?;
    }
    let (_contents, after) = der_span(rest)?;
    Some(&rest[..rest.len() - after.len()])
}

/// Splits one DER element of the expected tag into (contents, following).
fn der_element(input: &[u8], tag: u8) -> Option<(&[u8], &[u8])> {
    if *input.first()? != tag {
        return None;
    }
    der_span(input)
}

/// Skips one DER element of any tag.
fn der_skip(input: &[u8]) -> Option<&[u8]> {
    let (_contents, rest) = der_span(input)?;
    Some(rest)
}

/// Splits one DER element of any tag into (contents, following).
fn der_span(input: &[u8]) -> Option<(&[u8], &[u8])> {
    input.first()?;
    let (length, header) = der_length(&input[1..])?;
    let start = 1 + header;
    let end = start.checked_add(length)?;
    Some((input.get(start..end)?, &input[end..]))
}

/// Reads a DER length, returning (length, bytes the length occupied).
fn der_length(input: &[u8]) -> Option<(usize, usize)> {
    let first = *input.first()?;
    if first < 0x80 {
        return Some((usize::from(first), 1));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > 4 {
        return None;
    }
    let mut length = 0_usize;
    for byte in input.get(1..=count)? {
        length = length.checked_shl(8)?.checked_add(usize::from(*byte))?;
    }
    Some((length, 1 + count))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use super::{ResolvedPeerService, SupgangResolver};

    fn resolved(expires_at: u64) -> ResolvedPeerService {
        ResolvedPeerService {
            host: IpAddr::V4(Ipv4Addr::LOCALHOST),
            port: 4777,
            key_pin: [0xab; 32],
            expires_at,
        }
    }

    // A remembered answer outlives neither clock: a record whose own expiry
    // has passed is not served from the cache even while the monotonic
    // deadline it was remembered under is still open, and it is dropped.
    #[test]
    fn a_cached_record_is_dropped_when_its_own_expiry_passes() {
        let resolver = SupgangResolver::at(PathBuf::from("/nonexistent/supgang"));
        let key = ("MacSolis".to_owned(), "dibs".to_owned());
        let now = Instant::now();
        resolver.remember(key.clone(), &resolved(1_789_321_427));
        assert!(
            resolver.cached_at(&key, now, 1_789_300_000).is_some(),
            "a live record was not served from the cache"
        );
        assert!(
            resolver.cached_at(&key, now, 1_789_321_427).is_none(),
            "an expired record was served from the cache"
        );
        assert!(
            resolver.cached_at(&key, now, 1_789_300_000).is_none(),
            "an expired record stayed in the cache"
        );
        resolver.remember(key.clone(), &resolved(1_789_321_427));
        assert!(
            resolver
                .cached_at(&key, now + Duration::from_secs(301), 1_789_300_000)
                .is_none(),
            "a record was reused past the cache limit"
        );
    }
}
