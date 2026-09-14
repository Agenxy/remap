//! Executable specifications for routing to a Supgang peer's service
//! (ADR-0016): what a signed answer becomes, and which upstream keys the
//! gateway then accepts.

use std::error::Error;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use remap_network::{PeerResolveError, PinnedVerifier, parse_resolution, subject_public_key_info};
use rustls::client::danger::ServerCertVerifier;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

type TestResult = Result<(), Box<dyn Error>>;

fn fixture(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let text = match name {
        "ca" => include_str!("fixtures/ca.der.hex"),
        "leaf" => include_str!("fixtures/leaf.der.hex"),
        "impostor" => include_str!("fixtures/impostor.der.hex"),
        "pin" => include_str!("fixtures/ca.pin.hex"),
        _ => return Err("unknown fixture".into()),
    }
    .trim();
    (0..text.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&text[index..index + 2], 16).map_err(Into::into))
        .collect()
}

fn pin_bytes() -> Result<[u8; 32], Box<dyn Error>> {
    fixture("pin")?
        .try_into()
        .map_err(|_| "the pin fixture is not 32 bytes".into())
}

const NOW: u64 = 1_789_300_000;

const ANSWER: &str = r#"{"schema":"supgang.resolve/v5","status":"ok","node_id":"a8a37e32c37cdf4fb7634de622bc3f84ccb4636580d1ea26af3fe8ac31d1f152","name":"MacSolis","tags":["solis"],"fingerprint":"a8a37e32","generation":0,"sequence":217,"issued_at":1789299827,"expires_at":1789321427,"candidates":[{"scope":"public","kind":"direct","transport":"quic-v1","address":"[2600:1700:2f70:ce40::c]:44330","provenance":"device-signed","route_compatible":false,"preferred":false},{"scope":"local","kind":"local","transport":"quic-v1","address":"192.168.1.191:44330","provenance":"device-signed","route_compatible":true,"preferred":true}],"services":[{"name":"dibs","port":4777,"key_pin":"abababababababababababababababababababababababababababababababab"}]}"#;

// A signed answer becomes the preferred route-compatible host, the service's
// own port, and its key; Supgang's own port is never the destination.
#[test]
fn a_signed_answer_becomes_a_pinned_destination() -> TestResult {
    let resolved = parse_resolution(ANSWER.as_bytes(), "dibs", NOW)?;
    assert_eq!(resolved.host, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 191)));
    assert_eq!(resolved.port, 4777);
    assert_eq!(resolved.key_pin, [0xab; 32]);
    assert_eq!(resolved.expires_at, 1_789_321_427);
    Ok(())
}

// Each way an answer names no destination is its own reason, never a
// fallback to an unpinned or unresolved dial.
#[test]
fn every_failure_to_resolve_is_named() {
    assert_eq!(
        parse_resolution(ANSWER.as_bytes(), "remap", NOW),
        Err(PeerResolveError::NoService)
    );
    let unreachable = ANSWER.replace(r#""route_compatible":true"#, r#""route_compatible":false"#);
    assert_eq!(
        parse_resolution(unreachable.as_bytes(), "dibs", NOW),
        Err(PeerResolveError::NoAddress)
    );
    let older = ANSWER.replace("supgang.resolve/v5", "supgang.resolve/v4");
    assert!(matches!(
        parse_resolution(older.as_bytes(), "dibs", NOW),
        Err(PeerResolveError::Schema(_))
    ));
    let refused = r#"{"schema":"supgang.error/v1","status":"error","error":"no known peer significantly matches that name, tag, or fingerprint"}"#;
    assert!(matches!(
        parse_resolution(refused.as_bytes(), "dibs", NOW),
        Err(PeerResolveError::Refused(message)) if message.contains("no known peer")
    ));
    let bad_pin = ANSWER.replace(&"ab".repeat(32), "notakeypin");
    assert!(matches!(
        parse_resolution(bad_pin.as_bytes(), "dibs", NOW),
        Err(PeerResolveError::Malformed(_))
    ));
    assert!(matches!(
        parse_resolution(b"not json", "dibs", NOW),
        Err(PeerResolveError::Malformed(_))
    ));
}

// A record that has expired names nothing, one with no expiry is not a
// record, and the boundary second is already expired: a stale signature is
// never a destination, however recently it was.
#[test]
fn an_expired_or_unbounded_record_names_nothing() {
    assert_eq!(
        parse_resolution(ANSWER.as_bytes(), "dibs", 1_789_321_427),
        Err(PeerResolveError::Expired)
    );
    assert_eq!(
        parse_resolution(ANSWER.as_bytes(), "dibs", 1_800_000_000),
        Err(PeerResolveError::Expired)
    );
    assert!(parse_resolution(ANSWER.as_bytes(), "dibs", 1_789_321_426).is_ok());
    let unbounded = ANSWER.replace(r#""expires_at":1789321427,"#, "");
    assert!(matches!(
        parse_resolution(unbounded.as_bytes(), "dibs", NOW),
        Err(PeerResolveError::Malformed(_))
    ));
}

// The pin is the SHA-256 of the certificate's SubjectPublicKeyInfo, read out
// of the DER by the same walk the verifier uses, and it matches what the
// certificate's issuer computed (the fixture pin came from Go's x509).
#[test]
fn the_pin_is_the_subject_public_key_info_digest() -> TestResult {
    let ca = fixture("ca")?;
    let spki = subject_public_key_info(&ca).ok_or("a certificate has a public key")?;
    let digest: [u8; 32] = Sha256::digest(spki).into();
    assert_eq!(digest, pin_bytes()?);
    assert!(subject_public_key_info(b"\x30\x03\x02\x01\x00").is_none());
    assert!(subject_public_key_info(&[]).is_none());
    Ok(())
}

fn pinned_verifier(pin: [u8; 32]) -> PinnedVerifier {
    PinnedVerifier::for_pin(pin, Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
}

fn at_2026_09_14() -> UnixTime {
    UnixTime::since_unix_epoch(std::time::Duration::from_secs(NOW))
}

// A client for one advertised key accepts a chain only when the top of it
// carries that key AND the leaf is issued under it for the host dialled. An
// impostor that appends the peer's public CA to its own leaf matches the key
// and is refused; a stranger's key is refused; the right chain for another
// host is refused; and a client for a different key refuses the peer's chain.
#[test]
fn the_gateway_accepts_only_the_key_the_peer_advertised() -> TestResult {
    let verifier = pinned_verifier(pin_bytes()?);
    let host = ServerName::try_from("127.0.0.1")?;
    let ca = CertificateDer::from(fixture("ca")?);
    let leaf = CertificateDer::from(fixture("leaf")?);
    let impostor = CertificateDer::from(fixture("impostor")?);
    let now = at_2026_09_14();

    verifier.verify_server_cert(&leaf, std::slice::from_ref(&ca), &host, &[], now)?;

    let appended =
        verifier.verify_server_cert(&impostor, std::slice::from_ref(&ca), &host, &[], now);
    assert!(
        appended.is_err(),
        "an impostor's leaf with the peer's CA appended was accepted"
    );
    let strangers = verifier.verify_server_cert(&impostor, &[], &host, &[], now);
    assert!(
        strangers.is_err(),
        "a key the peer never advertised was accepted"
    );
    let elsewhere = ServerName::try_from("10.0.0.9")?;
    assert!(
        verifier
            .verify_server_cert(&leaf, std::slice::from_ref(&ca), &elsewhere, &[], now)
            .is_err(),
        "the peer's chain was accepted for a host it does not name"
    );
    let other_key = pinned_verifier([0x11; 32]);
    assert!(
        other_key
            .verify_server_cert(&leaf, std::slice::from_ref(&ca), &host, &[], now)
            .is_err(),
        "a client for another key accepted this peer's chain"
    );
    Ok(())
}
