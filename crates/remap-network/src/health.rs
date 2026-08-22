use std::fmt::{self, Debug, Formatter};
use std::sync::Arc;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::NetworkError;

/// Exact lowercase hexadecimal byte length of a runtime-health challenge nonce.
pub const HEALTH_NONCE_BYTES: usize = 32;
/// Exact lowercase hexadecimal byte length of an HMAC-SHA-256 proof.
pub const HEALTH_PROOF_BYTES: usize = 64;
/// Maximum runtime instance identifier length carried over local control.
pub const MAX_INSTANCE_ID_BYTES: usize = 64;
/// Maximum runtime release length carried over local control.
pub const MAX_RUNTIME_VERSION_BYTES: usize = 64;

const DNS_DOMAIN: &[u8] = b"remap.runtime-health/v1\0dns\0";
const HTTP_DOMAIN: &[u8] = b"remap.runtime-health/v1\0http\0";

/// One per-daemon-process identity shared by control, DNS, and HTTP runtimes.
#[derive(Clone)]
pub struct RuntimeIdentity {
    inner: Arc<RuntimeIdentityInner>,
}

struct RuntimeIdentityInner {
    secret: Zeroizing<[u8; 32]>,
    instance_id: String,
    version: String,
}

/// Distinct expected DNS and HTTP proofs for one validated challenge.
pub struct RuntimeProofs {
    dns: String,
    http: String,
}

impl RuntimeIdentity {
    /// Creates one identity from 256 bits supplied by the operating system.
    ///
    /// # Errors
    ///
    /// Returns a sanitized failure when identity metadata is invalid or secure
    /// random generation is unavailable.
    pub fn generate(instance_id: String, version: String) -> Result<Self, NetworkError> {
        validate_metadata(&instance_id, MAX_INSTANCE_ID_BYTES)?;
        validate_metadata(&version, MAX_RUNTIME_VERSION_BYTES)?;
        let mut secret = Zeroizing::new([0_u8; 32]);
        getrandom::fill(secret.as_mut()).map_err(|_error| {
            NetworkError::Configuration("secure runtime identity generation failed")
        })?;
        Ok(Self::from_zeroizing_secret(secret, instance_id, version))
    }

    #[cfg(test)]
    fn from_secret(secret: [u8; 32], instance_id: String, version: String) -> Self {
        Self::from_zeroizing_secret(Zeroizing::new(secret), instance_id, version)
    }

    fn from_zeroizing_secret(
        secret: Zeroizing<[u8; 32]>,
        instance_id: String,
        version: String,
    ) -> Self {
        Self {
            inner: Arc::new(RuntimeIdentityInner {
                secret,
                instance_id,
                version,
            }),
        }
    }

    /// Returns the bounded opaque identifier for this running daemon instance.
    #[must_use]
    pub fn instance_id(&self) -> &str {
        &self.inner.instance_id
    }

    /// Returns the bounded release reported by this running daemon instance.
    #[must_use]
    pub fn version(&self) -> &str {
        &self.inner.version
    }

    /// Produces domain-separated proofs only for a valid challenge nonce.
    #[must_use]
    pub fn proofs(&self, nonce: &str) -> Option<RuntimeProofs> {
        let nonce = HealthNonce::parse(nonce)?;
        Some(RuntimeProofs {
            dns: self.proof(DNS_DOMAIN, &nonce)?,
            http: self.proof(HTTP_DOMAIN, &nonce)?,
        })
    }

    fn proof(&self, domain: &[u8], nonce: &HealthNonce) -> Option<String> {
        let mut authenticator = Hmac::<Sha256>::new_from_slice(self.inner.secret.as_ref()).ok()?;
        authenticator.update(domain);
        authenticator.update(&nonce.0);
        let proof = authenticator.finalize().into_bytes();
        let mut encoded = Vec::with_capacity(HEALTH_PROOF_BYTES);
        for byte in proof {
            encoded.push(HEX_DIGITS[usize::from(byte >> 4)]);
            encoded.push(HEX_DIGITS[usize::from(byte & 0x0f)]);
        }
        String::from_utf8(encoded).ok()
    }
}

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

impl RuntimeProofs {
    /// Returns the expected DNS TXT proof.
    #[must_use]
    pub fn dns(&self) -> &str {
        &self.dns
    }

    /// Returns the expected HTTP response-body proof.
    #[must_use]
    pub fn http(&self) -> &str {
        &self.http
    }
}

impl Debug for RuntimeIdentity {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeIdentity")
            .field("instance_id", &self.inner.instance_id)
            .field("version", &self.inner.version)
            .field("secret", &"[redacted]")
            .finish()
    }
}

struct HealthNonce([u8; 16]);

impl HealthNonce {
    fn parse(value: &str) -> Option<Self> {
        if value.len() != HEALTH_NONCE_BYTES {
            return None;
        }
        let mut bytes = [0_u8; 16];
        for (index, pair) in value.as_bytes().as_chunks::<2>().0.iter().enumerate() {
            let high = decode_hex(pair[0])?;
            let low = decode_hex(pair[1])?;
            bytes[index] = (high << 4) | low;
        }
        Some(Self(bytes))
    }
}

const fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn validate_metadata(value: &str, maximum: usize) -> Result<(), NetworkError> {
    if value.is_empty()
        || value.len() > maximum
        || !value.is_ascii()
        || value.bytes().any(|byte| byte.is_ascii_control())
    {
        return Err(NetworkError::Configuration(
            "runtime identity metadata is invalid",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{HEALTH_PROOF_BYTES, RuntimeIdentity};

    #[test]
    fn proofs_are_bounded_domain_separated_and_nonce_bound()
    -> Result<(), Box<dyn std::error::Error>> {
        let identity =
            RuntimeIdentity::from_secret([7_u8; 32], "instance".to_owned(), "1.2.3".to_owned());
        let first = identity
            .proofs("00112233445566778899aabbccddeeff")
            .ok_or("valid nonce rejected")?;
        let second = identity
            .proofs("10112233445566778899aabbccddeeff")
            .ok_or("valid nonce rejected")?;
        assert_eq!(first.dns().len(), HEALTH_PROOF_BYTES);
        assert_eq!(first.http().len(), HEALTH_PROOF_BYTES);
        assert_ne!(first.dns(), first.http());
        assert_ne!(first.dns(), second.dns());
        Ok(())
    }

    #[test]
    fn malformed_nonces_are_rejected() {
        let identity =
            RuntimeIdentity::from_secret([9_u8; 32], "instance".to_owned(), "1.2.3".to_owned());
        for nonce in [
            "",
            "00112233445566778899aabbccddeef",
            "00112233445566778899aabbccddeeff0",
            "00112233445566778899AABBCCDDEEFF",
            "00112233445566778899aabbccddeefg",
        ] {
            assert!(identity.proofs(nonce).is_none());
        }
    }
}
