use sha2::{Digest, Sha256};

/// Returns the SHA-256 digest of one exact byte sequence.
pub(crate) fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
