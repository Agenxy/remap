// SPDX-License-Identifier: GPL-3.0-or-later
//! The per-run capability token (ADR-0041).

use std::fmt;
use std::hint::black_box;

use hyper::HeaderMap;
use hyper::header::AUTHORIZATION;
use remap_protocol::Diagnostic;

/// Bytes of operating-system randomness in one token: 256 bits.
pub(crate) const TOKEN_BYTES: usize = 32;

/// A 256-bit capability, held as 64 lowercase hexadecimal characters.
pub(crate) struct Token {
    hex: String,
}

impl Token {
    /// Draws a fresh token from the operating system's random source.
    pub(crate) fn generate() -> Result<Self, Diagnostic> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        getrandom::fill(&mut bytes).map_err(|_| {
            Diagnostic::new(
                "web-random-unavailable",
                "the operating system's random source did not answer",
                Some(
                    "retry; if it keeps failing, the system's entropy source needs attention"
                        .to_owned(),
                ),
                true,
            )
        })?;
        Ok(Self::from_bytes(bytes))
    }

    /// Encodes known bytes; tests use it for a fixed token.
    pub(crate) fn from_bytes(bytes: [u8; TOKEN_BYTES]) -> Self {
        const DIGITS: &[u8; 16] = b"0123456789abcdef";
        let mut hex = String::with_capacity(TOKEN_BYTES * 2);
        for byte in bytes {
            hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
            hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
        }
        Self { hex }
    }

    /// The encoded token, for the printed URL only.
    pub(crate) fn as_str(&self) -> &str {
        &self.hex
    }

    /// Whether the request carries exactly one `Authorization: Bearer`
    /// header naming this token. The token itself is compared in constant
    /// time; nothing about a refusal says which part was wrong.
    pub(crate) fn authorizes(&self, headers: &HeaderMap) -> bool {
        let mut values = headers.get_all(AUTHORIZATION).iter();
        let (Some(value), None) = (values.next(), values.next()) else {
            return false;
        };
        let bytes = value.as_bytes();
        let Some((scheme, credential)) = bytes.split_at_checked(7) else {
            return false;
        };
        let scheme_matches = scheme.eq_ignore_ascii_case(b"bearer ");
        let token_matches = constant_time_eq(credential, self.hex.as_bytes());
        scheme_matches & token_matches
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Token(redacted)")
    }
}

/// Compares two byte strings without an early exit on the first difference.
/// A length mismatch returns at once: the token's length is public.
pub(crate) fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            black_box(difference | (left ^ right))
        });
    black_box(difference) == 0
}

#[cfg(test)]
mod tests {
    use hyper::HeaderMap;
    use hyper::header::{AUTHORIZATION, HeaderValue};

    use super::{TOKEN_BYTES, Token, constant_time_eq};

    fn bearer(value: &str) -> Result<HeaderMap, Box<dyn std::error::Error>> {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_str(value)?);
        Ok(headers)
    }

    #[test]
    fn constant_time_compare_agrees_with_equality() {
        assert!(constant_time_eq(b"", b""));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"bbc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"abcd", b"abc"));
        assert!(!constant_time_eq(b"", b"a"));
    }

    #[test]
    fn generated_tokens_are_256_bit_lowercase_hex_and_distinct()
    -> Result<(), Box<dyn std::error::Error>> {
        let first = Token::generate()?;
        let second = Token::generate()?;
        assert_eq!(first.as_str().len(), TOKEN_BYTES * 2);
        assert!(
            first
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
        assert_ne!(first.as_str(), second.as_str());
        assert_eq!(format!("{first:?}"), "Token(redacted)");
        Ok(())
    }

    #[test]
    fn encodes_bytes_as_hex() {
        let mut bytes = [0_u8; TOKEN_BYTES];
        bytes[0] = 0xab;
        bytes[31] = 0x0f;
        let token = Token::from_bytes(bytes);
        assert!(token.as_str().starts_with("ab00"));
        assert!(token.as_str().ends_with("000f"));
    }

    #[test]
    fn authorizes_only_the_exact_bearer_token() -> Result<(), Box<dyn std::error::Error>> {
        let token = Token::from_bytes([0xab_u8; TOKEN_BYTES]);
        let secret = token.as_str().to_owned();
        assert!(token.authorizes(&bearer(&format!("Bearer {secret}"))?));
        assert!(token.authorizes(&bearer(&format!("bearer {secret}"))?));
        assert!(!token.authorizes(&HeaderMap::new()));
        assert!(!token.authorizes(&bearer(&secret)?));
        assert!(!token.authorizes(&bearer(&format!("Basic {secret}"))?));
        assert!(!token.authorizes(&bearer(&format!("Bearer  {secret}"))?));
        assert!(!token.authorizes(&bearer(&format!("Bearer {}", secret.to_uppercase()))?));
        assert!(!token.authorizes(&bearer(&format!("Bearer {secret}0"))?));
        assert!(!token.authorizes(&bearer("Bearer")?));
        let mut twice = bearer(&format!("Bearer {secret}"))?;
        twice.append(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {secret}"))?,
        );
        assert!(!token.authorizes(&twice));
        Ok(())
    }
}
