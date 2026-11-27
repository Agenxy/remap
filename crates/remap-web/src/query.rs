// SPDX-License-Identifier: GPL-3.0-or-later
//! Bounded, percent-decoded query strings for the read endpoints.

use remap_protocol::Diagnostic;

/// Longest raw query string accepted. A hostname is at most 253 bytes, so
/// even fully percent-encoded it fits.
pub(crate) const MAX_QUERY_BYTES: usize = 2_048;

/// Returns the one value of `key`, refusing a missing, repeated or unknown
/// parameter, an oversized query, and malformed percent-encoding.
pub(crate) fn single(query: Option<&str>, key: &str) -> Result<String, Diagnostic> {
    let raw = query.unwrap_or_default();
    if raw.len() > MAX_QUERY_BYTES {
        return Err(invalid(format!(
            "the query string is longer than {MAX_QUERY_BYTES} bytes"
        )));
    }
    let mut found = None;
    for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let name = decode(name)?;
        if name != key {
            return Err(invalid(format!("this endpoint takes only '{key}'")));
        }
        if found.replace(decode(value)?).is_some() {
            return Err(invalid(format!("'{key}' is given more than once")));
        }
    }
    found.ok_or_else(|| invalid(format!("'{key}' is required")))
}

/// Decodes `application/x-www-form-urlencoded` text, as `URLSearchParams`
/// writes it: `+` is a space and `%XX` is one byte. The bytes must be UTF-8.
pub(crate) fn decode(encoded: &str) -> Result<String, Diagnostic> {
    let bytes = encoded.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        match byte {
            b'+' => decoded.push(b' '),
            b'%' => {
                let high = bytes.get(index + 1).copied().and_then(hex_value);
                let low = bytes.get(index + 2).copied().and_then(hex_value);
                let (Some(high), Some(low)) = (high, low) else {
                    return Err(invalid("the query string has a malformed percent-escape"));
                };
                decoded.push((high << 4) | low);
                index += 2;
            }
            other => decoded.push(other),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| invalid("the query string is not UTF-8 text"))
}

const fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn invalid(message: impl Into<String>) -> Diagnostic {
    Diagnostic::new(
        "web-query-invalid",
        message,
        Some("send one percent-encoded parameter, as the page does".to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{MAX_QUERY_BYTES, decode, single};

    fn code(result: Result<String, remap_protocol::Diagnostic>) -> Option<String> {
        result.err().map(|diagnostic| diagnostic.code)
    }

    #[test]
    fn decodes_percent_escapes_and_plus() {
        assert_eq!(decode("a%2Eb+c").ok(), Some("a.b c".to_owned()));
        assert_eq!(decode("%2a.lab").ok(), Some("*.lab".to_owned()));
        assert_eq!(decode("caf%C3%A9").ok(), Some("café".to_owned()));
        assert_eq!(decode("").ok(), Some(String::new()));
        for malformed in ["%", "%4", "%zz", "a%g0", "%FF"] {
            assert_eq!(
                code(decode(malformed)).as_deref(),
                Some("web-query-invalid"),
                "{malformed}"
            );
        }
    }

    #[test]
    fn takes_exactly_one_known_parameter() {
        assert_eq!(
            single(Some("name=api.test"), "name").ok(),
            Some("api.test".to_owned())
        );
        assert_eq!(single(Some("name="), "name").ok(), Some(String::new()));
        assert_eq!(single(Some("name"), "name").ok(), Some(String::new()));
        assert_eq!(
            single(Some("&pattern=%2A.lab&"), "pattern").ok(),
            Some("*.lab".to_owned())
        );
        for refused in [
            None,
            Some(""),
            Some("other=1"),
            Some("name=a&name=b"),
            Some("name=a&extra=b"),
        ] {
            assert_eq!(
                code(single(refused, "name")).as_deref(),
                Some("web-query-invalid"),
                "{refused:?}"
            );
        }
    }

    #[test]
    fn bounds_the_query_length() {
        let longest = format!("name={}", "a".repeat(MAX_QUERY_BYTES - 5));
        assert!(single(Some(&longest), "name").is_ok());
        let longer = format!("{longest}a");
        assert_eq!(
            code(single(Some(&longer), "name")).as_deref(),
            Some("web-query-invalid")
        );
    }
}
