// SPDX-License-Identifier: GPL-3.0-or-later
//! The `Host` and `Origin` allow-lists that defeat DNS rebinding and
//! cross-site requests (ADR-0041).
//!
//! Remap itself can point any name at `127.0.0.1`, so a name is trusted
//! only when it is the loopback listener or the owner's own `--name`.

use remap_protocol::Diagnostic;

const MAX_NAME_BYTES: usize = 253;
const MAX_LABEL_BYTES: usize = 63;

/// The exact hosts and origins one listener accepts.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Allowed {
    hosts: Vec<String>,
    origins: Vec<String>,
}

impl Allowed {
    /// Builds the allow-lists for a bound port and an already validated,
    /// lowercase `--name`.
    pub(crate) fn new(port: u16, name: Option<String>) -> Self {
        let mut hosts = vec![format!("127.0.0.1:{port}"), format!("localhost:{port}")];
        // A browser leaves the default port out of `Host` and `Origin`.
        if port == 80 {
            hosts.extend(["127.0.0.1".to_owned(), "localhost".to_owned()]);
        }
        let mut origins = hosts
            .iter()
            .map(|host| format!("http://{host}"))
            .collect::<Vec<_>>();
        if let Some(name) = name {
            let named = [name.clone(), format!("{name}:{port}")];
            for host in &named {
                origins.push(format!("http://{host}"));
                origins.push(format!("https://{host}"));
            }
            hosts.extend(named);
        }
        Self { hosts, origins }
    }

    /// Whether a `Host` header value names this listener.
    pub(crate) fn host(&self, value: &[u8]) -> bool {
        Self::contains(&self.hosts, value)
    }

    /// Whether an `Origin` header value is one of this listener's origins.
    pub(crate) fn origin(&self, value: &[u8]) -> bool {
        Self::contains(&self.origins, value)
    }

    fn contains(allowed: &[String], value: &[u8]) -> bool {
        allowed
            .iter()
            .any(|candidate| candidate.as_bytes().eq_ignore_ascii_case(value))
    }
}

/// Validates `--name` as a DNS hostname and returns it in lowercase.
///
/// Single-label names are valid, as everywhere in Remap. An all-numeric
/// final label is refused, so an address literal cannot pass as a name.
pub(crate) fn validate_name(raw: &str) -> Result<String, Diagnostic> {
    let name = raw.to_ascii_lowercase();
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(invalid_name("it must be from 1 through 253 characters"));
    }
    let labels = name.split('.').collect::<Vec<_>>();
    for label in &labels {
        if label.is_empty() || label.len() > MAX_LABEL_BYTES {
            return Err(invalid_name(
                "each dot-separated label must be from 1 through 63 characters",
            ));
        }
        if !label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(invalid_name(
                "use only letters, digits and hyphens, with no scheme, port or path",
            ));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid_name("a label cannot start or end with a hyphen"));
        }
    }
    if labels
        .last()
        .is_some_and(|last| last.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(invalid_name(
            "an address is not a name; the last label must not be all digits",
        ));
    }
    Ok(name)
}

fn invalid_name(reason: &str) -> Diagnostic {
    Diagnostic::new(
        "web-name-invalid",
        format!("the --name value is not a hostname: {reason}"),
        Some("pass the hostname you open the page by, such as --name remap.lab".to_owned()),
        false,
    )
}

#[cfg(test)]
mod tests {
    use super::{Allowed, validate_name};

    #[test]
    fn hosts_are_exactly_the_loopback_listener() {
        let allowed = Allowed::new(7341, None);
        assert!(allowed.host(b"127.0.0.1:7341"));
        assert!(allowed.host(b"localhost:7341"));
        assert!(allowed.host(b"LOCALHOST:7341"));
        for refused in [
            &b"127.0.0.1"[..],
            b"localhost",
            b"127.0.0.1:7342",
            b"127.0.0.2:7341",
            b"[::1]:7341",
            b"evil.example:7341",
            b"localhost.evil.example:7341",
            b"127.0.0.1:7341.evil.example",
            b"127.0.0.1:7341 ",
            b"",
        ] {
            assert!(
                !allowed.host(refused),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[test]
    fn the_default_port_may_be_left_out() {
        let allowed = Allowed::new(80, None);
        assert!(allowed.host(b"127.0.0.1"));
        assert!(allowed.host(b"localhost:80"));
        assert!(allowed.origin(b"http://localhost"));
    }

    #[test]
    fn origins_are_the_loopback_listener_over_http() {
        let allowed = Allowed::new(7341, None);
        assert!(allowed.origin(b"http://127.0.0.1:7341"));
        assert!(allowed.origin(b"http://localhost:7341"));
        for refused in [
            &b"https://127.0.0.1:7341"[..],
            b"http://127.0.0.1:7342",
            b"http://127.0.0.1",
            b"http://evil.example",
            b"http://evil.example:7341",
            b"null",
            b"http://127.0.0.1:7341/",
            b"",
        ] {
            assert!(
                !allowed.origin(refused),
                "{}",
                String::from_utf8_lossy(refused)
            );
        }
    }

    #[test]
    fn a_name_adds_its_host_and_both_schemes() {
        let allowed = Allowed::new(7341, Some("remap.lab".to_owned()));
        assert!(allowed.host(b"remap.lab"));
        assert!(allowed.host(b"remap.lab:7341"));
        assert!(allowed.host(b"Remap.Lab"));
        assert!(!allowed.host(b"remap.lab:8080"));
        assert!(!allowed.host(b"x.remap.lab"));
        for accepted in [
            &b"http://remap.lab"[..],
            b"https://remap.lab",
            b"http://remap.lab:7341",
            b"https://remap.lab:7341",
        ] {
            assert!(
                allowed.origin(accepted),
                "{}",
                String::from_utf8_lossy(accepted)
            );
        }
        assert!(!allowed.origin(b"ftp://remap.lab"));
        assert!(!allowed.origin(b"https://remap.lab:8443"));
        assert!(!allowed.origin(b"https://remap.lab.evil.example"));
    }

    #[test]
    fn names_are_validated_and_lowercased() {
        assert_eq!(
            validate_name("Remap.Lab").ok(),
            Some("remap.lab".to_owned())
        );
        assert_eq!(validate_name("lab").ok(), Some("lab".to_owned()));
        assert_eq!(
            validate_name("a-1.b2.test").ok(),
            Some("a-1.b2.test".to_owned())
        );
        assert_eq!(validate_name("x.1a").ok(), Some("x.1a".to_owned()));
        let longest = format!("{}.{}", "a".repeat(63), "b".repeat(63));
        assert!(validate_name(&longest).is_ok());
        for refused in [
            "",
            ".",
            "remap..lab",
            "remap.lab.",
            ".remap.lab",
            "-remap.lab",
            "remap-.lab",
            "remap_lab",
            "remap.lab:7341",
            "http://remap.lab",
            "remap.lab/",
            "*.lab",
            "re map",
            "rémap.lab",
            "127.0.0.1",
            "10",
            &"a".repeat(64),
            &format!("{}lab", "a.".repeat(126)),
        ] {
            let refusal = validate_name(refused).err();
            assert_eq!(
                refusal.as_ref().map(|diagnostic| diagnostic.code.as_str()),
                Some("web-name-invalid"),
                "{refused:?}"
            );
            assert!(refusal.and_then(|diagnostic| diagnostic.hint).is_some());
        }
    }
}
