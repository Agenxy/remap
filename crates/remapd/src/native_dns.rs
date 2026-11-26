// SPDX-License-Identifier: GPL-3.0-or-later
//! Reads the macOS root-owned record of the owner turning Remap DNS off on
//! purpose (ADR-0036), so status can tell that from a fault and from DNS that
//! was never activated. The record is written only by `remap-system`; this
//! reader verifies its owner, mode, size, schema, and digest and otherwise
//! reports nothing.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use remap_protocol::DnsTurnedOff;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const MAXIMUM_RECORD_BYTES: u64 = 4 * 1024;
const DEACTIVATE_COMMAND: &str = "remap-system deactivate";
const INSTALLED_REMAP_SYSTEM: &str =
    "/Library/Application Support/Agenxy/Remap/Install/current/libexec/remap-system";
const INSTALLED_SYSTEM_SOCKET: &str = "/var/run/org.agenxy.Remap.system.sock";

/// Where the root-owned DNS turned-off record lives and who must own it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TurnedOffRecordSource {
    /// The record file, beside the native activation record.
    pub path: PathBuf,
    /// The account that must own it: root in the product.
    pub owner_uid: u32,
}

impl TurnedOffRecordSource {
    /// The installed macOS location; other platforms have none.
    #[must_use]
    pub fn standard() -> Option<Self> {
        cfg!(target_os = "macos").then(|| Self {
            path: PathBuf::from("/Library/Application Support/Agenxy/Remap/dns-turned-off-v1.json"),
            owner_uid: 0,
        })
    }

    /// The verified record, or nothing when it is absent or not trustworthy.
    pub(crate) fn read(&self) -> Option<DnsTurnedOff> {
        let data = self.read_bytes()?;
        let record: Record = serde_json::from_slice(&data).ok()?;
        record.verified()
    }

    fn read_bytes(&self) -> Option<Vec<u8>> {
        let trusted = |metadata: &std::fs::Metadata| {
            metadata.is_file()
                && metadata.uid() == self.owner_uid
                && metadata.mode() & 0o7777 == 0o644
                && metadata.len() <= MAXIMUM_RECORD_BYTES
        };
        if !trusted(&std::fs::symlink_metadata(&self.path).ok()?) {
            return None;
        }
        let mut file = File::options()
            .read(true)
            .custom_flags(nix::libc::O_NOFOLLOW)
            .open(&self.path)
            .ok()?;
        if !trusted(&file.metadata().ok()?) {
            return None;
        }
        let mut data = Vec::new();
        file.by_ref()
            .take(MAXIMUM_RECORD_BYTES + 1)
            .read_to_end(&mut data)
            .ok()?;
        (data.len() as u64 <= MAXIMUM_RECORD_BYTES).then_some(data)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    payload: Payload,
    sha256: String,
}

/// Fields in the sorted order Swift's canonical encoder writes, so the
/// digest is over the same bytes.
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    command: String,
    #[serde(rename = "ownerUID")]
    owner_uid: u32,
    #[serde(rename = "productVersion")]
    product_version: String,
    #[serde(rename = "schemaVersion")]
    schema_version: u32,
    #[serde(rename = "turnedOffAtMilliseconds")]
    turned_off_at_milliseconds: u64,
}

impl Record {
    fn verified(self) -> Option<DnsTurnedOff> {
        let payload = self.payload;
        let version_is_plain = payload
            .product_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'));
        if payload.schema_version != 1
            || payload.command != DEACTIVATE_COMMAND
            || payload.owner_uid == 0
            || payload.product_version.is_empty()
            || payload.product_version.len() > 64
            || !version_is_plain
        {
            return None;
        }
        let canonical = serde_json::to_vec(&payload).ok()?;
        if hex(&Sha256::digest(&canonical)) != self.sha256 {
            return None;
        }
        let turned_off_at = chrono::DateTime::from_timestamp_millis(
            i64::try_from(payload.turned_off_at_milliseconds).ok()?,
        )?
        .format("%Y-%m-%dT%H:%MZ")
        .to_string();
        Some(DnsTurnedOff {
            turned_off_at,
            turned_off_at_ms: payload.turned_off_at_milliseconds,
            turn_on: format!(
                "sudo '{INSTALLED_REMAP_SYSTEM}' activate --owner-uid {} --product-version {} \
                 --system-socket {INSTALLED_SYSTEM_SOCKET}",
                payload.owner_uid, payload.product_version
            ),
            command: payload.command,
        })
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(DIGITS[usize::from(byte >> 4)]));
        encoded.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    encoded
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::fs::Permissions;
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::TurnedOffRecordSource;

    /// The exact bytes `remap-system` writes for this payload; the Swift
    /// test `theTurnedOffRecordHasAStableCanonicalForm` checks the same.
    const RECORD: &str = concat!(
        r#"{"payload":{"command":"remap-system deactivate","ownerUID":501,"#,
        r#""productVersion":"0.2.0","schemaVersion":1,"turnedOffAtMilliseconds":1793409600000},"#,
        r#""sha256":"e36ff5314b7d49cfec7182148bf33cebc66dc6ae4a66b2f3609128a2f103f24a"}"#
    );

    fn source(directory: &tempfile::TempDir) -> TurnedOffRecordSource {
        TurnedOffRecordSource {
            path: directory.path().join("dns-turned-off-v1.json"),
            owner_uid: nix::unistd::Uid::effective().as_raw(),
        }
    }

    fn write(source: &TurnedOffRecordSource, data: &str, mode: u32) -> Result<(), Box<dyn Error>> {
        std::fs::write(&source.path, data)?;
        std::fs::set_permissions(&source.path, Permissions::from_mode(mode))?;
        Ok(())
    }

    #[test]
    fn a_verified_record_says_when_how_and_how_to_turn_dns_back_on() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let source = source(&directory);
        assert_eq!(source.read(), None);
        write(&source, RECORD, 0o644)?;

        let turned_off = source.read().ok_or("the verified record was not read")?;

        assert_eq!(turned_off.turned_off_at, "2026-10-31T01:20Z");
        assert_eq!(turned_off.turned_off_at_ms, 1_793_409_600_000);
        assert_eq!(
            turned_off.status_line(),
            "turned off by the owner at 2026-10-31T01:20Z (`remap-system deactivate`)"
        );
        assert_eq!(
            turned_off.turn_on,
            "sudo '/Library/Application Support/Agenxy/Remap/Install/current/libexec/remap-system' \
             activate --owner-uid 501 --product-version 0.2.0 \
             --system-socket /var/run/org.agenxy.Remap.system.sock"
        );
        Ok(())
    }

    #[test]
    fn an_untrustworthy_record_reports_nothing() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let source = source(&directory);
        for (data, mode) in [
            (RECORD, 0o666),
            (RECORD, 0o600),
            (&RECORD.replace("501", "502")[..], 0o644),
            (
                &RECORD.replace("remap-system deactivate", "rm -rf")[..],
                0o644,
            ),
            ("{}", 0o644),
        ] {
            write(&source, data, mode)?;
            assert_eq!(source.read(), None, "accepted {data} at {mode:o}");
        }
        std::fs::remove_file(&source.path)?;
        let target = directory.path().join("elsewhere.json");
        std::fs::write(&target, RECORD)?;
        std::fs::set_permissions(&target, Permissions::from_mode(0o644))?;
        symlink(&target, &source.path)?;
        assert_eq!(source.read(), None);
        let foreign = TurnedOffRecordSource {
            path: target,
            owner_uid: source.owner_uid.wrapping_add(1),
        };
        assert_eq!(foreign.read(), None);
        Ok(())
    }
}
