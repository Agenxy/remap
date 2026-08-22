use std::io;

use serde::Serialize;

use crate::lifecycle_contract::{Operation, PublicationEffect};

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalPayload<'a> {
    schema: &'static str,
    operation: Operation,
    generation_manifest_digest: Option<[u8; 32]>,
    source_manifest_sha256: Option<[u8; 32]>,
    state_digest: [u8; 32],
    effects: &'a [String],
    publications: &'a [PublicationEffect],
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct RecoveryApprovalPayload<'a> {
    schema: &'static str,
    operation: Operation,
    state_digest: [u8; 32],
    effects: &'a [String],
}

pub(crate) fn plan_token(
    operation: Operation,
    generation_manifest_digest: Option<[u8; 32]>,
    source_manifest_sha256: Option<[u8; 32]>,
    state_digest: [u8; 32],
    effects: &[String],
    publications: &[PublicationEffect],
) -> io::Result<String> {
    hex_digest(&ApprovalPayload {
        schema: "remap.linux-approval/v1",
        operation,
        generation_manifest_digest,
        source_manifest_sha256,
        state_digest,
        effects,
        publications,
    })
}

pub(crate) fn recovery_token(state_digest: [u8; 32], effects: &[String]) -> io::Result<String> {
    hex_digest(&RecoveryApprovalPayload {
        schema: "remap.linux-approval/v1",
        operation: Operation::Recover,
        state_digest,
        effects,
    })
}

pub(crate) fn digest<T: Serialize>(value: &T) -> io::Result<[u8; 32]> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_error| invalid_data("the lifecycle state could not be encoded"))?;
    Ok(crate::digest::sha256(&encoded))
}

pub(crate) fn hex(bytes: &[u8; 32]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

pub(crate) fn require_token(expected: &str, provided: &str) -> io::Result<()> {
    let valid_shape = provided.len() == 64
        && provided
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    let equal = valid_shape
        && expected
            .as_bytes()
            .iter()
            .zip(provided.as_bytes())
            .fold(0_u8, |difference, (left, right)| {
                difference | (left ^ right)
            })
            == 0;
    if equal {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the approval token does not authorize the current Linux lifecycle plan",
        ))
    }
}

fn hex_digest<T: Serialize>(value: &T) -> io::Result<String> {
    let encoded = serde_json::to_vec(value)
        .map_err(|_error| invalid_data("the lifecycle approval plan could not be encoded"))?;
    Ok(hex(&crate::digest::sha256(&encoded)))
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
