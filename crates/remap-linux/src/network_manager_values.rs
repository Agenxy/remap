// SPDX-License-Identifier: GPL-3.0-or-later
//! Typed reads and writes of the `NetworkManager` setting values Remap owns.

use std::collections::BTreeMap;

use zbus::{OwnedVariant, Variant};

use super::{LEGACY_DNS, invalid_state};
use crate::{LinuxResult, NetworkManagerLegacyDns};

pub(super) fn optional_strings(value: Option<&OwnedVariant>) -> LinuxResult<Option<Vec<String>>> {
    value
        .map(|value| {
            value
                .try_clone()
                .map_err(|_error| invalid_state())
                .and_then(|value| Vec::<String>::try_from(value).map_err(|_error| invalid_state()))
        })
        .transpose()
}

pub(super) fn optional_bool(value: Option<&OwnedVariant>) -> LinuxResult<Option<bool>> {
    value.map(value_bool).transpose()
}

pub(super) fn optional_i32(value: Option<&OwnedVariant>) -> LinuxResult<Option<i32>> {
    value.map(value_i32).transpose()
}

pub(super) fn optional_legacy_dns(
    value: Option<&OwnedVariant>,
    ipv4: bool,
) -> LinuxResult<Option<NetworkManagerLegacyDns>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.try_clone().map_err(|_error| invalid_state())?;
    if ipv4 {
        Vec::<u32>::try_from(value)
            .map(NetworkManagerLegacyDns::Ipv4)
            .map(Some)
            .map_err(|_error| invalid_state())
    } else {
        Vec::<Vec<u8>>::try_from(value)
            .map(NetworkManagerLegacyDns::Ipv6)
            .map(Some)
            .map_err(|_error| invalid_state())
    }
}

pub(super) fn value_string(value: &OwnedVariant) -> LinuxResult<String> {
    value
        .try_clone()
        .map_err(|_error| invalid_state())
        .and_then(|value| String::try_from(value).map_err(|_error| invalid_state()))
}

pub(super) fn value_bool(value: &OwnedVariant) -> LinuxResult<bool> {
    bool::try_from(value).map_err(|_error| invalid_state())
}

pub(super) fn value_i32(value: &OwnedVariant) -> LinuxResult<i32> {
    i32::try_from(value).map_err(|_error| invalid_state())
}

pub(super) fn insert_strings(
    section: &mut BTreeMap<String, OwnedVariant>,
    name: &str,
    values: &[&str],
) -> LinuxResult<()> {
    let values = values
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    let value = OwnedVariant::try_from(Variant::new(values)).map_err(|_error| invalid_state())?;
    section.insert(name.to_owned(), value);
    Ok(())
}

pub(super) fn insert_legacy_ipv4(
    section: &mut BTreeMap<String, OwnedVariant>,
    values: &[u32],
) -> LinuxResult<()> {
    let value =
        OwnedVariant::try_from(Variant::new(values.to_vec())).map_err(|_error| invalid_state())?;
    section.insert(LEGACY_DNS.to_owned(), value);
    Ok(())
}

pub(super) fn insert_legacy_ipv6(
    section: &mut BTreeMap<String, OwnedVariant>,
    values: &[Vec<u8>],
) -> LinuxResult<()> {
    let value =
        OwnedVariant::try_from(Variant::new(values.to_vec())).map_err(|_error| invalid_state())?;
    section.insert(LEGACY_DNS.to_owned(), value);
    Ok(())
}

pub(super) fn restore_strings(
    section: &mut BTreeMap<String, OwnedVariant>,
    name: &str,
    value: Option<&Vec<String>>,
) -> LinuxResult<()> {
    match value {
        Some(values) => {
            let value = OwnedVariant::try_from(Variant::new(values.clone()))
                .map_err(|_error| invalid_state())?;
            section.insert(name.to_owned(), value);
        }
        None => {
            section.remove(name);
        }
    }
    Ok(())
}

pub(super) fn restore_bool(
    section: &mut BTreeMap<String, OwnedVariant>,
    name: &str,
    value: Option<bool>,
) {
    match value {
        Some(value) => {
            section.insert(name.to_owned(), OwnedVariant::from(value));
        }
        None => {
            section.remove(name);
        }
    }
}

pub(super) fn restore_i32(
    section: &mut BTreeMap<String, OwnedVariant>,
    name: &str,
    value: Option<i32>,
) {
    match value {
        Some(value) => {
            section.insert(name.to_owned(), OwnedVariant::from(value));
        }
        None => {
            section.remove(name);
        }
    }
}

pub(super) fn restore_legacy(
    section: &mut BTreeMap<String, OwnedVariant>,
    value: Option<&NetworkManagerLegacyDns>,
) -> LinuxResult<()> {
    match value {
        Some(NetworkManagerLegacyDns::Ipv4(values)) => insert_legacy_ipv4(section, values),
        Some(NetworkManagerLegacyDns::Ipv6(values)) => insert_legacy_ipv6(section, values),
        None => {
            section.remove(LEGACY_DNS);
            Ok(())
        }
    }
}
