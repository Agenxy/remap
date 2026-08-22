use std::collections::BTreeMap;

use zbus::zvariant::{OwnedValue, Value};

use super::{
    DNS_DATA, DNS_PRIORITY, DNS_SEARCH, IGNORE_AUTO_DNS, IPV4, IPV6, LEGACY_DNS,
    NetworkManagerOwnership, Settings, active_rebase_mode, apply_owned_dns, connection_is_owned,
    digest, manager_identity_ready, prepare_owned_connection_rebase, protected_digest,
    require_interface_identity, restore_dns, snapshot_ip_dns,
};

#[test]
fn selected_network_manager_outage_retries_but_positive_manager_drift_conflicts() {
    assert_eq!(
        manager_identity_ready(
            false,
            crate::ResolverLinkManager::SystemdResolved,
            "eth0",
            "eth0"
        ),
        Ok(false)
    );
    assert!(
        manager_identity_ready(
            true,
            crate::ResolverLinkManager::SystemdNetworkd,
            "eth0",
            "eth0"
        )
        .is_err()
    );
}

#[test]
fn post_inspection_interface_switch_is_rejected_before_transaction_effects() {
    assert!(require_interface_identity("eth0", "eth0").is_ok());
    assert!(require_interface_identity("eth0", "renamed0").is_err());
}

#[test]
fn normalized_owned_connection_restores_exact_prior_and_detects_drift()
-> Result<(), Box<dyn std::error::Error>> {
    let before = fixture_settings()?;
    let ipv4 = snapshot_ip_dns(&before, IPV4)?;
    let ipv6 = snapshot_ip_dns(&before, IPV6)?;
    let mut normalized = apply_owned_dns(&before)?;
    normalize_empty_ipv6(&mut normalized);
    let ownership = NetworkManagerOwnership::new(
        "nm-test0".to_owned(),
        digest(&before)?,
        protected_digest(&before)?,
        ipv4,
        ipv6,
    )?;
    let applied = super::AppliedConnection {
        digest: digest(&normalized)?,
        settings: normalized.clone(),
        version: 2,
    };
    assert!(connection_is_owned(&applied, &ownership)?);
    assert_eq!(restore_dns(&normalized, &ownership)?, before);

    let ipv4 = normalized
        .get_mut(IPV4)
        .ok_or_else(|| std::io::Error::other("fixture IPv4 section is absent"))?;
    ipv4.insert("never-default".to_owned(), OwnedValue::from(false));
    let drifted = super::AppliedConnection {
        digest: digest(&normalized)?,
        settings: normalized,
        version: 3,
    };
    assert!(!connection_is_owned(&drifted, &ownership)?);
    Ok(())
}

#[test]
fn protected_drift_with_owned_dns_preserves_the_prior_restoration_fields()
-> Result<(), Box<dyn std::error::Error>> {
    let before = fixture_settings()?;
    let ipv4 = snapshot_ip_dns(&before, IPV4)?;
    let ipv6 = snapshot_ip_dns(&before, IPV6)?;
    let mut normalized = apply_owned_dns(&before)?;
    normalize_empty_ipv6(&mut normalized);
    let prior = NetworkManagerOwnership::new(
        "nm-test0".to_owned(),
        digest(&before)?,
        protected_digest(&before)?,
        ipv4,
        ipv6,
    )?;
    let ipv4 = normalized
        .get_mut(IPV4)
        .ok_or_else(|| std::io::Error::other("fixture IPv4 section is absent"))?;
    ipv4.insert("never-default".to_owned(), OwnedValue::from(false));
    let applied = super::AppliedConnection {
        digest: digest(&normalized)?,
        settings: normalized.clone(),
        version: 3,
    };
    assert!(!connection_is_owned(&applied, &prior)?);

    let successor = prepare_owned_connection_rebase("nm-test0", &applied, &prior)?;
    assert!(connection_is_owned(&applied, &successor)?);
    let restored = restore_dns(&normalized, &successor)?;
    let restored_ipv4 = restored
        .get(IPV4)
        .ok_or_else(|| std::io::Error::other("restored IPv4 section is absent"))?;
    assert_eq!(
        restored_ipv4.get("never-default"),
        Some(&OwnedValue::from(false))
    );
    assert_eq!(snapshot_ip_dns(&restored, IPV4)?, prior.ipv4().cloned());
    assert_eq!(digest(&restored)?, successor.before_connection_digest());
    Ok(())
}

#[test]
fn mixed_applied_connection_and_resolved_drift_fails_closed() {
    assert!(active_rebase_mode(true, true).is_ok_and(|direct| direct));
    assert!(active_rebase_mode(false, false).is_ok_and(|direct| !direct));
    assert!(active_rebase_mode(true, false).is_err());
    assert!(active_rebase_mode(false, true).is_err());
}

fn fixture_settings() -> Result<Settings, Box<dyn std::error::Error>> {
    let mut settings = BTreeMap::new();
    let mut connection = BTreeMap::new();
    connection.insert("id".to_owned(), owned_string("nm-fixture")?);
    settings.insert("connection".to_owned(), connection);

    let mut ipv4 = BTreeMap::new();
    ipv4.insert("method".to_owned(), owned_string("manual")?);
    ipv4.insert("never-default".to_owned(), OwnedValue::from(true));
    ipv4.insert(DNS_DATA.to_owned(), owned_strings(&["1.1.1.1"])?);
    ipv4.insert(DNS_SEARCH.to_owned(), owned_strings(&["before.test"])?);
    ipv4.insert(LEGACY_DNS.to_owned(), owned_u32s(&[16_843_009])?);
    settings.insert(IPV4.to_owned(), ipv4);

    let mut ipv6 = BTreeMap::new();
    ipv6.insert("method".to_owned(), owned_string("disabled")?);
    settings.insert(IPV6.to_owned(), ipv6);
    Ok(settings)
}

fn normalize_empty_ipv6(settings: &mut Settings) {
    if let Some(ipv6) = settings.get_mut(IPV6) {
        for property in [DNS_DATA, DNS_SEARCH, LEGACY_DNS] {
            ipv6.remove(property);
        }
        assert!(ipv6.contains_key(IGNORE_AUTO_DNS));
        assert!(ipv6.contains_key(DNS_PRIORITY));
    }
}

fn owned_string(value: &str) -> Result<OwnedValue, Box<dyn std::error::Error>> {
    Ok(OwnedValue::try_from(Value::new(value))?)
}

fn owned_strings(values: &[&str]) -> Result<OwnedValue, Box<dyn std::error::Error>> {
    let values = values
        .iter()
        .map(|value| (*value).to_owned())
        .collect::<Vec<_>>();
    Ok(OwnedValue::try_from(Value::new(values))?)
}

fn owned_u32s(values: &[u32]) -> Result<OwnedValue, Box<dyn std::error::Error>> {
    Ok(OwnedValue::try_from(Value::new(values.to_vec()))?)
}
