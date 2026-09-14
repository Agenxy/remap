use std::collections::BTreeMap;

use remap_core::{HostHeaderPolicy, MappingTarget, NamePattern};
use remap_protocol::{
    Change, ChangeEffect, Diagnostic, HostPolicy, MAX_ATOMIC_CHANGE_COUNT, MAX_TARGET_BYTES,
    MappingView, PreviewResult,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct StoredMapping {
    pub(crate) pattern: String,
    pub(crate) target: String,
    pub(crate) target_kind: String,
    pub(crate) host_policy: HostPolicy,
    pub(crate) enabled: bool,
    pub(crate) updated_revision: u64,
}

impl StoredMapping {
    pub(crate) fn view(&self) -> MappingView {
        MappingView {
            pattern: self.pattern.clone(),
            target: self.target.clone(),
            target_kind: self.target_kind.clone(),
            host_policy: self.host_policy,
            enabled: self.enabled,
            updated_revision: self.updated_revision,
        }
    }

    pub(crate) fn validate(
        pattern: &str,
        target: &str,
        host_policy: HostPolicy,
        enabled: bool,
        updated_revision: u64,
    ) -> Result<Self, Diagnostic> {
        if target.len() > MAX_TARGET_BYTES {
            return Err(Diagnostic::new(
                "E_TARGET_TOO_LARGE",
                format!(
                    "the target is {} bytes; targets are limited to {MAX_TARGET_BYTES} bytes",
                    target.len()
                ),
                Some("use a shorter upstream base path or DNS destination".to_owned()),
                false,
            ));
        }
        let pattern = NamePattern::parse(pattern).map_err(|error| {
            Diagnostic::new(
                "E_INVALID_PATTERN",
                error.to_string(),
                Some("use an exact hostname or a suffix wildcard such as '*.lab'".to_owned()),
                false,
            )
        })?;
        let core_policy = core_host_policy(host_policy);
        let target =
            MappingTarget::parse_with_http_policy(target, core_policy).map_err(|error| {
                Diagnostic::new(
                    "E_INVALID_TARGET",
                    error.to_string(),
                    Some(
                    "use an IP address, DNS alias, http(s) upstream URL, or supgang://<peer>/<service>"
                        .to_owned(),
                ),
                    false,
                )
            })?;
        Ok(Self {
            pattern: pattern.to_string(),
            target_kind: target.kind().to_string(),
            target: target.to_string(),
            host_policy,
            enabled,
            updated_revision,
        })
    }
}

pub(crate) struct Projection {
    pub(crate) mappings: BTreeMap<String, StoredMapping>,
    pub(crate) result: PreviewResult,
}

pub(crate) fn project(
    current: &BTreeMap<String, StoredMapping>,
    revision: u64,
    changes: &[Change],
) -> Result<Projection, Diagnostic> {
    validate_change_count(changes)?;
    let next_revision = revision.checked_add(1).ok_or_else(|| {
        Diagnostic::new(
            "E_REVISION_EXHAUSTED",
            "the registry revision counter is exhausted",
            Some("preserve the registry and contact the Remap maintainers".to_owned()),
            false,
        )
    })?;
    let mut mappings = current.clone();
    let mut effects = Vec::with_capacity(changes.len());
    let mut has_effect = false;
    for change in changes {
        let effect = apply_one(&mut mappings, change, next_revision)?;
        has_effect |= effect.action != "unchanged";
        effects.push(effect);
    }
    Ok(Projection {
        mappings,
        result: PreviewResult {
            base_revision: revision,
            will_change: has_effect,
            effects,
        },
    })
}

fn validate_change_count(changes: &[Change]) -> Result<(), Diagnostic> {
    if changes.is_empty() {
        return Err(Diagnostic::new(
            "E_EMPTY_CHANGE_SET",
            "an atomic change set must contain at least one change",
            Some("supply one or more set, enable, disable, or remove changes".to_owned()),
            false,
        ));
    }
    if changes.len() > MAX_ATOMIC_CHANGE_COUNT {
        return Err(Diagnostic::new(
            "E_TOO_MANY_CHANGES",
            format!(
                "the request contains {} changes; the atomic limit is {MAX_ATOMIC_CHANGE_COUNT}",
                changes.len()
            ),
            Some("split the work into smaller revision-checked batches".to_owned()),
            false,
        ));
    }
    Ok(())
}

fn apply_one(
    mappings: &mut BTreeMap<String, StoredMapping>,
    change: &Change,
    next_revision: u64,
) -> Result<ChangeEffect, Diagnostic> {
    match change {
        Change::Set {
            pattern,
            target,
            host_policy,
            enabled,
        } => apply_set(
            mappings,
            pattern,
            target,
            *host_policy,
            *enabled,
            next_revision,
        ),
        Change::Enable { pattern } => apply_enabled(mappings, pattern, true, next_revision),
        Change::Disable { pattern } => apply_enabled(mappings, pattern, false, next_revision),
        Change::Remove { pattern } => apply_remove(mappings, pattern),
    }
}

fn apply_set(
    mappings: &mut BTreeMap<String, StoredMapping>,
    pattern: &str,
    target: &str,
    host_policy: HostPolicy,
    enabled: Option<bool>,
    next_revision: u64,
) -> Result<ChangeEffect, Diagnostic> {
    let parsed = StoredMapping::validate(pattern, target, host_policy, true, next_revision)?;
    let canonical = parsed.pattern.clone();
    let before = mappings.get(&canonical).cloned();
    let resolved_enabled = enabled.or_else(|| before.as_ref().map(|record| record.enabled));
    let mut after = parsed;
    after.enabled = resolved_enabled.unwrap_or(true);
    let same = before
        .as_ref()
        .is_some_and(|record| same_value(record, &after));
    if same {
        after = before.clone().ok_or_else(internal_projection_error)?;
    } else {
        mappings.insert(canonical.clone(), after.clone());
    }
    let action = if same {
        "unchanged"
    } else if before.is_some() {
        "updated"
    } else {
        "created"
    };
    Ok(effect(canonical, action, before, Some(after)))
}

fn apply_enabled(
    mappings: &mut BTreeMap<String, StoredMapping>,
    pattern: &str,
    enabled: bool,
    next_revision: u64,
) -> Result<ChangeEffect, Diagnostic> {
    let canonical = NamePattern::parse(pattern)
        .map_err(|error| invalid_pattern(&error.to_string()))?
        .to_string();
    let before = mappings
        .get(&canonical)
        .cloned()
        .ok_or_else(|| missing_mapping(&canonical))?;
    if before.enabled == enabled {
        return Ok(effect(
            canonical,
            "unchanged",
            Some(before.clone()),
            Some(before),
        ));
    }
    let mut after = before.clone();
    after.enabled = enabled;
    after.updated_revision = next_revision;
    mappings.insert(canonical.clone(), after.clone());
    let action = if enabled { "enabled" } else { "disabled" };
    Ok(effect(canonical, action, Some(before), Some(after)))
}

fn apply_remove(
    mappings: &mut BTreeMap<String, StoredMapping>,
    pattern: &str,
) -> Result<ChangeEffect, Diagnostic> {
    let canonical = NamePattern::parse(pattern)
        .map_err(|error| invalid_pattern(&error.to_string()))?
        .to_string();
    let before = mappings
        .remove(&canonical)
        .ok_or_else(|| missing_mapping(&canonical))?;
    Ok(effect(canonical, "removed", Some(before), None))
}

fn effect(
    pattern: String,
    action: &str,
    before: Option<StoredMapping>,
    after: Option<StoredMapping>,
) -> ChangeEffect {
    ChangeEffect {
        pattern,
        action: action.to_owned(),
        before: before.map(|record| record.view()),
        after: after.map(|record| record.view()),
    }
}

fn same_value(left: &StoredMapping, right: &StoredMapping) -> bool {
    left.pattern == right.pattern
        && left.target == right.target
        && left.target_kind == right.target_kind
        && left.host_policy == right.host_policy
        && left.enabled == right.enabled
}

pub(crate) const fn core_host_policy(policy: HostPolicy) -> HostHeaderPolicy {
    match policy {
        HostPolicy::PreserveClient => HostHeaderPolicy::PreserveClient,
        HostPolicy::UseUpstream => HostHeaderPolicy::UseUpstream,
    }
}

fn missing_mapping(pattern: &str) -> Diagnostic {
    Diagnostic::new(
        "E_NO_MAPPING",
        format!("no mapping exists for '{pattern}'"),
        Some("list mappings or create this pattern before changing it".to_owned()),
        false,
    )
}

fn invalid_pattern(message: &str) -> Diagnostic {
    Diagnostic::new(
        "E_INVALID_PATTERN",
        message,
        Some("use an exact hostname or a suffix wildcard such as '*.lab'".to_owned()),
        false,
    )
}

fn internal_projection_error() -> Diagnostic {
    Diagnostic::new(
        "E_INTERNAL",
        "the registry projection lost an existing mapping",
        Some("preserve the registry and report this invariant failure".to_owned()),
        false,
    )
}
