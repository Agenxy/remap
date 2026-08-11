use remap_core::{HostHeaderPolicy, MappingTarget, NamePattern};

use crate::cli::Action;
use crate::diagnostic::Diagnostic;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum Report {
    Doctor(DoctorReport),
    Validation(ValidationReport),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct DoctorReport {
    pub(crate) version: &'static str,
    pub(crate) operating_system: &'static str,
    pub(crate) architecture: &'static str,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct ValidationReport {
    pub(crate) pattern: String,
    pub(crate) target: String,
    pub(crate) target_kind: &'static str,
    pub(crate) host_header_policy: Option<&'static str>,
}

pub(crate) fn execute(action: Action) -> Result<Report, Diagnostic> {
    match action {
        Action::Doctor => Ok(Report::Doctor(DoctorReport {
            version: env!("CARGO_PKG_VERSION"),
            operating_system: std::env::consts::OS,
            architecture: std::env::consts::ARCH,
        })),
        Action::Validate {
            pattern,
            target,
            host_header_policy,
        } => validate(&pattern, &target, host_header_policy).map(Report::Validation),
    }
}

fn validate(
    pattern: &str,
    target: &str,
    host_header_policy: HostHeaderPolicy,
) -> Result<ValidationReport, Diagnostic> {
    let pattern = NamePattern::parse(pattern)
        .map_err(|error| Diagnostic::invalid_pattern(error.to_string()))?;
    let target = MappingTarget::parse_with_http_policy(target, host_header_policy)
        .map_err(|error| Diagnostic::invalid_target(error.to_string()))?;
    let policy = match &target {
        MappingTarget::Http(upstream) => Some(upstream.host_header_policy().as_str()),
        MappingTarget::DnsAddress(_) | MappingTarget::DnsAlias(_) => None,
    };
    Ok(ValidationReport {
        pattern: pattern.to_string(),
        target: target.to_string(),
        target_kind: target.kind().as_str(),
        host_header_policy: policy,
    })
}
