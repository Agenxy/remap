//! The `remap_health` tool's output: whether the system resolver returns
//! Remap's answer, so an agent can tell a silent fallback from a healthy one.

use remap_protocol::{Command, CommandResult, ControlClient};
use schemars::JsonSchema;
use serde::Serialize;

use crate::system_lookup::{self, SystemLookup};

/// Resolver health as the operating system sees it.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, JsonSchema)]
pub(crate) struct HealthReport {
    /// `ready`, `bypassed`, `unresolved`, or `not_checked`.
    pub(crate) system_lookup: &'static str,
    /// The mapped name that was resolved through the system, if any.
    pub(crate) name: Option<String>,
    /// The first address the system returned, if any.
    pub(crate) answer: Option<String>,
}

impl HealthReport {
    pub(crate) fn summary(&self) -> String {
        let name = self.name.as_deref().unwrap_or("");
        let answer = self.answer.as_deref().unwrap_or("");
        match self.system_lookup {
            "ready" => format!("The system resolver answers '{name}' with Remap's {answer}."),
            "bypassed" => format!(
                "The system resolver answered '{name}' with {answer}, not Remap's answer: the system is not asking Remap."
            ),
            "unresolved" => format!("'{name}' did not resolve through the system resolver."),
            _ => "No enabled exact mapping has a predictable answer to probe.".to_owned(),
        }
    }
}

/// Probes the first enabled exact mapping through the system resolver.
pub(crate) async fn report(client: &ControlClient) -> HealthReport {
    let lookup = match client
        .execute(Command::List {
            after: None,
            limit: 64,
            include_disabled: false,
        })
        .await
    {
        Ok(CommandResult::List(list)) => match system_lookup::candidate(&list.mappings) {
            Some((name, expected)) => system_lookup::probe(name, &expected).await,
            None => SystemLookup::NotChecked,
        },
        _ => SystemLookup::NotChecked,
    };
    HealthReport {
        system_lookup: lookup.state(),
        name: lookup.name().map(str::to_owned),
        answer: lookup.answer().map(|answer| answer.to_string()),
    }
}
