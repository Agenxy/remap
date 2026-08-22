use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};

/// A stable failure returned by `remapd` or its local-control client.
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize, schemars::JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    /// Stable machine-readable category.
    pub code: String,
    /// Concise description of what failed.
    pub message: String,
    /// Concrete corrective action when one exists.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hint: Option<String>,
    /// Whether retrying without changing the request may succeed.
    pub retryable: bool,
    /// Small, explicitly safe contextual values.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub context: BTreeMap<String, String>,
}

impl Diagnostic {
    /// Creates a diagnostic without contextual fields.
    #[must_use]
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        hint: Option<String>,
        retryable: bool,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            hint,
            retryable,
            context: BTreeMap::new(),
        }
    }

    /// Adds one safe context field.
    #[must_use]
    pub fn with_context(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.context.insert(key.into(), value.into());
        self
    }

    /// Reports that the local authority is not reachable.
    #[must_use]
    pub fn daemon_unavailable() -> Self {
        Self::new(
            "E_DAEMON_UNAVAILABLE",
            "the Remap daemon is not reachable",
            Some("run 'remap doctor' for the exact service recovery path, then retry".to_owned()),
            true,
        )
    }

    /// Reports an invalid or incompatible local-control exchange.
    #[must_use]
    pub fn protocol(message: impl Into<String>) -> Self {
        Self::new(
            "E_CONTROL_PROTOCOL",
            message,
            Some("update the Remap client and daemon together, then retry".to_owned()),
            false,
        )
    }
}

impl Display for Diagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)?;
        if let Some(hint) = &self.hint {
            write!(formatter, "; {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for Diagnostic {}
