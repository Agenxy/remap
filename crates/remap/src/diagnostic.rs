use std::collections::BTreeMap;
use std::fmt::{self, Display, Formatter};

/// A stable command failure with human guidance and machine identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Diagnostic {
    code: Box<str>,
    message: Box<str>,
    detail: String,
    hint: Box<str>,
    retryable: bool,
    context: BTreeMap<String, String>,
    exit_code: u8,
}

impl Display for Diagnostic {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Diagnostic {}

impl Diagnostic {
    pub(crate) fn usage(detail: &str) -> Self {
        Self {
            code: "R001".into(),
            message: "the command could not be understood".into(),
            detail: detail.trim().to_owned(),
            hint: "Run 'remap --help' to see the complete command surface.".into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 2,
        }
    }

    pub(crate) fn invalid_pattern(detail: String) -> Self {
        Self {
            code: "R101".into(),
            message: "the mapping name is not valid".into(),
            detail,
            hint: "Use a hostname such as 'atlas', 'api.lab', or '*.lab'; addresses belong on the target side.".into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 2,
        }
    }

    pub(crate) fn invalid_target(detail: String) -> Self {
        Self {
            code: "R102".into(),
            message: "the mapping target is not valid".into(),
            detail,
            hint: "Use an IPv4/IPv6 address, DNS hostname, or an http(s) upstream URL without credentials, a query, or a fragment.".into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 2,
        }
    }

    pub(crate) fn change_document(detail: String) -> Self {
        Self {
            code: "R103".into(),
            message: "the atomic change document is not valid".into(),
            detail,
            hint: "Provide a bounded JSON array of set, enable, disable, or remove changes.".into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 2,
        }
    }

    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self {
            code: "R900".into(),
            message: "Remap encountered an internal command-state error".into(),
            detail: detail.into(),
            hint: "Please report this with the Remap version and command, but remove private names and addresses first.".into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 70,
        }
    }

    pub(crate) fn native_lifecycle(detail: impl Into<String>) -> Self {
        Self {
            code: "R701".into(),
            message: "the installed Remap service is not available".into(),
            detail: detail.into(),
            hint:
                "Install Remap, or run 'remap system recover' if an installation was interrupted."
                    .into(),
            retryable: false,
            context: BTreeMap::new(),
            exit_code: 69,
        }
    }

    pub(crate) fn service(error: remap_protocol::Diagnostic) -> Self {
        let detail = if error
            .context
            .get("outcome")
            .is_some_and(|value| value == "unknown")
        {
            "The response was lost after the request may have reached the daemon; the complete outcome is unknown."
                .to_owned()
        } else if error.context.is_empty() {
            String::new()
        } else {
            error
                .context
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        Self {
            code: error.code.into_boxed_str(),
            message: error.message.into_boxed_str(),
            detail,
            hint: error
                .hint
                .unwrap_or_else(|| {
                    "Review the request and run 'remap doctor' before retrying.".to_owned()
                })
                .into_boxed_str(),
            retryable: error.retryable,
            context: error.context,
            exit_code: if error.retryable { 75 } else { 1 },
        }
    }

    pub(crate) fn mutation_service(
        error: remap_protocol::Diagnostic,
        operation_id: &str,
        expected_revision: u64,
    ) -> Self {
        let uncertain = error
            .context
            .get("outcome")
            .is_some_and(|value| value == "unknown");
        let mut diagnostic = Self::service(error);
        if uncertain {
            diagnostic
                .context
                .insert("operation_id".to_owned(), operation_id.to_owned());
            diagnostic.context.insert(
                "expected_revision".to_owned(),
                expected_revision.to_string(),
            );
            "The mutation may have committed completely; Remap never partially commits a batch."
                .clone_into(&mut diagnostic.detail);
            diagnostic.hint = format!(
                "Inspect remap status/get first. To retrieve the same receipt safely, retry the identical mutation with --expect {expected_revision} --operation-id {operation_id}."
            )
            .into_boxed_str();
        }
        diagnostic
    }

    pub(crate) fn code(&self) -> &str {
        &self.code
    }

    pub(crate) fn message(&self) -> &str {
        &self.message
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }

    pub(crate) fn hint(&self) -> &str {
        &self.hint
    }

    pub(crate) const fn retryable(&self) -> bool {
        self.retryable
    }

    pub(crate) fn context(&self) -> &BTreeMap<String, String> {
        &self.context
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        self.exit_code
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::Diagnostic;

    #[test]
    fn uncertain_mutation_preserves_exact_retry_guards_without_claiming_rollback() {
        let operation_id = "c82b1476-abcf-4674-903f-c793f66f38f6";
        let mut context = BTreeMap::new();
        context.insert("outcome".to_owned(), "unknown".to_owned());
        let service = remap_protocol::Diagnostic {
            code: "E_DAEMON_TIMEOUT".to_owned(),
            message: "the daemon did not answer before the deadline".to_owned(),
            hint: None,
            retryable: true,
            context,
        };
        let diagnostic = Diagnostic::mutation_service(service, operation_id, 9);
        assert!(
            diagnostic
                .detail()
                .contains("may have committed completely")
        );
        assert!(!diagnostic.detail().contains("made no"));
        assert!(diagnostic.hint().contains("--expect 9"));
        assert!(diagnostic.hint().contains(operation_id));
        assert_eq!(
            diagnostic.context().get("operation_id").map(String::as_str),
            Some(operation_id)
        );
        assert_eq!(
            diagnostic
                .context()
                .get("expected_revision")
                .map(String::as_str),
            Some("9")
        );
    }
}
