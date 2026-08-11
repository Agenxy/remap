/// A stable command failure with human guidance and machine identity.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Diagnostic {
    code: &'static str,
    message: &'static str,
    detail: String,
    hint: &'static str,
    exit_code: u8,
}

impl Diagnostic {
    pub(crate) fn usage(detail: &str) -> Self {
        Self {
            code: "R001",
            message: "the command could not be understood",
            detail: detail.trim().to_owned(),
            hint: "Run 'remap --help' to see the complete command surface.",
            exit_code: 2,
        }
    }

    pub(crate) fn invalid_pattern(detail: String) -> Self {
        Self {
            code: "R101",
            message: "the mapping name is not valid",
            detail,
            hint: "Use a hostname such as 'atlas', 'api.lab', or '*.lab'; addresses belong on the target side.",
            exit_code: 2,
        }
    }

    pub(crate) fn invalid_target(detail: String) -> Self {
        Self {
            code: "R102",
            message: "the mapping target is not valid",
            detail,
            hint: "Use an IPv4/IPv6 address, DNS hostname, or an http(s) upstream URL without credentials, a query, or a fragment.",
            exit_code: 2,
        }
    }

    pub(crate) fn internal(detail: impl Into<String>) -> Self {
        Self {
            code: "R900",
            message: "Remap encountered an internal command-state error",
            detail: detail.into(),
            hint: "Please report this with the Remap version and command, but remove private names and addresses first.",
            exit_code: 70,
        }
    }

    pub(crate) const fn code(&self) -> &'static str {
        self.code
    }

    pub(crate) const fn message(&self) -> &'static str {
        self.message
    }

    pub(crate) fn detail(&self) -> &str {
        &self.detail
    }

    pub(crate) const fn hint(&self) -> &'static str {
        self.hint
    }

    pub(crate) const fn exit_code(&self) -> u8 {
        self.exit_code
    }
}
