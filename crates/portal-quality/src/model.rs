use std::path::PathBuf;

use serde_json::{Value, json};

/// One structural rule enforced by the repository-native analyzer.
#[derive(Debug, Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum Rule {
    FileLines,
    FunctionLines,
    TypeLines,
    Parameters,
    Complexity,
    Nesting,
}

impl Rule {
    pub(crate) const fn code(self) -> &'static str {
        match self {
            Self::FileLines => "Q001",
            Self::FunctionLines => "Q002",
            Self::TypeLines => "Q003",
            Self::Parameters => "Q004",
            Self::Complexity => "Q005",
            Self::Nesting => "Q006",
        }
    }

    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::FileLines => "source file is too long",
            Self::FunctionLines => "function is too long",
            Self::TypeLines => "type or implementation is too long",
            Self::Parameters => "function has too many parameters",
            Self::Complexity => "function is too complex",
            Self::Nesting => "function is nested too deeply",
        }
    }

    pub(crate) const fn help(self) -> &'static str {
        match self {
            Self::FileLines => "split by cohesive responsibility, not arbitrary line ranges",
            Self::FunctionLines => "extract a named operation with one clear responsibility",
            Self::TypeLines => "separate independent behavior behind a focused type or module",
            Self::Parameters => "introduce a meaningful parameter object or simplify the operation",
            Self::Complexity => "replace branching with smaller decisions or explicit state",
            Self::Nesting => "use guard clauses and extract nested control flow",
        }
    }
}

/// A deterministic, actionable structural diagnostic.
#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Violation {
    pub(crate) rule: Rule,
    pub(crate) path: PathBuf,
    pub(crate) line: usize,
    pub(crate) symbol: Option<String>,
    pub(crate) actual: usize,
    pub(crate) maximum: usize,
}

impl Violation {
    pub(crate) fn to_json(&self) -> Value {
        json!({
            "code": self.rule.code(),
            "message": self.rule.description(),
            "path": self.path,
            "line": self.line,
            "symbol": self.symbol,
            "actual": self.actual,
            "maximum": self.maximum,
            "help": self.rule.help(),
        })
    }
}
