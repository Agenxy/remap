// SPDX-License-Identifier: GPL-3.0-or-later
use std::fs;
use std::path::Path;

use crate::limits::MAX_FILE_LINES;
use crate::model::{Rule, Violation};
use crate::rust_metrics;

pub(crate) fn workspace(root: &Path) -> Result<Vec<Violation>, String> {
    crate::toolchain::verify(root)?;
    let mut violations = crate::repository_policy::check(root)?;
    for path in crate::discover::source_files(root)? {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {} as UTF-8: {error}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        check_file_length(&relative, &source, &mut violations);
        violations.extend(crate::installation_policy::analyze(
            root, &relative, &source,
        )?);
        if path.extension().is_some_and(|extension| extension == "rs") {
            violations.extend(rust_metrics::analyze(&relative, &source)?);
        }
    }
    violations.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then(left.line.cmp(&right.line))
            .then(left.rule.cmp(&right.rule))
    });
    Ok(violations)
}

/// Count the lines whose presence the author decided.
///
/// A mandatory `SPDX-License-Identifier` is not one of them. It is imposed on every
/// first-party file by the repository's licence, so charging it against a per-file
/// budget would quietly take one line of headroom from every file at once, and would
/// fail the files already sitting exactly on the limit. The budget exists to bound how
/// much a reader must hold in their head, and a licence line asks nothing of a reader.
fn authored_line_count(source: &str) -> usize {
    source
        .lines()
        .filter(|line| !line.contains("SPDX-License-Identifier:"))
        .count()
}

fn check_file_length(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let line_count = authored_line_count(source);
    if line_count > MAX_FILE_LINES {
        violations.push(Violation {
            rule: Rule::FileLines,
            path: path.to_path_buf(),
            line: 1,
            symbol: None,
            actual: line_count,
            maximum: MAX_FILE_LINES,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::check_file_length;
    use crate::limits::MAX_FILE_LINES;
    use crate::model::Rule;

    #[test]
    fn reports_file_limit() {
        let source = "line\n".repeat(MAX_FILE_LINES + 1);
        let mut violations = Vec::new();
        check_file_length(Path::new("large.rs"), &source, &mut violations);
        assert_eq!(violations.len(), 1);
        assert_eq!(violations[0].rule, Rule::FileLines);
    }

    #[test]
    fn the_licence_identifier_does_not_spend_the_budget() {
        let source = format!(
            "// SPDX-License-Identifier: GPL-3.0-or-later\n{}",
            "line\n".repeat(MAX_FILE_LINES)
        );
        let mut violations = Vec::new();
        check_file_length(Path::new("exactly_full.rs"), &source, &mut violations);
        assert!(
            violations.is_empty(),
            "a file at the limit must not be failed by a header it had no say in"
        );
    }

    #[test]
    fn the_budget_still_bites_on_authored_lines() {
        let source = format!(
            "// SPDX-License-Identifier: GPL-3.0-or-later\n{}",
            "line\n".repeat(MAX_FILE_LINES + 1)
        );
        let mut violations = Vec::new();
        check_file_length(Path::new("over.rs"), &source, &mut violations);
        assert_eq!(
            violations.len(),
            1,
            "the exemption is one line, not a reprieve"
        );
        assert_eq!(violations[0].actual, MAX_FILE_LINES + 1);
    }
}
