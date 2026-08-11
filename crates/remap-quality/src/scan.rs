use std::fs;
use std::path::Path;

use crate::limits::MAX_FILE_LINES;
use crate::model::{Rule, Violation};
use crate::rust_metrics;

pub(crate) fn workspace(root: &Path) -> Result<Vec<Violation>, String> {
    crate::toolchain::verify(root)?;
    let mut violations = Vec::new();
    for path in crate::discover::source_files(root)? {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {} as UTF-8: {error}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        check_file_length(&relative, &source, &mut violations);
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

fn check_file_length(path: &Path, source: &str, violations: &mut Vec<Violation>) {
    let line_count = source.lines().count();
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
}
