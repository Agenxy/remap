use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::model::{Rule, Violation};

const IGNORED_DIRECTORIES: [&str; 5] = [".build", ".git", "node_modules", "target", "test-results"];
const ROOT_PROSE: [&str; 2] = ["PRIVACY.md", "README.md"];

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut violations = check_em_dashes(root)?;
    collect_shell_scripts(root, root, &mut violations)?;
    Ok(violations)
}

fn check_em_dashes(root: &Path) -> Result<Vec<Violation>, String> {
    let mut paths = crate::discover::source_files(root)?;
    paths.extend(ROOT_PROSE.iter().map(|name| root.join(name)));
    collect_markdown(&root.join("docs"), &mut paths)?;
    let mut violations = Vec::new();
    for path in paths.into_iter().collect::<BTreeSet<_>>() {
        let source = fs::read_to_string(&path)
            .map_err(|error| format!("cannot read {} as UTF-8: {error}", path.display()))?;
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        for (index, line) in source.lines().enumerate() {
            let count = line.matches('\u{2014}').count();
            if count != 0 {
                violations.push(Violation {
                    rule: Rule::EmDash,
                    path: relative.clone(),
                    line: index + 1,
                    symbol: None,
                    actual: count,
                    maximum: 0,
                });
            }
        }
    }
    Ok(violations)
}

fn collect_markdown(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<(), String> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_dir() {
            collect_markdown(&entry.path(), paths)?;
        } else if file_type.is_file() && entry.path().extension().is_some_and(|value| value == "md")
        {
            paths.push(entry.path());
        }
    }
    Ok(())
}

fn collect_shell_scripts(
    root: &Path,
    directory: &Path,
    violations: &mut Vec<Violation>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?
    {
        let entry =
            entry.map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_dir() {
            let name = entry.file_name();
            if !IGNORED_DIRECTORIES.iter().any(|ignored| name == *ignored) {
                collect_shell_scripts(root, &entry.path(), violations)?;
            }
        } else if file_type.is_file() && entry.path().extension().is_some_and(|value| value == "sh")
        {
            violations.push(Violation {
                rule: Rule::ShellScript,
                path: entry
                    .path()
                    .strip_prefix(root)
                    .unwrap_or(&entry.path())
                    .to_path_buf(),
                line: 1,
                symbol: None,
                actual: 1,
                maximum: 0,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::{check_em_dashes, collect_shell_scripts};
    use crate::model::Rule;

    #[test]
    fn rejects_em_dashes_in_documentation() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        fs::create_dir(root.path().join("docs"))?;
        fs::write(root.path().join("README.md"), "Clear prose.\n")?;
        fs::write(
            root.path().join("PRIVACY.md"),
            format!("one {} two\n", '\u{2014}'),
        )?;
        let findings = check_em_dashes(root.path())?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::EmDash);
        Ok(())
    }

    #[test]
    fn rejects_maintained_shell_scripts() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempdir()?;
        fs::create_dir(root.path().join("tools"))?;
        fs::write(root.path().join("tools/bootstrap.sh"), "#!/bin/sh\n")?;
        let mut findings = Vec::new();
        collect_shell_scripts(root.path(), root.path(), &mut findings)?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::ShellScript);
        Ok(())
    }
}
