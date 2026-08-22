use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_ROOTS: [&str; 4] = ["crates", "platforms", "tests", "tools"];
const ROOT_SOURCE_FILES: [&str; 1] = ["playwright.config.ts"];
const SOURCE_EXTENSIONS: [&str; 14] = [
    "c", "cc", "cpp", "cxx", "go", "h", "hh", "hpp", "py", "rs", "swift", "ts", "tsx", "mts",
];

pub(crate) fn workspace_root() -> Result<PathBuf, String> {
    let mut candidate = env::current_dir()
        .map_err(|error| format!("cannot read the current directory: {error}"))?;
    loop {
        let manifest = candidate.join("Cargo.toml");
        if manifest.is_file() {
            let contents = fs::read_to_string(&manifest)
                .map_err(|error| format!("cannot read {}: {error}", manifest.display()))?;
            if contents.lines().any(|line| line.trim() == "[workspace]") {
                return Ok(candidate);
            }
        }
        if !candidate.pop() {
            return Err("cannot find Remap's workspace Cargo.toml from this directory".to_owned());
        }
    }
}

pub(crate) fn source_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    for source_root in SOURCE_ROOTS {
        let path = root.join(source_root);
        if path.is_dir() {
            collect_directory(&path, &mut files)?;
        }
    }
    for source_file in ROOT_SOURCE_FILES {
        let path = root.join(source_file);
        if path.is_file() {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn collect_directory(directory: &Path, files: &mut Vec<PathBuf>) -> Result<(), String> {
    let entries = fs::read_dir(directory)
        .map_err(|error| format!("cannot read {}: {error}", directory.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("cannot inspect {}: {error}", directory.display()))?;
        let file_type = entry
            .file_type()
            .map_err(|error| format!("cannot inspect {}: {error}", entry.path().display()))?;
        if file_type.is_dir() {
            collect_directory(&entry.path(), files)?;
        } else if file_type.is_file() && is_source_file(&entry.path()) {
            files.push(entry.path());
        }
    }
    Ok(())
}

fn is_source_file(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| SOURCE_EXTENSIONS.contains(&extension))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::source_files;

    #[test]
    fn discovers_root_tool_test_and_crate_sources() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        for relative in [
            "playwright.config.ts",
            "tools/build.ts",
            "tests/app.spec.ts",
            "crates/example/src/lib.rs",
        ] {
            let path = directory.path().join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, "const value = true;\n")?;
        }
        let files = source_files(directory.path())?
            .into_iter()
            .filter_map(|path| {
                path.strip_prefix(directory.path())
                    .ok()
                    .map(Path::to_path_buf)
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(files.len(), 4);
        assert!(files.contains(Path::new("playwright.config.ts")));
        assert!(files.contains(Path::new("tools/build.ts")));
        assert!(files.contains(Path::new("tests/app.spec.ts")));
        assert!(files.contains(Path::new("crates/example/src/lib.rs")));
        Ok(())
    }
}
