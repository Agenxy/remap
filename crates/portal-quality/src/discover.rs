use std::env;
use std::fs;
use std::path::{Path, PathBuf};

const SOURCE_ROOTS: [&str; 2] = ["crates", "platforms"];
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
            return Err("cannot find Portal's workspace Cargo.toml from this directory".to_owned());
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
