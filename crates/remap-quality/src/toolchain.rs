use std::fs;
use std::path::Path;

const CARGO_MANIFEST: &str = "Cargo.toml";
const MAKEFILE: &str = "Makefile";
const MISE_CONFIG: &str = "mise.toml";

pub(crate) fn verify(root: &Path) -> Result<(), String> {
    let cargo = read(root, CARGO_MANIFEST)?;
    let makefile = read(root, MAKEFILE)?;
    let mise = read(root, MISE_CONFIG)?;
    let cargo_version = toml_value(&cargo, "rust-version")
        .ok_or_else(|| "Cargo.toml is missing workspace rust-version".to_owned())?;
    let mise_version = toml_value(&mise, "rust")
        .ok_or_else(|| "mise.toml is missing the Rust toolchain pin".to_owned())?;
    let make_version = make_value(&makefile, "RUST_TOOLCHAIN")
        .ok_or_else(|| "Makefile is missing the install toolchain pin".to_owned())?;

    if cargo_version == mise_version && mise_version == make_version {
        return Ok(());
    }
    Err(format!(
        "Rust toolchain pins disagree: Cargo.toml={cargo_version}, mise.toml={mise_version}, Makefile={make_version}"
    ))
}

fn read(root: &Path, relative: &str) -> Result<String, String> {
    let path = root.join(relative);
    fs::read_to_string(&path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn toml_value<'source>(source: &'source str, key: &str) -> Option<&'source str> {
    source.lines().find_map(|line| {
        let (candidate, value) = line.split_once('=')?;
        if candidate.trim() != key {
            return None;
        }
        value.trim().strip_prefix('"')?.strip_suffix('"')
    })
}

fn make_value<'source>(source: &'source str, key: &str) -> Option<&'source str> {
    source.lines().find_map(|line| {
        let (candidate, value) = line.split_once(":=")?;
        (candidate.trim() == key).then(|| value.trim())
    })
}

#[cfg(test)]
mod tests {
    use super::{make_value, toml_value};

    #[test]
    fn reads_exact_version_assignments() {
        assert_eq!(toml_value("rust = \"1.97.1\"", "rust"), Some("1.97.1"));
        assert_eq!(
            make_value("RUST_TOOLCHAIN := 1.97.1", "RUST_TOOLCHAIN"),
            Some("1.97.1")
        );
    }
}
