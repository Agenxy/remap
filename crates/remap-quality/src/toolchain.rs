use std::fs;
use std::path::Path;

const CARGO_MANIFEST: &str = "Cargo.toml";
const MAKEFILE: &str = "Makefile";
const MISE_CONFIG: &str = "mise.toml";
const TYPED_TASK_ENTRYPOINT: &str = "tools.remap_tasks";

pub(crate) fn verify(root: &Path) -> Result<(), String> {
    let cargo = read(root, CARGO_MANIFEST)?;
    let makefile = read(root, MAKEFILE)?;
    let mise = read(root, MISE_CONFIG)?;
    let cargo_version = toml_value(&cargo, "rust-version")
        .ok_or_else(|| "Cargo.toml is missing workspace rust-version".to_owned())?;
    let mise_version = toml_value(&mise, "rust")
        .ok_or_else(|| "mise.toml is missing the Rust toolchain pin".to_owned())?;
    if cargo_version != mise_version {
        return Err(format!(
            "Rust toolchain pins disagree: Cargo.toml={cargo_version}, mise.toml={mise_version}"
        ));
    }
    if !makefile.contains(TYPED_TASK_ENTRYPOINT) {
        return Err(format!(
            "Makefile must delegate maintained behavior to {TYPED_TASK_ENTRYPOINT}"
        ));
    }
    Ok(())
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
        quoted(value).or_else(|| inline_table_version(value))
    })
}

/// A bare `"1.98.1"` assignment.
fn quoted(value: &str) -> Option<&str> {
    value.trim().strip_prefix('"')?.strip_suffix('"')
}

/// The `{ version = "1.98.1", components = [...] }` form mise uses when a
/// tool carries options, such as the rustfmt and clippy components a fresh
/// CI runner's minimal rustup profile does not include.
fn inline_table_version(value: &str) -> Option<&str> {
    let body = value.trim().strip_prefix('{')?.strip_suffix('}')?;
    body.split(',').find_map(|field| {
        let (name, assigned) = field.split_once('=')?;
        (name.trim() == "version")
            .then(|| quoted(assigned))
            .flatten()
    })
}

#[cfg(test)]
mod tests {
    use super::toml_value;

    #[test]
    fn reads_exact_version_assignments() {
        assert_eq!(toml_value("rust = \"1.97.1\"", "rust"), Some("1.97.1"));
    }

    #[test]
    fn reads_the_version_of_a_tool_with_options() {
        assert_eq!(
            toml_value(
                "rust = { version = \"1.98.1\", components = [\"rustfmt\", \"clippy\"] }",
                "rust"
            ),
            Some("1.98.1")
        );
    }
}
