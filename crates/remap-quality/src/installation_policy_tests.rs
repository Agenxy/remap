#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::installation_policy::analyze;
    use crate::model::Rule;

    #[test]
    fn embedded_assets_must_stay_inside_the_published_crate()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let package = root.path().join("crates/example");
        fs::create_dir_all(package.join("src"))?;
        fs::write(package.join("Cargo.toml"), "[package]\nname = 'example'\n")?;
        fs::write(package.join("asset.txt"), "inside")?;
        fs::write(root.path().join("outside.txt"), "outside")?;
        let path = Path::new("crates/example/src/lib.rs");
        for source in [
            "const A: &str = include_str!(\"../asset.txt\");",
            "const A: &[u8] = include_bytes!(\"../asset.txt\");",
            "const A: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/generated.html\"));",
        ] {
            assert!(analyze(root.path(), path, source)?.is_empty(), "{source}");
        }
        for source in [
            "const A: &str = include_str!(\"../../../outside.txt\");",
            "fn test() { assert!(include_str!(\"../../../outside.txt\").is_empty()); }",
            "const A: &[u8] = include_bytes!(r#\"/etc/passwd\"#);",
            "const A: &str = include_str!(concat!(env!(\"OUT_DIR\"), \"/../outside\"));",
        ] {
            let findings = analyze(root.path(), path, source)?;
            assert_eq!(findings.len(), 1, "{source}");
            assert_eq!(findings[0].rule, Rule::ExternalEmbeddedAsset);
        }
        Ok(())
    }

    #[test]
    fn embedded_asset_symlinks_cannot_escape_the_crate() -> Result<(), Box<dyn std::error::Error>> {
        let root = tempfile::tempdir()?;
        let package = root.path().join("crates/example");
        fs::create_dir_all(package.join("src"))?;
        fs::write(package.join("Cargo.toml"), "[package]\n")?;
        fs::write(root.path().join("outside"), "outside")?;
        std::os::unix::fs::symlink(root.path().join("outside"), package.join("src/asset"))?;
        let findings = analyze(
            root.path(),
            Path::new("crates/example/src/lib.rs"),
            "const A: &str = include_str!(\"asset\");",
        )?;
        assert_eq!(findings.len(), 1);
        fs::create_dir_all(root.path().join("foreign/child"))?;
        fs::write(root.path().join("foreign/local"), "outside through parent")?;
        fs::write(package.join("src/local"), "inside lexical path")?;
        std::os::unix::fs::symlink(root.path().join("foreign/child"), package.join("src/link"))?;
        let findings = analyze(
            root.path(),
            Path::new("crates/example/src/lib.rs"),
            "const A: &str = include_str!(\"link/../local\");",
        )?;
        assert_eq!(findings.len(), 1);
        Ok(())
    }

    #[test]
    fn installer_copies_must_create_fresh_files_even_in_staging() -> Result<(), String> {
        let path = Path::new("tools/remap_macos_install.py");
        for source in [
            "shutil.copyfile(source, destination)",
            "shutil.copy2(\n source,\n destination\n)",
            "shutil . copy(source, destination)",
        ] {
            let findings = analyze(Path::new("."), path, source)?;
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].rule, Rule::ExecutableOverwrite);
        }
        assert_eq!(
            analyze(
                Path::new("."),
                path,
                "with destination.open(\"xb\") as writer:\n    shutil.copyfileobj(reader, writer)"
            )?,
            Vec::new()
        );
        Ok(())
    }

    #[test]
    fn rust_literal_executable_writes_are_rejected() -> Result<(), String> {
        let path = Path::new("crates/example/src/lib.rs");
        for source in [
            "fn bad() { std::fs::copy(source, \"/usr/local/bin/remap\"); }",
            "fn bad() { fs::write(\"/usr/libexec/remap/remapd\", bytes); }",
            "fn bad() { File::create(\"/Applications/Remap.app/Contents/MacOS/Remap\"); }",
            "fn bad() { fs::copy(source, Path::new(\"/usr/local/bin/remap\")); }",
        ] {
            let findings = analyze(Path::new("."), path, source)?;
            assert_eq!(findings.len(), 1);
            assert_eq!(findings[0].rule, Rule::ExecutableOverwrite);
        }
        assert_eq!(
            analyze(
                Path::new("."),
                path,
                "fn good() { fs::rename(staged, \"/usr/local/bin/remap\"); }"
            )?,
            Vec::new()
        );
        Ok(())
    }

    #[test]
    fn native_installer_authority_cannot_introduce_truncating_opens() -> Result<(), String> {
        let path = Path::new("platforms/macos/Sources/RemapInstallKit/FileSystemAuthority.swift");
        let findings = analyze(Path::new("."), path, "open(path, O_WRONLY | O_TRUNC)")?;
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, Rule::ExecutableOverwrite);
        assert_eq!(
            analyze(
                Path::new("."),
                path,
                "open(path, O_WRONLY | O_CREAT | O_EXCL)"
            )?,
            Vec::new()
        );
        Ok(())
    }
}
