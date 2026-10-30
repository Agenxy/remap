// SPDX-License-Identifier: GPL-3.0-or-later
//! The Info.plist macOS reads to name `remap` (ADR-0034).

const PLIST: &str = include_str!(concat!(env!("OUT_DIR"), "/Info.plist"));

#[test]
fn the_plist_names_the_product_and_its_signing_identifier() {
    for expected in [
        "<key>CFBundleIdentifier</key>\n\t<string>org.agenxy.Remap.cli</string>",
        "<key>CFBundleName</key>\n\t<string>Remap CLI</string>",
        "<key>CFBundleDisplayName</key>\n\t<string>Remap CLI</string>",
        concat!(
            "<key>CFBundleShortVersionString</key>\n\t<string>",
            env!("CARGO_PKG_VERSION"),
            "</string>"
        ),
    ] {
        assert!(PLIST.contains(expected), "Info.plist lacks {expected:?}");
    }
    // Laid out as plistlib and Xcode write one: entries indented by one tab.
    assert!(PLIST.starts_with("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist "));
    assert!(PLIST.lines().all(|line| !line.starts_with(' ')));
    assert!(PLIST.ends_with("\n</dict>\n</plist>\n"));
}

#[cfg(target_os = "macos")]
#[test]
fn the_built_executable_carries_the_plist() -> std::io::Result<()> {
    let executable = std::fs::read(env!("CARGO_BIN_EXE_remap"))?;
    let embedded = executable
        .windows(PLIST.len())
        .any(|window| window == PLIST.as_bytes());
    assert!(embedded, "remap does not embed its Info.plist");
    Ok(())
}
