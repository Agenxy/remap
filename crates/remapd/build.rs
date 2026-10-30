// SPDX-License-Identifier: GPL-3.0-or-later
//! Embeds `remapd`'s Info.plist in its macOS executable (ADR-0034).
//!
//! A bare executable has no bundle to read a name from, so macOS shows its file
//! name wherever it names the program, and code signing has no identifier of the
//! product's choosing to bind. The linker copies the plist into the executable's
//! `__TEXT,__info_plist` section, which macOS reads as the program's bundle
//! information. Other platforms build the same plist and link nothing.

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

/// The signing identifier every Remap installer gives this executable.
const IDENTIFIER: &str = "org.agenxy.Remap.daemon";
/// The name macOS shows for this executable.
const NAME: &str = "Remap Service";

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=build.rs");
    let output = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?;
    let plist = output.join("Info.plist");
    fs::write(&plist, info_plist(env!("CARGO_PKG_VERSION"))?)?;
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        let path = plist
            .to_str()
            .ok_or_else(|| io::Error::other("OUT_DIR is not valid UTF-8"))?;
        for argument in ["-sectcreate", "__TEXT", "__info_plist", path] {
            println!("cargo:rustc-link-arg-bins=-Xlinker");
            println!("cargo:rustc-link-arg-bins={argument}");
        }
    }
    Ok(())
}

fn info_plist(version: &str) -> io::Result<String> {
    for value in [IDENTIFIER, NAME, version] {
        // Every value is written into XML unescaped, so none may need escaping.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" .-+".contains(&byte))
        {
            return Err(io::Error::other(format!(
                "{value:?} cannot be written into Info.plist unescaped"
            )));
        }
    }
    Ok(format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n         <!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n         <plist version=\"1.0\">\n         <dict>\n         \t<key>CFBundleDevelopmentRegion</key>\n\t<string>en</string>\n         \t<key>CFBundleDisplayName</key>\n\t<string>{NAME}</string>\n         \t<key>CFBundleIdentifier</key>\n\t<string>{IDENTIFIER}</string>\n         \t<key>CFBundleInfoDictionaryVersion</key>\n\t<string>6.0</string>\n         \t<key>CFBundleName</key>\n\t<string>{NAME}</string>\n         \t<key>CFBundleShortVersionString</key>\n\t<string>{version}</string>\n         \t<key>CFBundleVersion</key>\n\t<string>{version}</string>\n         \t<key>NSHumanReadableCopyright</key>\n\t<string>Copyright 2026 Agenxy. Licensed under GPL-3.0-or-later.</string>\n         </dict>\n         </plist>\n"
    ))
}
