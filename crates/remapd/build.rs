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
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::PathBuf;

/// The signing identifier every Remap installer gives this executable.
const IDENTIFIER: &str = "org.agenxy.Remap.daemon";
/// The name macOS shows for this executable.
const NAME: &str = "Remap Service";
/// The copyright every Remap executable and the app state.
const COPYRIGHT: &str = "Copyright 2026 Agenxy. Licensed under GPL-3.0-or-later.";

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
    let entries = [
        ("CFBundleDevelopmentRegion", "en"),
        ("CFBundleDisplayName", NAME),
        ("CFBundleIdentifier", IDENTIFIER),
        ("CFBundleInfoDictionaryVersion", "6.0"),
        ("CFBundleName", NAME),
        ("CFBundleShortVersionString", version),
        ("CFBundleVersion", version),
        ("NSHumanReadableCopyright", COPYRIGHT),
    ];
    let mut plist = String::from(concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" ",
        "\"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
        "<plist version=\"1.0\">\n",
        "<dict>\n",
    ));
    for (key, value) in entries {
        // Every value is written into XML unescaped, so none may need escaping.
        if !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b" .-+".contains(&byte))
        {
            return Err(io::Error::other(format!(
                "{value:?} cannot be written into Info.plist unescaped"
            )));
        }
        writeln!(plist, "\t<key>{key}</key>\n\t<string>{value}</string>")
            .map_err(io::Error::other)?;
    }
    plist.push_str("</dict>\n</plist>\n");
    Ok(plist)
}
