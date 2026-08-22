//! Builds the self-contained, content-addressed MCP App document.

use std::env;
use std::error::Error;
use std::fs;
use std::io;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    for path in [
        "app/dashboard.html",
        "app/dashboard.css",
        "app/dashboard.js",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
    let template = read("app/dashboard.html")?;
    let style = read("app/dashboard.css")?.replace("</style", "<\\/style");
    let script = read("app/dashboard.js")?.replace("</script", "<\\/script");
    let html = replace_once(&template, "__REMAP_STYLE__", &style)?;
    let html = replace_once(&html, "__REMAP_SCRIPT__", &script)?;
    let html = replace_once(&html, "__REMAP_VERSION__", env!("CARGO_PKG_VERSION"))?;
    let output = env::var_os("OUT_DIR")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::other("Cargo did not provide OUT_DIR"))?;
    fs::write(output.join("dashboard.html"), html)?;
    Ok(())
}

fn read(path: &str) -> io::Result<String> {
    fs::read_to_string(path)
}

fn replace_once(source: &str, marker: &str, value: &str) -> io::Result<String> {
    if source.matches(marker).count() != 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("dashboard marker {marker} must occur exactly once"),
        ));
    }
    Ok(source.replacen(marker, value, 1))
}
