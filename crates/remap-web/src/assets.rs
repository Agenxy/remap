// SPDX-License-Identifier: GPL-3.0-or-later
//! The page, embedded in the binary. Assets carry no data and need no
//! token; everything they show comes from the authenticated API.

/// One embedded file.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(crate) struct Asset {
    pub(crate) content_type: &'static str,
    pub(crate) body: &'static [u8],
}

const INDEX: Asset = Asset {
    content_type: "text/html; charset=utf-8",
    body: include_bytes!("../app/index.html"),
};

const SCRIPT: Asset = Asset {
    content_type: "text/javascript; charset=utf-8",
    body: include_bytes!("../app/app.js"),
};

const STYLE: Asset = Asset {
    content_type: "text/css; charset=utf-8",
    body: include_bytes!("../app/app.css"),
};

const MARK: Asset = Asset {
    content_type: "image/svg+xml",
    body: include_bytes!("../app/remap-mark.svg"),
};

/// The asset served at an exact path, if any.
pub(crate) fn asset(path: &str) -> Option<Asset> {
    match path {
        "/" => Some(INDEX),
        "/app.js" => Some(SCRIPT),
        "/app.css" => Some(STYLE),
        "/remap-mark.svg" => Some(MARK),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::asset;

    #[test]
    fn serves_only_the_fixed_paths() {
        for (path, content_type) in [
            ("/", "text/html; charset=utf-8"),
            ("/app.js", "text/javascript; charset=utf-8"),
            ("/app.css", "text/css; charset=utf-8"),
            ("/remap-mark.svg", "image/svg+xml"),
        ] {
            let found = asset(path);
            assert_eq!(found.map(|asset| asset.content_type), Some(content_type));
            assert!(found.is_some_and(|asset| !asset.body.is_empty()));
        }
        for path in [
            "/index.html",
            "/app.ts",
            "//",
            "/app.js/",
            "/../Cargo.toml",
            "",
        ] {
            assert!(asset(path).is_none(), "{path}");
        }
    }

    #[test]
    fn the_page_references_only_same_origin_assets() {
        let page = String::from_utf8_lossy(asset("/").map_or(&[][..], |asset| asset.body));
        assert!(page.contains(r#"<script src="/app.js" defer></script>"#));
        assert!(page.contains(r#"<link rel="stylesheet" href="/app.css">"#));
        assert!(!page.contains("http://"));
        assert!(!page.contains("https://"));
        assert!(!page.contains("<style"));
        assert!(!page.contains("style=\""));
        assert!(!page.contains("onclick"));
    }
}
