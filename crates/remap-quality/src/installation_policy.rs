// SPDX-License-Identifier: GPL-3.0-or-later
use std::path::{Component, Path, PathBuf};

use proc_macro2::{TokenStream, TokenTree};
use syn::spanned::Spanned;
use syn::visit::{self, Visit};

use crate::model::{Rule, Violation};

/// Conservative checks at the installer copy boundary, plus crate asset confinement.
pub(crate) fn analyze(root: &Path, path: &Path, source: &str) -> Result<Vec<Violation>, String> {
    let mut findings = Vec::new();
    if path.extension().is_some_and(|extension| extension == "rs") {
        let syntax = syn::parse_file(source)
            .map_err(|error| format!("cannot parse {}: {error}", path.display()))?;
        let mut analyzer = RustInstallPolicy {
            root,
            path,
            findings: &mut findings,
        };
        analyzer.visit_file(&syntax);
    }
    if python_installer(path) {
        // Reject the truncating primitive even in currently fresh staging directories.
        // This makes freshness local to the copy, independent of its callers.
        let compact: String = source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect();
        for primitive in ["shutil.copyfile(", "shutil.copy2(", "shutil.copy("] {
            if compact.contains(primitive) {
                findings.push(finding(path, 1, Rule::ExecutableOverwrite, primitive));
            }
        }
    }
    if path.starts_with("platforms/macos/Sources/RemapInstallKit")
        && path
            .extension()
            .is_some_and(|extension| extension == "swift")
    {
        for (index, line) in source.lines().enumerate() {
            if line
                .split(|value: char| !value.is_alphanumeric() && value != '_')
                .any(|token| token == "O_TRUNC")
            {
                findings.push(finding(
                    path,
                    index + 1,
                    Rule::ExecutableOverwrite,
                    "O_TRUNC",
                ));
            }
        }
    }
    Ok(findings)
}

fn python_installer(path: &Path) -> bool {
    path.starts_with("tools")
        && path.extension().is_some_and(|extension| extension == "py")
        && path
            .file_stem()
            .and_then(|value| value.to_str())
            .is_some_and(|name| {
                name.contains("install")
                    || name.contains("bootstrap")
                    || name == "remap_native_package"
            })
}

struct RustInstallPolicy<'a> {
    root: &'a Path,
    path: &'a Path,
    findings: &'a mut Vec<Violation>,
}

impl<'ast> Visit<'ast> for RustInstallPolicy<'_> {
    fn visit_macro(&mut self, node: &'ast syn::Macro) {
        let name = node
            .path
            .segments
            .last()
            .map(|segment| segment.ident.to_string());
        if matches!(name.as_deref(), Some("include_str" | "include_bytes")) {
            if !self.confined_asset(&node.tokens) {
                self.findings.push(finding(
                    self.path,
                    node.span().start().line,
                    Rule::ExternalEmbeddedAsset,
                    &node.tokens.to_string(),
                ));
            }
        } else {
            // Includes can occur inside another macro, including assert! and matches!.
            self.nested_macros(node.tokens.clone());
        }
    }

    fn visit_expr_call(&mut self, node: &'ast syn::ExprCall) {
        if let syn::Expr::Path(function) = node.func.as_ref() {
            let names: Vec<_> = function
                .path
                .segments
                .iter()
                .map(|part| part.ident.to_string())
                .collect();
            let destination = match names.last().map(String::as_str) {
                Some("copy") if names.iter().any(|part| part == "fs") => node.args.iter().nth(1),
                Some("write") if names.iter().any(|part| part == "fs") => node.args.first(),
                Some("create") if names.iter().any(|part| part == "File") => node.args.first(),
                _ => None,
            };
            if destination.is_some_and(literal_executable_path) {
                self.findings.push(finding(
                    self.path,
                    node.span().start().line,
                    Rule::ExecutableOverwrite,
                    &names.join("::"),
                ));
            }
        }
        visit::visit_expr_call(self, node);
    }
}

impl RustInstallPolicy<'_> {
    fn confined_asset(&self, tokens: &TokenStream) -> bool {
        let Ok(literal) = syn::parse2::<syn::LitStr>(tokens.clone()) else {
            // build.rs outputs are checked by building the extracted crate archive.
            return generated_asset(tokens);
        };
        let Some(crate_root) = self.crate_root() else {
            return false;
        };
        let Some(parent) = self.root.join(self.path).parent().map(Path::to_path_buf) else {
            return false;
        };
        let candidate = parent.join(literal.value());
        if Path::new(&literal.value()).is_absolute()
            || !normalize(&candidate).starts_with(&crate_root)
        {
            return false;
        }
        // A repository symlink must not make a lexically local asset external.
        match (candidate.canonicalize(), crate_root.canonicalize()) {
            (Ok(asset), Ok(root)) => asset.starts_with(root),
            _ => false,
        }
    }

    fn crate_root(&self) -> Option<PathBuf> {
        let absolute = self.root.join(self.path);
        absolute
            .parent()?
            .ancestors()
            .take_while(|path| path.starts_with(self.root))
            .find(|path| path.join("Cargo.toml").is_file())
            .map(Path::to_path_buf)
    }

    fn nested_macros(&mut self, tokens: TokenStream) {
        let tokens: Vec<_> = tokens.into_iter().collect();
        for window in tokens.windows(3) {
            if let [
                TokenTree::Ident(name),
                TokenTree::Punct(mark),
                TokenTree::Group(arguments),
            ] = window
                && mark.as_char() == '!'
                && (name == "include_str" || name == "include_bytes")
                && !self.confined_asset(&arguments.stream())
            {
                self.findings.push(finding(
                    self.path,
                    name.span().start().line,
                    Rule::ExternalEmbeddedAsset,
                    &arguments.stream().to_string(),
                ));
            }
        }
        for token in tokens {
            if let TokenTree::Group(group) = token {
                self.nested_macros(group.stream());
            }
        }
    }
}

fn normalize(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                result.pop();
            }
            Component::CurDir => {}
            other => result.push(other),
        }
    }
    result
}

fn generated_asset(tokens: &TokenStream) -> bool {
    let Ok(syn::Expr::Macro(expression)) = syn::parse2::<syn::Expr>(tokens.clone()) else {
        return false;
    };
    if !expression.mac.path.is_ident("concat") {
        return false;
    }
    let parser = syn::punctuated::Punctuated::<syn::Expr, syn::Token![,]>::parse_terminated;
    let Ok(parts) = syn::parse::Parser::parse2(parser, expression.mac.tokens) else {
        return false;
    };
    let mut parts = parts.iter();
    let Some(syn::Expr::Macro(environment)) = parts.next() else {
        return false;
    };
    if !environment.mac.path.is_ident("env")
        || !syn::parse2::<syn::LitStr>(environment.mac.tokens.clone())
            .is_ok_and(|value| value.value() == "OUT_DIR")
    {
        return false;
    }
    let suffix: Option<String> = parts
        .map(|part| match part {
            syn::Expr::Lit(syn::ExprLit {
                lit: syn::Lit::Str(value),
                ..
            }) => Some(value.value()),
            _ => None,
        })
        .collect();
    suffix.is_some_and(|suffix| {
        suffix.starts_with('/')
            && !suffix[1..].is_empty()
            && Path::new(&suffix[1..])
                .components()
                .all(|part| matches!(part, Component::Normal(_)))
    })
}

fn literal_executable_path(expression: &syn::Expr) -> bool {
    match expression {
        syn::Expr::Reference(reference) => return literal_executable_path(&reference.expr),
        syn::Expr::Call(call) => {
            if let syn::Expr::Path(function) = call.func.as_ref()
                && function
                    .path
                    .segments
                    .last()
                    .is_some_and(|part| part.ident == "new")
            {
                return call.args.first().is_some_and(literal_executable_path);
            }
        }
        _ => {}
    }
    let syn::Expr::Lit(syn::ExprLit {
        lit: syn::Lit::Str(value),
        ..
    }) = expression
    else {
        return false;
    };
    let value = value.value();
    [
        "/bin/",
        "/libexec/",
        "/Contents/MacOS/",
        "/PrivilegedHelperTools/",
    ]
    .iter()
    .any(|part| value.contains(part))
}

fn finding(path: &Path, line: usize, rule: Rule, symbol: &str) -> Violation {
    Violation {
        path: path.to_path_buf(),
        line,
        rule,
        symbol: Some(symbol.to_owned()),
        actual: 1,
        maximum: 0,
    }
}
