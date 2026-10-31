//! `import … from`, `require(…)`, and tsconfig path aliases.

use super::{Import, unquote};
use ast_grep_core::{Doc, Node};
use std::path::{Path, PathBuf};

pub(super) fn imports<D: Doc>(root: &Node<D>, dir: &Path, repo: &Path) -> Vec<Import> {
    let mut out = Vec::new();
    for n in root.dfs() {
        match n.kind().as_ref() {
            "import_statement" => {
                let Some(path) = n
                    .field("source")
                    .and_then(|s| js_path(unquote(&s.text()), dir, repo))
                else {
                    continue;
                };
                let mut imp = Import {
                    path,
                    names: Vec::new(),
                    namespace: None,
                    all: false,
                };
                for c in n
                    .children()
                    .filter(|c| c.kind() == "import_clause")
                    .flat_map(|c| c.children().collect::<Vec<_>>())
                {
                    match c.kind().as_ref() {
                        "identifier" => imp.names.push(("default".into(), c.text().to_string())),
                        "namespace_import" => {
                            imp.namespace = c
                                .children()
                                .find(|i| i.kind() == "identifier")
                                .map(|i| i.text().to_string())
                        }
                        "named_imports" => imp.names.extend(
                            c.children()
                                .filter(|s| s.kind() == "import_specifier")
                                .filter_map(|s| {
                                    let name = s.field("name")?.text().to_string();
                                    let local = s
                                        .field("alias")
                                        .map_or_else(|| name.clone(), |a| a.text().to_string());
                                    Some((name, local))
                                }),
                        ),
                        _ => {}
                    }
                }
                out.push(imp);
            }
            // `const m = require('./m')`, `const { a, b: c } = require('./m')`
            "variable_declarator" => {
                let (Some(target), Some(value)) = (n.field("name"), n.field("value")) else {
                    continue;
                };
                if value.kind() != "call_expression"
                    || value
                        .field("function")
                        .is_none_or(|f| f.text() != "require")
                {
                    continue;
                }
                let spec = value
                    .field("arguments")
                    .and_then(|a| a.children().find(|c| c.kind() == "string"));
                let Some(path) = spec.and_then(|s| js_path(unquote(&s.text()), dir, repo)) else {
                    continue;
                };
                let mut imp = Import {
                    path,
                    names: Vec::new(),
                    namespace: None,
                    all: false,
                };
                match target.kind().as_ref() {
                    "identifier" => imp.namespace = Some(target.text().to_string()),
                    "object_pattern" => {
                        for p in target.children() {
                            match p.kind().as_ref() {
                                "shorthand_property_identifier_pattern" => {
                                    imp.names.push((p.text().to_string(), p.text().to_string()))
                                }
                                "pair_pattern" => {
                                    if let (Some(k), Some(v)) = (p.field("key"), p.field("value")) {
                                        imp.names
                                            .push((k.text().to_string(), v.text().to_string()));
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                    _ => continue,
                }
                out.push(imp);
            }
            _ => {}
        }
    }
    out
}

fn js_path(spec: &str, dir: &Path, repo: &Path) -> Option<PathBuf> {
    let base = if spec.starts_with('.') {
        dir.join(spec)
    } else {
        alias(spec, repo)?
    };
    let exts = ["ts", "tsx", "js", "jsx", "mjs", "cjs"];
    let stripped = base.with_extension("");
    std::iter::once(base.clone())
        .chain(exts.iter().map(|e| stripped.with_extension(e)))
        .chain(exts.iter().map(|e| base.join(format!("index.{e}"))))
        .find(|p| p.is_file())
}

/// `@/lib/db` through `compilerOptions.paths` in tsconfig.json (`"@/*": ["./src/*"]`).
fn alias(spec: &str, repo: &Path) -> Option<PathBuf> {
    let text = std::fs::read_to_string(repo.join("tsconfig.json")).ok()?;
    let doc: serde_json::Value =
        jsonc_parser::parse_to_serde_value(&text, &Default::default()).ok()?;
    let opts = &doc["compilerOptions"];
    let base = repo.join(opts["baseUrl"].as_str().unwrap_or("."));
    for (pattern, targets) in opts["paths"].as_object()? {
        let prefix = pattern.trim_end_matches('*');
        let Some(rest) = spec.strip_prefix(prefix) else {
            continue;
        };
        let target = targets.get(0)?.as_str()?.trim_end_matches('*');
        return Some(base.join(target).join(rest));
    }
    None
}
