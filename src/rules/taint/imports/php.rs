//! PHP: `require`/`include` (and `_once`) of a literal path, relative to the
//! file or written `__DIR__ . '/x.php'`. Their functions are callable by name.

use super::{Import, unquote};
use ast_grep_core::{Doc, Node};
use std::path::Path;

const INCLUDES: [&str; 4] = [
    "include_expression",
    "include_once_expression",
    "require_expression",
    "require_once_expression",
];

pub(super) fn imports<D: Doc>(root: &Node<D>, dir: &Path) -> Vec<Import> {
    root.dfs()
        .filter(|n| INCLUDES.contains(&n.kind().as_ref()))
        .filter_map(|n| {
            // The literal is the last string in the expression: `'x.php'`,
            // `('x.php')`, `__DIR__ . '/x.php'`.
            let literal = n
                .dfs()
                .filter(|c| matches!(c.kind().as_ref(), "string" | "encapsed_string"))
                .last()?;
            let rel = unquote(&literal.text()).trim_start_matches('/').to_string();
            if rel.is_empty() || rel.contains('$') || !rel.ends_with(".php") {
                return None;
            }
            let path = dir.join(rel);
            path.is_file().then_some(Import {
                path,
                names: Vec::new(),
                namespace: None,
                all: true,
            })
        })
        .collect()
}
