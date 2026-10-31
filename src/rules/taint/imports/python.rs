//! `from … import …` and `import …`: relative, from the root or `src/`.

use super::Import;
use ast_grep_core::{Doc, Node};
use std::path::{Path, PathBuf};

pub(super) fn imports<D: Doc>(root: &Node<D>, dir: &Path, repo: &Path) -> Vec<Import> {
    let mut out = Vec::new();
    for n in root.dfs() {
        match n.kind().as_ref() {
            "import_from_statement" => {
                let Some(module) = n.field("module_name") else {
                    continue;
                };
                let Some(path) = py_path(&module.text(), dir, repo) else {
                    continue;
                };
                let names = n
                    .children()
                    .filter(|c| {
                        c.range() != module.range()
                            && matches!(c.kind().as_ref(), "dotted_name" | "aliased_import")
                    })
                    .filter_map(|c| match c.kind().as_ref() {
                        "aliased_import" => Some((
                            c.field("name")?.text().to_string(),
                            c.field("alias")?.text().to_string(),
                        )),
                        _ => Some((c.text().to_string(), c.text().to_string())),
                    })
                    .collect();
                out.push(Import {
                    path,
                    names,
                    namespace: None,
                    all: false,
                });
            }
            "import_statement" => {
                for c in n
                    .children()
                    .filter(|c| matches!(c.kind().as_ref(), "dotted_name" | "aliased_import"))
                {
                    let (module, local) = match c.kind().as_ref() {
                        "aliased_import" => match (c.field("name"), c.field("alias")) {
                            (Some(m), Some(a)) => (m.text().to_string(), a.text().to_string()),
                            _ => continue,
                        },
                        _ => (c.text().to_string(), c.text().to_string()),
                    };
                    if let Some(path) = py_path(&module, dir, repo) {
                        out.push(Import {
                            path,
                            names: Vec::new(),
                            namespace: Some(local),
                            all: false,
                        });
                    }
                }
            }
            _ => {}
        }
    }
    out
}

/// `.utils`, `..pkg.mod`, `app.utils` → a module file (or package `__init__.py`).
fn py_path(module: &str, dir: &Path, repo: &Path) -> Option<PathBuf> {
    let dots = module.chars().take_while(|c| *c == '.').count();
    let rest: PathBuf = module[dots..]
        .split('.')
        .filter(|s| !s.is_empty())
        .collect();
    let bases: Vec<PathBuf> = if dots > 0 {
        vec![dir.ancestors().nth(dots - 1)?.to_path_buf()]
    } else {
        vec![repo.to_path_buf(), repo.join("src"), dir.to_path_buf()]
    };
    bases
        .iter()
        .flat_map(|b| {
            [
                b.join(&rest).with_extension("py"),
                b.join(&rest).join("__init__.py"),
            ]
        })
        .find(|p| p.is_file())
}
