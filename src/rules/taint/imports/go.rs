//! The other files of the same package, and packages of the same module.

use super::{Import, unquote};
use ast_grep_core::{Doc, Node};
use std::path::{Path, PathBuf};

pub(super) fn imports<D: Doc>(root: &Node<D>, file: &Path, repo: &Path) -> Vec<Import> {
    let mut out: Vec<Import> = go_files(file.parent().unwrap_or(repo))
        .into_iter()
        .filter(|p| p != file)
        .map(|path| Import {
            path,
            names: Vec::new(),
            namespace: None,
            all: true,
        })
        .collect();
    let module = std::fs::read_to_string(repo.join("go.mod"))
        .ok()
        .and_then(|m| {
            m.lines().find_map(|l| {
                l.trim()
                    .strip_prefix("module ")
                    .map(|s| s.trim().to_string())
            })
        });
    let Some(module) = module else { return out };
    for spec in root.dfs().filter(|n| n.kind() == "import_spec") {
        let Some(path) = spec.field("path") else {
            continue;
        };
        let import = unquote(&path.text()).to_string();
        let Some(sub) = import.strip_prefix(&module) else {
            continue;
        };
        let alias = spec.field("name").map_or_else(
            || import.rsplit('/').next().unwrap_or(&import).to_string(),
            |n| n.text().to_string(),
        );
        for path in go_files(&repo.join(sub.trim_start_matches('/'))) {
            out.push(Import {
                path,
                names: Vec::new(),
                namespace: Some(alias.clone()),
                all: false,
            });
        }
    }
    out
}

fn go_files(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut files: Vec<PathBuf> = entries
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "go"))
        .collect();
    files.sort();
    files
}
