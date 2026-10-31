//! Ruby: `require_relative "x"`, and Rails/Zeitwerk autoloading: a constant
//! the file uses (`User`, `Admin::Report`) is defined in `user.rb` /
//! `admin/report.rb` under one of the autoloaded directories (`app/*/`,
//! `lib/`).

use super::{Import, unquote};
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

/// Relative path under an autoload directory (`admin/report.rb`) → files.
type Autoload = Arc<HashMap<String, Vec<PathBuf>>>;
static REPOS: LazyLock<Mutex<HashMap<PathBuf, Autoload>>> = LazyLock::new(Default::default);

pub(super) fn imports<D: Doc>(root: &Node<D>, dir: &Path, file: &Path, repo: &Path) -> Vec<Import> {
    let mut paths: HashSet<PathBuf> = HashSet::new();
    for call in root.dfs().filter(|n| n.kind() == "call") {
        let required = call
            .field("method")
            .is_some_and(|m| m.text() == "require_relative");
        if let Some(arg) = call
            .field("arguments")
            .and_then(|a| a.children().find(|c| c.is_named()))
            && required
            && arg.kind() == "string"
        {
            let rel = unquote(&arg.text()).to_string();
            let rel = if rel.ends_with(".rb") {
                rel
            } else {
                format!("{rel}.rb")
            };
            paths.insert(dir.join(rel));
        }
    }
    let autoload = autoload(repo);
    let constants = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "constant" | "scope_resolution"))
        .map(|n| snake_path(&n.text()));
    for rel in constants.collect::<HashSet<_>>() {
        if let Some(found) = autoload.get(&rel) {
            paths.extend(found.iter().cloned());
        }
    }
    let mut out: Vec<Import> = paths
        .into_iter()
        .filter(|p| p != file && p.is_file())
        .map(|path| Import {
            path,
            names: Vec::new(),
            namespace: None,
            all: true,
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

/// `Admin::ReportCard` → `admin/report_card.rb`.
fn snake_path(constant: &str) -> String {
    let parts: Vec<String> = constant
        .trim_start_matches("::")
        .split("::")
        .map(|part| {
            let mut s = String::new();
            for (i, c) in part.chars().enumerate() {
                if c.is_uppercase() && i > 0 {
                    s.push('_');
                }
                s.extend(c.to_lowercase());
            }
            s
        })
        .collect();
    format!("{}.rb", parts.join("/"))
}

fn autoload(repo: &Path) -> Autoload {
    if let Some(known) = REPOS.lock().ok().and_then(|r| r.get(repo).cloned()) {
        return known;
    }
    let mut roots: Vec<PathBuf> = std::fs::read_dir(repo.join("app"))
        .into_iter()
        .flatten()
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.is_dir())
        .collect();
    roots.push(repo.join("lib"));
    let mut index: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for base in roots {
        let walk = ignore::WalkBuilder::new(&base).build();
        for entry in walk.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "rb")
                && let Ok(rel) = path.strip_prefix(&base)
            {
                let rel = rel.to_string_lossy().replace('\\', "/");
                index.entry(rel).or_default().push(path.to_path_buf());
            }
        }
    }
    let index = Arc::new(index);
    if let Ok(mut r) = REPOS.lock() {
        r.insert(repo.to_path_buf(), index.clone());
    }
    index
}
