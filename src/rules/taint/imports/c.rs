//! C and C++: no imports, only declarations, and the linker joins the files.
//! A function called here but not defined here is looked up among the
//! functions defined in the C/C++ files of the same directory (indexed once per
//! directory: a definition starts at column 0 and its line does not end the
//! declaration with `;`).

use super::Import;
use ast_grep_core::{Doc, Node};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

static DEFINITION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^(?:static\s+|inline\s+|extern\s+)*[A-Za-z_][\w \t]*?[\s*]+([A-Za-z_]\w*)\s*\([^;{]*\)?\s*(?:\{.*)?\r?$")
        .expect("valid regex")
});
type Index = Arc<HashMap<String, PathBuf>>;
static DIRECTORIES: LazyLock<Mutex<HashMap<PathBuf, Index>>> = LazyLock::new(Default::default);
const EXTENSIONS: [&str; 5] = ["c", "cc", "cpp", "cxx", "h"];

pub(super) fn imports<D: Doc>(root: &Node<D>, file: &Path) -> Vec<Import> {
    let Some(dir) = file.parent() else {
        return Vec::new();
    };
    let defined: HashSet<String> = root
        .dfs()
        .filter(|n| n.kind() == "function_declarator")
        // Definitions, not prototypes (`void f(char *data);` is a declaration).
        .filter(|n| {
            n.ancestors()
                .take(2)
                .find(|a| a.kind() != "pointer_declarator")
                .is_some_and(|a| a.kind() == "function_definition")
        })
        .filter_map(|n| n.field("declarator").map(|d| d.text().to_string()))
        .collect();
    let called: HashSet<String> = root
        .dfs()
        .filter(|n| n.kind() == "call_expression")
        .filter_map(|n| n.field("function"))
        .filter(|f| f.kind() == "identifier")
        .map(|f| f.text().to_string())
        .filter(|name| !defined.contains(name))
        .collect();
    if called.is_empty() {
        return Vec::new();
    }
    let index = directory(dir);
    let mut by_file: HashMap<&PathBuf, Vec<(String, String)>> = HashMap::new();
    for name in &called {
        if let Some(path) = index.get(name).filter(|p| p.as_path() != file) {
            by_file
                .entry(path)
                .or_default()
                .push((name.clone(), name.clone()));
        }
    }
    by_file
        .into_iter()
        .map(|(path, names)| Import {
            path: path.clone(),
            names,
            namespace: None,
            all: false,
        })
        .collect()
}

/// Function name → the file of the directory that defines it.
fn directory(dir: &Path) -> Index {
    if let Some(known) = DIRECTORIES.lock().ok().and_then(|d| d.get(dir).cloned()) {
        return known;
    }
    let mut out = HashMap::new();
    for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
        let path = entry.path();
        if !path
            .extension()
            .is_some_and(|e| EXTENSIONS.iter().any(|x| e == *x))
        {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for c in DEFINITION.captures_iter(&text) {
            out.entry(c[1].to_string()).or_insert_with(|| path.clone());
        }
    }
    let index = Arc::new(out);
    if let Ok(mut d) = DIRECTORIES.lock() {
        d.insert(dir.to_path_buf(), index.clone());
    }
    index
}
