//! Java and C#: classes of the same package/namespace need no import. The
//! files of the same directory whose name (the class they declare, by
//! convention) the file uses as an identifier are imported, so
//! `Helper.run(x)` and `new Helper().run(x)` reach `Helper.run`.

use super::Import;
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

/// Source files of a directory by extension, listed once per run: a
/// directory of 2,740 classes is otherwise listed 2,740 times.
type Listing = Arc<HashMap<String, PathBuf>>;
static DIRS: LazyLock<Mutex<HashMap<PathBuf, Listing>>> = LazyLock::new(Default::default);

pub(super) fn imports<D: Doc>(root: &Node<D>, file: &Path) -> Vec<Import> {
    let (Some(dir), Some(ext)) = (file.parent(), file.extension()) else {
        return Vec::new();
    };
    let classes = listing(dir, &ext.to_string_lossy());
    if classes.len() < 2 {
        return Vec::new();
    }
    let used: HashSet<String> = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "identifier" | "type_identifier"))
        .map(|n| n.text().to_string())
        .collect();
    let mut out: Vec<Import> = used
        .iter()
        .filter_map(|name| classes.get(name))
        .filter(|path| path.as_path() != file)
        .map(|path| Import {
            path: path.clone(),
            names: Vec::new(),
            namespace: None,
            all: true,
        })
        .collect();
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

pub(super) fn listing(dir: &Path, ext: &str) -> Listing {
    let key = dir.join(format!("*.{ext}"));
    if let Some(known) = DIRS.lock().ok().and_then(|d| d.get(&key).cloned()) {
        return known;
    }
    let found: HashMap<String, PathBuf> = std::fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.extension().is_some_and(|e| e == ext))
        .filter_map(|p| Some((p.file_stem()?.to_str()?.to_string(), p.clone())))
        .collect();
    let found = Arc::new(found);
    if let Ok(mut d) = DIRS.lock() {
        d.insert(key, found.clone());
    }
    found
}
