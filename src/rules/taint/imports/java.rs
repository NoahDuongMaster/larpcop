//! Java: `import a.b.C;`, `import a.b.*;` and `import static a.b.C.m;`
//! resolved through the source root, the directory the file's `package`
//! declaration is relative to, or, in a multi-module build, the
//! `src/main/java` of any module of the repository.

use super::Import;
use super::siblings::listing;
use ast_grep_core::{Doc, Node};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

/// Answers that are the same for every file of a run: which paths are files,
/// which directories of the repository are build modules.
static IS_FILE: LazyLock<Mutex<HashMap<PathBuf, bool>>> = LazyLock::new(Default::default);
static MODULES: LazyLock<Mutex<HashMap<PathBuf, Vec<PathBuf>>>> = LazyLock::new(Default::default);

fn is_file(p: &Path) -> bool {
    if let Some(known) = IS_FILE.lock().ok().and_then(|m| m.get(p).copied()) {
        return known;
    }
    let found = p.is_file();
    if let Ok(mut m) = IS_FILE.lock() {
        m.insert(p.to_path_buf(), found);
    }
    found
}

pub(super) fn imports<D: Doc>(root: &Node<D>, file: &Path, repo: &Path) -> Vec<Import> {
    let declarations: Vec<Node<D>> = root
        .children()
        .filter(|n| n.kind() == "import_declaration")
        .collect();
    // `new org.acme.helpers.Request(r)`: a class named in full, no import.
    let qualified: HashSet<String> = root
        .dfs()
        .filter(|n| n.kind() == "scoped_type_identifier")
        .filter(|n| {
            n.parent()
                .is_none_or(|p| p.kind() != "scoped_type_identifier")
        })
        .map(|n| {
            n.text()
                .split('<')
                .next()
                .unwrap_or_default()
                .replace(char::is_whitespace, "")
        })
        .filter(|t| {
            t.split('.')
                .next()
                .is_some_and(|s| s.starts_with(char::is_lowercase))
        })
        .collect();
    if declarations.is_empty() && qualified.is_empty() {
        return Vec::new();
    }
    let roots = source_roots(root, file, repo);
    let mut out: Vec<Import> = qualified
        .iter()
        .filter_map(|q| {
            let relative = format!("{}.java", q.replace('.', "/"));
            roots.iter().map(|r| r.join(&relative)).find(|p| is_file(p))
        })
        .map(|p| whole(&p))
        .collect();
    let used: HashSet<String> = root
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "identifier" | "type_identifier"))
        .map(|n| n.text().to_string())
        .collect();
    for decl in declarations {
        let text = decl.text();
        let is_static = text.contains("static ");
        let wildcard = decl.children().any(|c| c.kind() == "asterisk");
        let Some(name) = decl
            .children()
            .find(|c| matches!(c.kind().as_ref(), "scoped_identifier" | "identifier"))
        else {
            continue;
        };
        let dotted = name.text().to_string();
        let parts: Vec<&str> = dotted.split('.').collect();
        if wildcard {
            for dir in roots.iter().map(|r| r.join(parts.join("/"))) {
                let classes = listing(&dir, "java");
                out.extend(used.iter().filter_map(|n| classes.get(n)).map(|p| whole(p)));
            }
            continue;
        }
        // `import static a.b.C.m;` names member `m` of class `a.b.C`.
        let (class, member) = match (is_static, parts.split_last()) {
            (true, Some((m, rest))) => (rest, Some(*m)),
            _ => (parts.as_slice(), None),
        };
        let relative = format!("{}.java", class.join("/"));
        let Some(path) = roots.iter().map(|r| r.join(&relative)).find(|p| is_file(p)) else {
            continue;
        };
        out.push(match member {
            Some(m) => Import {
                path,
                names: vec![(m.to_string(), m.to_string())],
                namespace: None,
                all: false,
            },
            None => whole(&path),
        });
    }
    out.retain(|i| i.path != file);
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path && a.names == b.names);
    out
}

fn whole(path: &Path) -> Import {
    Import {
        path: path.to_path_buf(),
        names: Vec::new(),
        namespace: None,
        all: true,
    }
}

/// The file's own source root first, then every module's `src/main/java`.
fn source_roots<D: Doc>(root: &Node<D>, file: &Path, repo: &Path) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    let package = root
        .children()
        .find(|n| n.kind() == "package_declaration")
        .and_then(|p| {
            p.children()
                .find(|c| matches!(c.kind().as_ref(), "scoped_identifier" | "identifier"))
        })
        .map(|n| n.text().to_string());
    if let (Some(package), Some(mut dir)) = (package, file.parent().map(Path::to_path_buf)) {
        let depth = package.split('.').count();
        let tail: PathBuf = package.split('.').collect();
        if dir.ends_with(&tail) {
            for _ in 0..depth {
                dir.pop();
            }
            roots.push(dir);
        }
    }
    for module in std::iter::once(repo.to_path_buf()).chain(modules(repo)) {
        let r = module.join("src/main/java");
        if r.is_dir() && !roots.contains(&r) {
            roots.push(r);
        }
    }
    roots
}

fn modules(repo: &Path) -> Vec<PathBuf> {
    if let Some(known) = MODULES.lock().ok().and_then(|m| m.get(repo).cloned()) {
        return known;
    }
    let mut found: Vec<PathBuf> = std::fs::read_dir(repo)
        .into_iter()
        .flatten()
        .filter_map(|e| Some(e.ok()?.path()))
        .filter(|p| p.join("src/main/java").is_dir())
        .collect();
    found.sort();
    if let Ok(mut m) = MODULES.lock() {
        m.insert(repo.to_path_buf(), found.clone());
    }
    found
}
