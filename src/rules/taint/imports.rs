//! Which files a file's functions come from, so taint follows calls across
//! files: relative and `tsconfig` path-alias imports in JS/TS, `import`/`from`
//! in Python (relative, from the root or `src/`), and in Go the other files of
//! the same package plus packages of the same module, PHP `require`/`include`.

use ast_grep_core::{Doc, Node};
use ast_grep_language::SupportLang;
use std::path::{Path, PathBuf};

mod go;
mod js;
mod php;
mod python;

pub struct Import {
    pub path: PathBuf,
    /// (name exported there, name used here)
    pub names: Vec<(String, String)>,
    /// `import * as m`, `const m = require(…)`, `import m`, Go packages: calls look like `m.f`.
    pub namespace: Option<String>,
    /// Go: same package, every function is callable by its bare name.
    pub all: bool,
}

pub fn imports<D: Doc>(lang: SupportLang, root: &Node<D>, file: &Path, repo: &Path) -> Vec<Import> {
    let dir = file.parent().unwrap_or(repo);
    let mut found = match lang {
        SupportLang::TypeScript | SupportLang::Tsx | SupportLang::JavaScript => {
            js::imports(root, dir, repo)
        }
        SupportLang::Python => python::imports(root, dir, repo),
        SupportLang::Go => go::imports(root, file, repo),
        SupportLang::Php => php::imports(root, dir),
        _ => Vec::new(),
    };
    for imp in &mut found {
        imp.path = normalize(&imp.path);
    }
    found
}

/// `a/./b/../c` → `a/c`, without touching the file system.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

pub(super) fn unquote(s: &str) -> &str {
    s.trim_matches(['"', '\'', '`'])
}
