//! Kotlin: the other files of the package's directory (top-level functions
//! and classes of a package need no import), and `import a.b.C`,
//! `import a.b.f as g`, `import a.b.*` through the source root the
//! `package` header is relative to. A class may be a `.kt` or, in a mixed
//! project, a `.java` file (`src/main/java` next to `src/main/kotlin`).

use super::Import;
use super::siblings::listing;
use ast_grep_core::{Doc, Node};
use std::path::{Path, PathBuf};

pub(super) fn imports<D: Doc>(root: &Node<D>, file: &Path, repo: &Path) -> Vec<Import> {
    let mut out: Vec<Import> = Vec::new();
    if let Some(dir) = file.parent() {
        out.extend(package_files(dir, file).into_iter().map(whole));
    }
    let package = root
        .children()
        .find(|c| c.kind() == "package_header")
        .and_then(|p| p.children().find(|c| c.kind() == "identifier"))
        .map(|i| i.text().replace(char::is_whitespace, ""))
        .unwrap_or_default();
    let roots = source_roots(file, &package, repo);
    let headers: Vec<Node<D>> = root
        .children()
        .filter(|c| c.kind() == "import_list")
        .flat_map(|l| {
            l.children()
                .filter(|h| h.kind() == "import_header")
                .collect::<Vec<_>>()
        })
        .collect();
    for header in headers {
        let Some(dotted) = header.children().find(|c| c.kind() == "identifier") else {
            continue;
        };
        let parts: Vec<String> = dotted
            .text()
            .split('.')
            .map(|p| p.trim().to_string())
            .collect();
        if header.children().any(|c| c.kind() == "wildcard_import") {
            for dir in roots.iter().map(|r| r.join(parts.join("/"))) {
                out.extend(package_files(&dir, file).into_iter().map(whole));
            }
            continue;
        }
        let relative = parts.join("/");
        let class = roots
            .iter()
            .flat_map(|r| ["kt", "java"].map(|ext| r.join(format!("{relative}.{ext}"))))
            .find(|p| p.is_file());
        if let Some(path) = class {
            out.push(whole(path));
            continue;
        }
        // `import a.b.f as g`: a top-level function of package `a.b`.
        let Some((function, package)) = parts.split_last() else {
            continue;
        };
        let alias = header
            .children()
            .find(|c| c.kind() == "import_alias")
            .and_then(|a| a.children().find(|c| c.is_named()))
            .map_or_else(|| function.clone(), |a| a.text().to_string());
        for dir in roots.iter().map(|r| r.join(package.join("/"))) {
            out.extend(package_files(&dir, file).into_iter().map(|path| Import {
                path,
                names: vec![(function.clone(), alias.clone())],
                namespace: None,
                all: false,
            }));
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out.dedup_by(|a, b| a.path == b.path && a.names == b.names);
    out
}

fn whole(path: PathBuf) -> Import {
    Import {
        path,
        names: Vec::new(),
        namespace: None,
        all: true,
    }
}

/// The `.kt` files of a package's directory, but `file`.
fn package_files(dir: &Path, file: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = listing(dir, "kt")
        .values()
        .filter(|p| p.as_path() != file)
        .cloned()
        .collect();
    files.sort();
    files
}

/// The directory `package` is relative to, and its `java`/`kotlin` twin.
fn source_roots(file: &Path, package: &str, repo: &Path) -> Vec<PathBuf> {
    let mut root = file.parent().unwrap_or(repo).to_path_buf();
    for part in package.split('.').filter(|p| !p.is_empty()).rev() {
        if root.file_name().is_none_or(|n| n != part) {
            return vec![file.parent().unwrap_or(repo).to_path_buf()];
        }
        root.pop();
    }
    let mut out = vec![root.clone()];
    let twin = match root.file_name().and_then(|n| n.to_str()) {
        Some("kotlin") => Some("java"),
        Some("java") => Some("kotlin"),
        _ => None,
    };
    if let Some(twin) = twin {
        out.push(root.with_file_name(twin));
    }
    out
}
