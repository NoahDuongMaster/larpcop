//! Selects which files a check covers and loads their content.

mod git;

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::{WalkBuilder, WalkState};
use rayon::prelude::*;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::{env, fs};

use git::git_list;
pub use git::{blobs, git, in_repo, show, tree};

pub enum Scope {
    /// Every non-ignored file under the root.
    All,
    /// Explicit files or directories.
    Paths(Vec<PathBuf>),
    /// Files an agent just changed, judged as changes against HEAD (hook feedback):
    /// a lockfile's old entries are not this edit's doing.
    Touched(Vec<PathBuf>),
    /// Staged content (what the commit will contain) — for pre-commit.
    Staged,
    /// Uncommitted changes + untracked files — for agent stop hooks.
    Changed,
    /// Files changed since a ref (merge-base diff) — for CI on pull requests.
    Since(String),
}

pub struct SourceFile {
    /// Root-relative, `/`-separated.
    pub rel: String,
    pub content: String,
}

pub fn globset(patterns: &[String]) -> Result<GlobSet> {
    let mut builder = GlobSetBuilder::new();
    for p in patterns {
        builder.add(Glob::new(p).with_context(|| format!("invalid glob `{p}`"))?);
    }
    Ok(builder.build()?)
}

pub fn collect(root: &Path, scope: &Scope, exclude: &GlobSet) -> Result<Vec<SourceFile>> {
    collect_listed(root, scope, exclude, &list(root, scope)?)
}

/// The text files among `listed` that `exclude` does not skip. A file that cannot
/// be read is an error, never a clean file.
pub fn collect_listed(
    root: &Path,
    scope: &Scope,
    exclude: &GlobSet,
    listed: &[String],
) -> Result<Vec<SourceFile>> {
    let wanted: Vec<&String> = listed
        .iter()
        .filter(|r| !exclude.is_match(r.as_str()))
        .collect();
    let contents: Vec<Option<String>> = if matches!(scope, Scope::Staged) {
        let specs: Vec<String> = wanted.iter().map(|rel| format!(":./{rel}")).collect();
        blobs(root, &specs)?
            .into_iter()
            .map(|bytes| bytes.and_then(|b| String::from_utf8(b).ok()))
            .collect()
    } else {
        wanted
            .par_iter()
            .map(|rel| read_worktree(root, rel))
            .collect::<Result<_>>()?
    };
    Ok(wanted
        .into_iter()
        .zip(contents)
        .filter_map(|(rel, content)| {
            Some(SourceFile {
                rel: rel.clone(),
                content: content?,
            })
        })
        .collect())
}

/// Root-relative paths a scope covers, sorted, before any `exclude`.
pub fn list(root: &Path, scope: &Scope) -> Result<Vec<String>> {
    const DIFF: [&str; 5] = [
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "--relative",
        "-z",
    ];
    let mut rels = match scope {
        Scope::All => walk(root, root)?,
        Scope::Paths(paths) | Scope::Touched(paths) => from_paths(root, paths)?,
        Scope::Staged => git_list(root, &[&DIFF[..], &["--cached"]].concat())?,
        Scope::Changed => changed(root)?,
        Scope::Since(base) => git_list(root, &[&DIFF[..], &[&format!("{base}...HEAD")]].concat())?,
    };
    rels.sort();
    rels.dedup();
    Ok(rels)
}

/// Commit a scope's changes are measured against: the merge-base for `Since`,
/// otherwise HEAD. `None` in a repository without commits.
pub fn base(root: &Path, scope: &Scope) -> Option<String> {
    let rev = match scope {
        Scope::Since(b) => git_list(root, &["merge-base", b, "HEAD"])
            .ok()?
            .pop()?
            .trim()
            .to_string(),
        _ => "HEAD".to_string(),
    };
    let check = format!("{rev}^{{commit}}");
    git_list(root, &["rev-parse", "--verify", "-q", &check]).ok()?;
    Some(rev)
}

fn walk(root: &Path, start: &Path) -> Result<Vec<String>> {
    // Dot-directories hold code too (`.github/workflows`, `.env`, `.husky`):
    // only `.git` itself and git-ignored files are skipped.
    let (tx, rx) = mpsc::channel();
    WalkBuilder::new(start)
        .hidden(false)
        .filter_entry(|e| e.file_name() != ".git")
        .build_parallel()
        .run(|| {
            let tx = tx.clone();
            Box::new(move |entry| {
                let found = match entry {
                    Ok(e) if e.file_type().is_some_and(|t| t.is_file()) => {
                        rel_of(root, e.path()).map(Ok)
                    }
                    Ok(_) => None,
                    Err(e) => Some(Err(e.to_string())),
                };
                match found.map(|f| tx.send(f)) {
                    Some(Err(_)) => WalkState::Quit,
                    _ => WalkState::Continue,
                }
            })
        });
    drop(tx);
    let (mut out, mut errors) = (Vec::new(), Vec::new());
    for found in rx {
        match found {
            Ok(rel) => out.push(rel),
            Err(e) => errors.push(e),
        }
    }
    if !errors.is_empty() {
        bail!("walking {}: {}", start.display(), errors.join("; "));
    }
    // Workers finish in any order.
    out.sort();
    // A file committed despite `.gitignore` (`git add -f .env`) is in the repo
    // all the same: tracked files are always checked.
    let under = rel_of(root, start).unwrap_or_default();
    let spec = if under.is_empty() {
        ".".to_string()
    } else {
        under
    };
    let tracked = match git_list(root, &["ls-files", "-z", "--", &spec]) {
        Ok(tracked) => tracked,
        Err(_) if !in_repo(root) => Vec::new(),
        Err(e) => return Err(e),
    };
    let known: std::collections::HashSet<&str> = out.iter().map(String::as_str).collect();
    let extra: Vec<String> = tracked
        .into_iter()
        .filter(|f| !known.contains(f.as_str()) && root.join(f).is_file())
        .collect();
    out.extend(extra);
    Ok(out)
}

/// Root-relative form of `path`, which may not exist yet (nor its parents).
pub fn rel_of_new(root: &Path, path: &Path) -> Option<String> {
    let existing = path.ancestors().find(|a| a.exists())?;
    let rest = path.strip_prefix(existing).ok()?;
    rel_of(root, &dunce::canonicalize(existing).ok()?.join(rest))
}

fn rel_of(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    let parts: Vec<_> = rel
        .components()
        .map(|c| c.as_os_str().to_string_lossy())
        .collect();
    Some(parts.join("/"))
}

fn from_paths(root: &Path, paths: &[PathBuf]) -> Result<Vec<String>> {
    let cwd = env::current_dir()?;
    let mut out = Vec::new();
    for p in paths {
        // Deleted or outside-the-root paths are simply not checked.
        let Ok(abs) = dunce::canonicalize(cwd.join(p)) else {
            continue;
        };
        if abs.is_dir() {
            out.extend(walk(root, &abs)?);
        } else if let Some(rel) = rel_of(root, &abs) {
            out.push(rel);
        }
    }
    Ok(out)
}

fn changed(root: &Path) -> Result<Vec<String>> {
    let diff = [
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "--relative",
        "-z",
        "HEAD",
    ];
    // A repo without commits has no HEAD: everything tracked counts as changed.
    let mut out =
        git_list(root, &diff).or_else(|_| git_list(root, &["ls-files", "-z", "--cached"]))?;
    out.extend(git_list(
        root,
        &["ls-files", "-z", "--others", "--exclude-standard"],
    )?);
    Ok(out)
}

/// Text of `rel`; `None` for a file that is not text (not UTF-8), a directory
/// (a submodule) or gone. Any other failure is an error: a file that cannot be
/// read is not a clean file.
pub fn try_read(root: &Path, rel: &str, staged: bool) -> Result<Option<String>> {
    if staged {
        let spec = [format!(":./{rel}")];
        let blob = blobs(root, &spec)?.pop().flatten();
        return Ok(blob.and_then(|b| String::from_utf8(b).ok()));
    }
    read_worktree(root, rel)
}

fn read_worktree(root: &Path, rel: &str) -> Result<Option<String>> {
    match fs::read(root.join(rel)) {
        Ok(bytes) => Ok(String::from_utf8(bytes).ok()),
        Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::IsADirectory) => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading {rel}")),
    }
}

/// `try_read` for callers that cannot propagate an error (the dependency
/// rules): the failure is reported on stderr, and the file counts as unreadable.
pub fn read(root: &Path, rel: &str, staged: bool) -> Option<String> {
    try_read(root, rel, staged).unwrap_or_else(|e| {
        eprintln!("larpcop: warning: {e:#}");
        None
    })
}

/// Minified or bundled code: lines averaging over 300 bytes. Hand-written code
/// stays far below that; prism.js, a 67 KB bundle in 28 lines, averages 2,400.
pub fn minified(content: &str) -> bool {
    let lines = content.lines().count().max(1);
    content.len() >= 1024 && content.len() / lines > 300
}
