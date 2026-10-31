//! Selects which files a check covers and loads their content.

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};
use ignore::WalkBuilder;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::{env, fs};

pub enum Scope {
    /// Every non-ignored file under the root.
    All,
    /// Explicit files or directories.
    Paths(Vec<PathBuf>),
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
    const DIFF: [&str; 5] = [
        "diff",
        "--name-only",
        "--diff-filter=ACMR",
        "--relative",
        "-z",
    ];
    let mut rels = match scope {
        Scope::All => walk(root, root),
        Scope::Paths(paths) => from_paths(root, paths)?,
        Scope::Staged => git_list(root, &[&DIFF[..], &["--cached"]].concat())?,
        Scope::Changed => changed(root)?,
        Scope::Since(base) => git_list(root, &[&DIFF[..], &[&format!("{base}...HEAD")]].concat())?,
    };
    rels.retain(|r| !exclude.is_match(r));
    rels.sort();
    rels.dedup();
    let staged = matches!(scope, Scope::Staged);
    Ok(rels
        .into_iter()
        .filter_map(|rel| read(root, &rel, staged).map(|content| SourceFile { rel, content }))
        .collect())
}

fn walk(root: &Path, start: &Path) -> Vec<String> {
    WalkBuilder::new(start)
        .build()
        .filter_map(Result::ok)
        .filter(|e| e.file_type().is_some_and(|t| t.is_file()))
        .filter_map(|e| rel_of(root, e.path()))
        .collect()
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
            out.extend(walk(root, &abs));
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

fn git_list(root: &Path, args: &[&str]) -> Result<Vec<String>> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect())
}

/// Binary or unreadable files are skipped: rules only apply to text.
fn read(root: &Path, rel: &str, staged: bool) -> Option<String> {
    let bytes = if staged {
        let out = Command::new("git")
            .args(["show", &format!(":./{rel}")])
            .current_dir(root)
            .output()
            .ok()?;
        out.status.success().then_some(out.stdout)?
    } else {
        fs::read(root.join(rel)).ok()?
    };
    String::from_utf8(bytes).ok()
}
