//! What `agentkit learn` reads: the team's review comments, the repo's languages.

use crate::files::SourceFile;
use anyhow::{Context, Result, bail};
use ast_grep_language::{Language, SupportLang};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::Path;
use std::process::Command;

/// Recent pull request review comments of the repository, for `--reviews N`.
pub fn review_comments(root: &Path, n: usize) -> Result<String> {
    let gh = |args: &[&str]| -> Result<String> {
        let out = Command::new("gh")
            .args(args)
            .current_dir(root)
            .output()
            .context("running `gh`")?;
        if !out.status.success() {
            bail!(
                "gh {}: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    };
    let repo = gh(&[
        "repo",
        "view",
        "--json",
        "nameWithOwner",
        "-q",
        ".nameWithOwner",
    ])?;
    let path = format!(
        "repos/{repo}/pulls/comments?sort=created&direction=desc&per_page={}",
        n.min(100)
    );
    let comments: Value = serde_json::from_str(&gh(&["api", &path])?)?;
    let mut text = String::from(
        "Review comments from this repository's pull requests. Propose rules only for feedback that \
recurs or states a standard, and that a syntax pattern can check; skip the rest.\n",
    );
    for c in comments.as_array().into_iter().flatten() {
        let hunk: String = c["diff_hunk"]
            .as_str()
            .unwrap_or("")
            .chars()
            .rev()
            .take(500)
            .collect();
        let hunk: String = hunk.chars().rev().collect();
        let _ = write!(
            text,
            "\n---\nFile: {}\nCode:\n{hunk}\nComment: {}\n",
            c["path"].as_str().unwrap_or(""),
            c["body"].as_str().unwrap_or("").trim()
        );
    }
    Ok(text)
}

pub fn languages(sources: &[SourceFile]) -> String {
    let mut count: BTreeMap<String, usize> = BTreeMap::new();
    for f in sources {
        if let Some(l) = SupportLang::from_path(&f.rel) {
            *count.entry(l.to_string()).or_default() += 1;
        }
    }
    let mut v: Vec<_> = count.into_iter().collect();
    v.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    let list: Vec<String> = v
        .iter()
        .take(6)
        .map(|(l, n)| format!("{l} ({n} files)"))
        .collect();
    format!("The repository is written in: {}.", list.join(", "))
}
