//! Thin wrapper over the GitHub CLI: it already handles auth, SSO and enterprise
//! hosts, so agentkit never stores a token.

use anyhow::{Context, Result, bail};
use base64::Engine;
use serde_json::Value;
use std::process::Command;

pub fn gh(args: &[&str]) -> Result<String> {
    let out = Command::new("gh")
        .args(args)
        .output()
        .context("running `gh` (install the GitHub CLI and run `gh auth login`)")?;
    if !out.status.success() {
        bail!(
            "gh {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn json(args: &[&str]) -> Result<Value> {
    serde_json::from_str(&gh(args)?).context("gh returned invalid JSON")
}

pub struct Repo {
    pub full: String,
    pub default_branch: String,
}

/// Every non-archived, non-fork repository of a user or organization.
pub fn repos(owner: &str) -> Result<Vec<Repo>> {
    let list = json(&[
        "repo",
        "list",
        owner,
        "--limit",
        "1000",
        "--no-archived",
        "--source",
        "--json",
        "nameWithOwner,defaultBranchRef",
    ])?;
    Ok(list
        .as_array()
        .into_iter()
        .flatten()
        .map(|r| Repo {
            full: r["nameWithOwner"].as_str().unwrap_or_default().to_string(),
            default_branch: r["defaultBranchRef"]["name"]
                .as_str()
                .unwrap_or("main")
                .to_string(),
        })
        .collect())
}

/// Raw content of a file on a branch; `None` when it does not exist.
pub fn file(repo: &str, path: &str, branch: &str) -> Option<String> {
    let endpoint = format!("repos/{repo}/contents/{path}?ref={branch}");
    gh(&[
        "api",
        &endpoint,
        "-H",
        "Accept: application/vnd.github.raw+json",
    ])
    .ok()
}

/// Names of the files in a directory (empty when it does not exist).
pub fn dir(repo: &str, path: &str, branch: &str) -> Vec<String> {
    let endpoint = format!("repos/{repo}/contents/{path}?ref={branch}");
    json(&["api", &endpoint])
        .ok()
        .and_then(|v| v.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["name"].as_str().map(String::from))
        .collect()
}

/// Creates or updates a file on `branch` (one commit).
pub fn put(repo: &str, path: &str, branch: &str, content: &str, message: &str) -> Result<()> {
    let endpoint = format!("repos/{repo}/contents/{path}");
    let sha = json(&["api", &format!("{endpoint}?ref={branch}")])
        .ok()
        .and_then(|v| v["sha"].as_str().map(String::from));
    let encoded = base64::engine::general_purpose::STANDARD.encode(content);
    let mut args = vec![
        "api".to_string(),
        "-X".into(),
        "PUT".into(),
        endpoint,
        "-f".into(),
        format!("message={message}"),
        "-f".into(),
        format!("content={encoded}"),
        "-f".into(),
        format!("branch={branch}"),
    ];
    if let Some(sha) = sha {
        args.extend(["-f".into(), format!("sha={sha}")]);
    }
    gh(&args.iter().map(String::as_str).collect::<Vec<_>>()).map(drop)
}
