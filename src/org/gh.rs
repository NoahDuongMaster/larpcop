//! Thin wrapper over the GitHub CLI: it already handles auth, SSO and enterprise
//! hosts, so larpcop never stores a token.

use anyhow::{Context, Result, bail, ensure};
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

/// Most repositories one `gh repo list` returns; it cuts off silently beyond it.
const REPO_LIMIT: usize = 1000;

/// Every non-archived, non-fork repository of a user or organization.
pub fn repos(owner: &str) -> Result<Vec<Repo>> {
    let list = json(&[
        "repo",
        "list",
        owner,
        "--limit",
        &REPO_LIMIT.to_string(),
        "--no-archived",
        "--source",
        "--json",
        "nameWithOwner,defaultBranchRef",
    ])?;
    parse_repos(owner, &list)
}

/// A full page means the list may have been cut off: the repositories after it
/// would be missing from a status or a rollout without a word, so it is an error.
fn parse_repos(owner: &str, list: &Value) -> Result<Vec<Repo>> {
    let repos: Vec<Repo> = list
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
        .collect();
    ensure!(
        repos.len() < REPO_LIMIT,
        "`gh repo list {owner}` returned {REPO_LIMIT} repositories, its limit: {owner} probably has \
more, and they would be missing from the result"
    );
    Ok(repos)
}

/// Is this `gh api` failure a 404, i.e. the thing asked for does not exist?
/// Any other failure (auth, rate limit, 5xx) says nothing about existence.
fn not_found(e: &anyhow::Error) -> bool {
    e.to_string().contains("HTTP 404")
}

/// Raw content of a file on a branch; `None` when it does not exist.
pub fn file(repo: &str, path: &str, branch: &str) -> Result<Option<String>> {
    let endpoint = format!("repos/{repo}/contents/{path}?ref={branch}");
    match gh(&[
        "api",
        &endpoint,
        "-H",
        "Accept: application/vnd.github.raw+json",
    ]) {
        Ok(content) => Ok(Some(content)),
        Err(e) if not_found(&e) => Ok(None),
        Err(e) => Err(e),
    }
}

/// Names of the files in a directory (empty when it does not exist).
pub fn dir(repo: &str, path: &str, branch: &str) -> Result<Vec<String>> {
    let endpoint = format!("repos/{repo}/contents/{path}?ref={branch}");
    let listing = match json(&["api", &endpoint]) {
        Ok(listing) => listing,
        Err(e) if not_found(&e) => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    Ok(listing
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|e| e["name"].as_str().map(String::from))
        .collect())
}

/// Creates or updates a file on `branch` (one commit).
pub fn put(repo: &str, path: &str, branch: &str, content: &str, message: &str) -> Result<()> {
    let endpoint = format!("repos/{repo}/contents/{path}");
    let sha = match json(&["api", &format!("{endpoint}?ref={branch}")]) {
        Ok(v) => v["sha"].as_str().map(String::from),
        Err(e) if not_found(&e) => None,
        Err(e) => return Err(e),
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn listed(n: usize) -> Value {
        Value::Array(
            (0..n)
                .map(|i| json!({ "nameWithOwner": format!("acme/r{i}"), "defaultBranchRef": { "name": "dev" } }))
                .collect(),
        )
    }

    #[test]
    fn a_list_cut_off_at_the_limit_is_an_error_not_a_smaller_org() {
        let repos = parse_repos("acme", &listed(REPO_LIMIT - 1)).unwrap();
        assert_eq!(repos.len(), REPO_LIMIT - 1);
        assert_eq!(
            (repos[0].full.as_str(), repos[0].default_branch.as_str()),
            ("acme/r0", "dev")
        );
        let Err(err) = parse_repos("acme", &listed(REPO_LIMIT)) else {
            panic!("a full page of repositories was accepted");
        };
        assert!(
            err.to_string()
                .contains("returned 1000 repositories, its limit"),
            "{err:#}"
        );
    }
}
