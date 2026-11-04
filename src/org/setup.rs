//! `larpcop org setup`: one pull request per repository with `.larpcop.yaml`,
//! the CI gate and every generated agent file, so the PR passes `sync --check`.

use super::{BRANCH, Status, WORKFLOW, gh};
use crate::context::Ctx;
use anyhow::{Context, Result, bail};
use std::fs;

pub struct Plan<'a> {
    pub owner: &'a str,
    pub standards: &'a str,
    /// Repository names to cover; empty = all.
    pub only: &'a [String],
    /// Tag of NoahDuongMaster/larpcop's reusable workflow.
    pub workflow_ref: &'a str,
    pub dry_run: bool,
}

/// Returns one line per repository: what was done, or why it was skipped. A
/// repository that fails does not stop the others (their pull requests are
/// opened already); the error then lists every line, failed ones included.
pub fn setup(plan: &Plan) -> Result<Vec<String>> {
    let mut out = Vec::new();
    let mut failed = 0;
    for repo in gh::repos(plan.owner)? {
        let name = repo.full.rsplit('/').next().unwrap_or(&repo.full);
        if !plan.only.is_empty() && !plan.only.iter().any(|r| r == name || *r == repo.full) {
            continue;
        }
        out.push(repo_line(&repo, plan).unwrap_or_else(|e| {
            failed += 1;
            format!("{}: FAILED: {e:#}", repo.full)
        }));
    }
    if failed > 0 {
        bail!("{failed} repositories failed:\n{}", out.join("\n"));
    }
    Ok(out)
}

fn repo_line(repo: &gh::Repo, plan: &Plan) -> Result<String> {
    let status: Status = super::repo_status(repo)?;
    Ok(match (&status.gate, &status.setup_pr) {
        (Some(gate), _) => format!("{}: already enforced ({gate})", repo.full),
        (None, Some(pr)) => format!("{}: setup PR already open: {pr}", repo.full),
        (None, None) => {
            let files = files_for(repo, plan)?;
            let names: Vec<&str> = files.iter().map(|(p, _)| p.as_str()).collect();
            if plan.dry_run {
                format!("{}: would open a PR with {}", repo.full, names.join(", "))
            } else {
                let url = open_pr(repo, &files)?;
                format!("{}: opened {url}", repo.full)
            }
        }
    })
}

/// Config (unless present), the gate workflow, and the agent files `larpcop sync`
/// produces from the repository's current files plus the forced standards.
fn files_for(repo: &gh::Repo, plan: &Plan) -> Result<Vec<(String, String)>> {
    // Removed when it goes out of scope, on the error paths as well.
    let scratch = tempfile::tempdir().context("creating a scratch directory")?;
    let tmp = scratch.path();
    let branch = &repo.default_branch;
    let mut out = Vec::new();
    let config = match gh::file(&repo.full, ".larpcop.yaml", branch)? {
        Some(existing) => existing,
        None => {
            let c = format!(
                "# Company coding rules, enforced by larpcop in hooks, pre-commit and CI.\nextends:\n  - '{}'\n",
                plan.standards
            );
            out.push((".larpcop.yaml".to_string(), c.clone()));
            c
        }
    };
    fs::write(tmp.join(".larpcop.yaml"), &config)?;
    let generated = crate::sync::AGENT_FILES.iter().map(|(_, rel, _)| *rel);
    for rel in std::iter::once("AGENTS.md").chain(generated) {
        if let Some(current) = gh::file(&repo.full, rel, branch)? {
            let path = tmp.join(rel);
            fs::create_dir_all(path.parent().context("agent file without a directory")?)?;
            fs::write(path, current)?;
        }
    }
    let ctx = Ctx::new(tmp, vec![plan.standards.to_string()], false)?;
    let (cfg, engine) = ctx
        .load()
        .with_context(|| format!("{}: resolving standards", repo.full))?;
    for rel in crate::sync::run(&cfg, &engine.rules(), false)? {
        let rel = rel.to_string_lossy().replace('\\', "/");
        out.push((rel.clone(), fs::read_to_string(tmp.join(&rel))?));
    }
    out.push((WORKFLOW.to_string(), workflow(plan)));
    Ok(out)
}

fn workflow(plan: &Plan) -> String {
    [
        "# The merge gate: violations of the company coding rules cannot be merged.",
        "name: larpcop",
        "on:",
        "  pull_request:",
        "jobs:",
        "  larpcop:",
        "    permissions:",
        "      contents: read",
        "      pull-requests: write",
        &format!(
            "    uses: NoahDuongMaster/larpcop/.github/workflows/enforce.yml@{}",
            plan.workflow_ref
        ),
        "    with:",
        &format!("      standards: '{}'", plan.standards),
        "    secrets:",
        "      larpcop-token: ${{ secrets.LARPCOP_TOKEN }}",
        "",
    ]
    .join("\n")
}

fn open_pr(repo: &gh::Repo, files: &[(String, String)]) -> Result<String> {
    let full = &repo.full;
    let head = gh::json(&[
        "api",
        &format!("repos/{full}/git/ref/heads/{}", repo.default_branch),
    ])?;
    let sha = head["object"]["sha"]
        .as_str()
        .context("default branch has no commit")?;
    let created = gh::gh(&[
        "api",
        "-X",
        "POST",
        &format!("repos/{full}/git/refs"),
        "-f",
        &format!("ref=refs/heads/{BRANCH}"),
        "-f",
        &format!("sha={sha}"),
    ]);
    // A previous run that stopped half-way left the branch: reuse it.
    if let Err(e) = created
        && !e.to_string().contains("Reference already exists")
    {
        return Err(e);
    }
    let mut body = "Adds the company coding rules (larpcop): `.larpcop.yaml`, the CI gate \
that blocks merging violations, and the hook/instruction files every coding agent reads.\n\n\
Generated by `larpcop org setup`. Merge it, then make the `larpcop` check required.\n"
        .to_string();
    let mut missing = "";
    for (path, content) in files {
        match gh::put(full, path, BRANCH, content, &format!("larpcop: add {path}")) {
            // Only tokens with the `workflow` scope may write workflow files.
            Err(_) if path == WORKFLOW => {
                missing = " (workflow file not committed: the token lacks the `workflow` scope)";
                body += &format!(
                    "\n**Missing:** `{WORKFLOW}` could not be committed (the token lacks the \
`workflow` scope; `gh auth refresh -s workflow` adds it). Add it by hand:\n\n```yaml\n{content}```\n"
                );
            }
            other => other?,
        }
    }
    let url = gh::gh(&[
        "pr",
        "create",
        "--repo",
        full,
        "--base",
        &repo.default_branch,
        "--head",
        BRANCH,
        "--title",
        "Enforce the company coding rules (larpcop)",
        "--body",
        &body,
    ])?;
    Ok(format!("{}{missing}", url.trim()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn workflow_is_valid_yaml_calling_the_gate() {
        let plan = Plan {
            owner: "acme",
            standards: "https://github.com/acme/standards.git#v1.2.0",
            only: &[],
            workflow_ref: "v0.2.0",
            dry_run: true,
        };
        // Regression: a `\` line continuation once ate the indentation of `with:`.
        let doc: serde_json::Value = serde_saphyr::from_str(&workflow(&plan)).unwrap();
        let job = &doc["jobs"]["larpcop"];
        assert_eq!(
            job["uses"],
            "NoahDuongMaster/larpcop/.github/workflows/enforce.yml@v0.2.0"
        );
        assert_eq!(job["with"]["standards"], plan.standards);
        assert_eq!(job["permissions"]["pull-requests"], "write");
    }
}
