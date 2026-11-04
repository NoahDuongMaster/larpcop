//! `larpcop org`: roll the standards out to every repository of a GitHub user or
//! organization, and see which ones are actually enforced.

mod gh;
mod setup;

pub use setup::{Plan, setup};

use anyhow::{Context, Result};
use rayon::prelude::*;
use serde::Serialize;
use std::fmt::Write;

pub const BRANCH: &str = "larpcop/setup";
pub const WORKFLOW: &str = ".github/workflows/larpcop.yml";

#[derive(Serialize)]
pub struct Status {
    pub repo: String,
    /// `.larpcop.yaml` on the default branch.
    pub config: bool,
    /// `extends` entries of that config.
    pub standards: Vec<String>,
    /// Workflow that runs the enforce gate, if any.
    pub gate: Option<String>,
    /// Conclusion of the gate's latest run.
    pub last_run: Option<String>,
    /// Open `larpcop org setup` pull request.
    pub setup_pr: Option<String>,
}

impl Status {
    pub fn enforced(&self) -> bool {
        self.gate.is_some()
    }
}

/// A repository's status takes several `gh` processes that wait on the network:
/// more threads than CPUs keep them busy.
const GH_THREADS: usize = 16;

pub fn status(owner: &str) -> Result<Vec<Status>> {
    let repos = gh::repos(owner)?;
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(GH_THREADS)
        .build()
        .context("starting the threads that read the repositories")?;
    pool.install(|| {
        repos
            .par_iter()
            .map(|r| repo_status(r).with_context(|| format!("{}: reading its status", r.full)))
            .collect()
    })
}

fn repo_status(repo: &gh::Repo) -> Result<Status> {
    let (full, branch) = (repo.full.as_str(), repo.default_branch.as_str());
    let config = gh::file(full, ".larpcop.yaml", branch)?;
    let standards = config
        .as_deref()
        .and_then(|c| serde_saphyr::from_str::<crate::config::RawConfig>(c).ok())
        .map(|c| c.extends.iter().map(spec_label).collect())
        .unwrap_or_default();
    let mut gate = None;
    for n in gh::dir(full, ".github/workflows", branch)? {
        if !(n.ends_with(".yml") || n.ends_with(".yaml")) {
            continue;
        }
        // The caller, not a reusable definition that mentions itself.
        let calls_gate =
            gh::file(full, &format!(".github/workflows/{n}"), branch)?.is_some_and(|w| {
                let calls = w.contains("larpcop/.github/workflows/enforce.yml")
                    || (full.ends_with("/larpcop")
                        && w.contains("./.github/workflows/enforce.yml"))
                    || w.contains("larpcop check");
                calls && !w.contains("workflow_call:")
            });
        if calls_gate {
            gate = Some(n);
            break;
        }
    }
    let last_run = match &gate {
        Some(w) => {
            let runs = gh::json(&[
                "run",
                "list",
                "--repo",
                full,
                "--workflow",
                w,
                "--limit",
                "1",
                "--json",
                "conclusion,status",
            ])?;
            runs.get(0).and_then(|run| {
                let state = run["conclusion"].as_str().filter(|c| !c.is_empty());
                Some(state.or(run["status"].as_str())?.to_string())
            })
        }
        None => None,
    };
    let setup_pr = gh::json(&[
        "pr", "list", "--repo", full, "--head", BRANCH, "--state", "open", "--json", "url",
    ])?
    .get(0)
    .and_then(|v| v["url"].as_str().map(String::from));
    Ok(Status {
        repo: repo.full.clone(),
        config: config.is_some(),
        standards,
        gate,
        last_run,
        setup_pr,
    })
}

fn spec_label(spec: &crate::config::ExtendSpec) -> String {
    match spec.normalized() {
        crate::config::ExtendSpec::Git { git, reference, .. } => {
            format!("{git}#{}", reference.unwrap_or_else(|| "HEAD".into()))
        }
        crate::config::ExtendSpec::Path { path } => path,
        crate::config::ExtendSpec::Short(s) => s,
    }
}

/// One line per repository, then a summary. `expected`: the standards every
/// repository should extend (flags missing and outdated pins).
pub fn render(rows: &[Status], expected: Option<&str>) -> String {
    let mut out = format!(
        "{:<44} {:<8} {:<10} {:<14} standards\n",
        "repository", "config", "gate", "last run"
    );
    for r in rows {
        let gate = if r.enforced() { "✓" } else { "✗" };
        let mut standards = r.standards.join(", ");
        if let Some(want) = expected
            && !r.standards.iter().any(|s| s == want)
        {
            standards = format!(
                "{} (expected {want})",
                if standards.is_empty() {
                    "-"
                } else {
                    &standards
                }
            );
        }
        let _ = writeln!(
            out,
            "{:<44} {:<8} {:<10} {:<14} {standards}{}",
            r.repo,
            if r.config { "✓" } else { "✗" },
            gate,
            r.last_run.as_deref().unwrap_or("-"),
            r.setup_pr
                .as_ref()
                .map(|u| format!("  [setup PR: {u}]"))
                .unwrap_or_default(),
        );
    }
    let enforced = rows.iter().filter(|r| r.enforced()).count();
    let _ = writeln!(
        out,
        "\n{enforced}/{} repositories run the larpcop gate in CI.",
        rows.len()
    );
    out
}
