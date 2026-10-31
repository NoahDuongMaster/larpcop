//! Supply-chain rules. Dependencies are code nobody on the team wrote:
//! - `dependency-approval`: a new direct dependency needs a human's approval;
//! - `dependency-release-age`: no version younger than N days enters a lockfile
//!   (compromised releases are usually caught and pulled within days), and the
//!   package manager's own age gate stays on, so dev machines are covered at
//!   install time, before install scripts run;
//! - `dependency-vulnerability`: no known-malicious package anywhere, and no new
//!   version with a known vulnerability from a severity up (OSV.dev).

mod age;
mod approval;
mod ecosystem;
mod install;
mod lockfile;
mod manifest;
mod osv;
mod pm_config;
mod registry;
mod vulns;

pub use osv::Severity;

use crate::config::Config;
use crate::files::{self, Scope};
use crate::rules::{Level, RuleInfo, Violation};
use anyhow::Result;
use ecosystem::Patterns;
use globset::GlobSet;
use std::collections::BTreeSet;
use std::path::Path;

pub const AGE_ID: &str = "dependency-release-age";
pub const APPROVAL_ID: &str = "dependency-approval";
pub const VULN_ID: &str = "dependency-vulnerability";

pub struct Deps {
    min_days: Option<u32>,
    approval: bool,
    /// Lowest severity of a known vulnerability that blocks; malware always does.
    vulns: Option<Severity>,
    approved: Patterns,
    exempt: Patterns,
    exclude: GlobSet,
}

/// Both sides of a change: the scope's content (worktree or index) and the base commit.
struct View<'a> {
    root: &'a Path,
    staged: bool,
    base: Option<String>,
}

impl View<'_> {
    fn current(&self, rel: &str) -> Option<String> {
        files::read(self.root, rel, self.staged)
    }

    fn old(&self, rel: &str) -> Option<String> {
        files::show(self.root, self.base.as_deref()?, rel)
    }
}

/// Cheap pre-filter: the agent hook loads the config only for commands that matter.
pub fn concerns(command: &str) -> bool {
    !install::requests(command).is_empty() || install::weakens_age_gate(command)
}

impl Deps {
    pub fn new(cfg: &Config) -> Result<Option<Self>> {
        let p = &cfg.deps;
        let min_days = p
            .min_release_age
            .filter(|d| *d > 0 && !cfg.disabled.contains(AGE_ID));
        let approval = p.require_approval && !cfg.disabled.contains(APPROVAL_ID);
        let vulns = p
            .vulnerabilities
            .filter(|_| !cfg.disabled.contains(VULN_ID));
        if min_days.is_none() && !approval && vulns.is_none() {
            return Ok(None);
        }
        Ok(Some(Self {
            min_days,
            approval,
            vulns,
            approved: Patterns::new(&p.approved)?,
            exempt: Patterns::new(&p.exempt)?,
            exclude: files::globset(&cfg.exclude)?,
        }))
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        let mut out = Vec::new();
        if let Some(days) = self.min_days {
            out.push(RuleInfo {
                id: AGE_ID.into(),
                level: Level::Error,
                scope: "lockfiles".into(),
                message: format!(
                    "Every dependency version, direct or transitive, must have been published at \
least {days} days ago."
                ),
                note: Some(
                    "Keep the package manager's own minimum-release-age setting on; never override it."
                        .into(),
                ),
            });
        }
        if let Some(min) = self.vulns {
            out.push(RuleInfo {
                id: VULN_ID.into(),
                level: Level::Error,
                scope: "lockfiles, installs".into(),
                message: format!(
                    "No known-malicious package, and no new dependency version with a known {min:?} \
or worse vulnerability (OSV.dev)."
                ),
                note: Some("Pick a fixed version or another package; never install one an advisory names as malicious.".into()),
            });
        }
        if self.approval {
            out.push(RuleInfo {
                id: APPROVAL_ID.into(),
                level: Level::Error,
                scope: "manifests".into(),
                message: "Adding a direct dependency needs a human's approval.".into(),
                note: Some(
                    "Do not add or install a package the repo does not already use or list in \
`dependencies.approved`: solve the task without it, or ask the user."
                        .into(),
                ),
            });
        }
        out
    }

    pub fn check(&self, root: &Path, scope: &Scope) -> Result<Vec<Violation>> {
        let view = View {
            root,
            staged: matches!(scope, Scope::Staged),
            base: files::base(root, scope),
        };
        let mut out = Vec::new();
        let mut fresh = Vec::new();
        let mut gated_dirs = BTreeSet::new();
        let mut known = None;
        let mut locked = Vec::new();
        let audit = matches!(scope, Scope::All | Scope::Paths(_));
        for rel in files::list(root, scope)? {
            if self.exclude.is_match(&rel) {
                continue;
            }
            let name = file_name(&rel);
            if self.approval && manifest::is_manifest(name) {
                let known = known.get_or_insert_with(|| approval::known(&view));
                out.extend(self.unapproved(&rel, name, &view, known));
            }
            if self.min_days.is_some() {
                fresh.extend(self.fresh_pins(&rel, name, &view, &mut out));
                if pm_config::relevant(name) {
                    gated_dirs.insert(dir_of(&rel).to_string());
                }
            }
        }
        if let Some(min) = self.vulns {
            // Every lockfile, not only changed ones: a package reported as malware
            // today must block even a pull request that does not touch it.
            for rel in files::list(root, &Scope::All)? {
                if !self.exclude.is_match(&rel) {
                    locked.extend(self.locked(&rel, file_name(&rel), &view, audit));
                }
            }
            out.extend(self.vulnerable(min, &locked));
        }
        if let Some(days) = self.min_days {
            out.extend(age::too_new(days, &fresh)?);
            for dir in &gated_dirs {
                let gaps = pm_config::check(dir, days, &|rel| view.current(rel));
                out.extend(gaps.into_iter().map(|g| Violation {
                    rule: AGE_ID.into(),
                    level: Level::Error,
                    file: g.lockfile,
                    line: 0,
                    column: 0,
                    message: g.message,
                    note: Some(g.note),
                    snippet: None,
                }));
            }
        }
        Ok(out)
    }

    /// Agent hook check on a shell command before it runs; `Some(reason)` blocks it.
    pub fn gate_command(&self, root: &Path, cwd: &Path, command: &str) -> Option<String> {
        if self.min_days.is_some() && install::weakens_age_gate(command) {
            return Some(
                "overriding the package manager's minimum release age is not allowed: the repo \
sets it for everyone."
                    .into(),
            );
        }
        let requests = install::requests(command);
        if requests.is_empty() {
            return None;
        }
        if let Some(reason) = self
            .vulns
            .and_then(|min| self.gate_vulnerable(min, &requests))
        {
            return Some(reason);
        }
        if !self.approval {
            return None;
        }
        let known = approval::known_now(root, cwd);
        let blocked: Vec<String> = requests
            .iter()
            .filter(|r| match &r.name {
                Some(n) => !self.approved.matches(r.eco, n) && !known.contains(&(r.eco, n.clone())),
                None => !self.approved.matches(r.eco, &r.spec),
            })
            .map(|r| format!("`{}` ({})", r.name.as_deref().unwrap_or(&r.spec), r.eco))
            .collect();
        (!blocked.is_empty()).then(|| {
            format!(
                "installing {} needs a human's approval first: a new dependency is reviewed \
before any of its code runs here. Solve the task without it, or stop and ask the user to approve \
it (they add it to `dependencies.approved` in .larpcop.yaml).",
                blocked.join(", ")
            )
        })
    }
}

fn unreadable(rel: &str, rule: &str, e: &anyhow::Error) -> Violation {
    Violation {
        rule: rule.into(),
        level: Level::Error,
        file: rel.into(),
        line: 0,
        column: 0,
        message: format!("cannot read dependencies: {e:#}"),
        note: Some(
            "Fix the file so it parses; dependency rules cannot be checked otherwise.".into(),
        ),
        snippet: None,
    }
}

fn file_name(rel: &str) -> &str {
    rel.rsplit('/').next().unwrap_or(rel)
}

fn dir_of(rel: &str) -> &str {
    rel.rsplit_once('/').map_or("", |(dir, _)| dir)
}
