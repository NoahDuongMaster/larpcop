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
mod check;
mod clock;
mod ecosystem;
#[cfg(test)]
mod fake;
mod gate;
mod install;
mod install_gate;
mod lockfile;
mod manifest;
mod net;
mod osv;
mod pm_config;
mod registry;
mod view;
mod vulns;

pub use check::Findings;
pub use osv::Severity;

use crate::config::Config;
use crate::files;
use crate::rules::{Level, RuleInfo, Violation};
use crate::shell_ast::Script;
use anyhow::Result;
use ecosystem::Patterns;
use globset::GlobSet;
use view::View;

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

/// Lockfiles, manifests and package-manager configs: what the dependency rules read.
pub fn is_dependency_file(file_name: &str) -> bool {
    lockfile::reads_pins(file_name)
        || manifest::is_manifest(file_name)
        || pm_config::relevant(file_name)
}

/// Cheap pre-filter: the agent hook loads the config only for commands that matter.
/// `script` is `command`, parsed.
pub fn concerns(command: &str, script: &Script) -> bool {
    let lower = command.to_ascii_lowercase();
    !install::invocations(script).is_empty()
        || install_gate::mentions(script)
        || [
            "release-age",
            "release_age",
            "minimalagegate",
            "minimal_age_gate",
            "exclude-newer",
            "exclude_newer",
        ]
        .iter()
        .any(|k| lower.contains(k))
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
