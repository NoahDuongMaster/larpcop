//! The agent hook's view of a shell command before it runs: installs of
//! unapproved, malicious or too-new packages, and weakened age gates.

use super::osv::Osv;
use super::{Deps, approval, clock, install};
use crate::shell_ast::Script;
use jiff::Timestamp;
use std::path::Path;

impl Deps {
    /// Agent hook check on a parsed shell command before it runs; `Some(reason)`
    /// blocks it.
    pub fn gate_command(&self, root: &Path, cwd: &Path, script: &Script) -> Option<String> {
        if self
            .min_days
            .is_some_and(|days| install::weakens_age_gate(script, days))
        {
            return Some(
                "weakening the package manager's minimum release age is not allowed: the repo \
sets it for everyone."
                    .into(),
            );
        }
        // The release-age window as a date; a window that cannot be computed blocks.
        let window: Option<(u32, Timestamp)> = match self
            .min_days
            .map(|days| clock::cutoff(days).map(|cutoff| (days, cutoff)))
            .transpose()
        {
            Ok(window) => window,
            Err(e) => return Some(format!("{e:#}; this check fails closed.")),
        };
        let invocations = install::invocations(script);
        if let Some(reason) =
            window.and_then(|(days, cutoff)| self.gate_forms(days, cutoff, script, &invocations))
        {
            return Some(reason);
        }
        let requests: Vec<install::Request> = invocations
            .iter()
            .flat_map(install::Invocation::requests)
            .collect();
        if requests.is_empty() {
            return None;
        }
        if let Some(reason) = self
            .vulns
            .and_then(|min| self.gate_vulnerable(&Osv::new(), min, &requests))
        {
            return Some(reason);
        }
        if self.approval
            && let Some(reason) = self.gate_unapproved(root, cwd, &requests)
        {
            return Some(reason);
        }
        window
            .and_then(|(days, cutoff)| self.gate_young(days, cutoff, &requests, &invocations, cwd))
    }

    fn gate_unapproved(
        &self,
        root: &Path,
        cwd: &Path,
        requests: &[install::Request],
    ) -> Option<String> {
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
