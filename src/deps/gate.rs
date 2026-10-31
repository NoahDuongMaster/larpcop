//! The agent hook's view of a shell command before it runs: installs of
//! unapproved, malicious or too-new packages, and weakened age gates.

use super::{Deps, approval, install};
use std::path::Path;

impl Deps {
    /// Agent hook check on a shell command before it runs; `Some(reason)` blocks it.
    pub fn gate_command(&self, root: &Path, cwd: &Path, command: &str) -> Option<String> {
        let script = crate::shell_ast::parse(command);
        if self
            .min_days
            .is_some_and(|days| install::weakens_age_gate(command, days))
        {
            return Some(
                "weakening the package manager's minimum release age is not allowed: the repo \
sets it for everyone."
                    .into(),
            );
        }
        let invocations = install::invocations(&script);
        if let Some(reason) = self
            .min_days
            .and_then(|days| self.gate_forms(days, &script, &invocations))
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
            .and_then(|min| self.gate_vulnerable(min, &requests))
        {
            return Some(reason);
        }
        if self.approval
            && let Some(reason) = self.gate_unapproved(root, cwd, &requests)
        {
            return Some(reason);
        }
        self.min_days
            .and_then(|days| self.gate_young(days, &requests, &invocations, cwd))
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
