//! `dependency-approval`: direct dependencies the repo did not declare before.

use super::ecosystem::Ecosystem;
use super::manifest::{self, Direct};
use super::{APPROVAL_ID, Deps, View, file_name, unreadable};
use crate::files::{self, Scope};
use crate::rules::{Level, Violation};
use std::fs;
use std::path::Path;

impl Deps {
    /// Dependencies `rel` declares that no manifest declared at the base commit.
    pub(super) fn unapproved(
        &self,
        rel: &str,
        name: &str,
        view: &View,
        known: &Direct,
    ) -> Vec<Violation> {
        let Some(content) = view.current(rel) else {
            return Vec::new();
        };
        let declared = match manifest::parse(name, &content) {
            Some(Ok(d)) => d,
            Some(Err(e)) => return vec![unreadable(rel, APPROVAL_ID, &e)],
            None => return Vec::new(),
        };
        declared
            .iter()
            .filter(|dep| !known.contains(*dep) && !self.approved.matches(dep.0, &dep.1))
            .map(|(eco, dep)| new_dependency(rel, &content, *eco, dep))
            .collect()
    }
}

fn new_dependency(rel: &str, content: &str, eco: Ecosystem, dep: &str) -> Violation {
    let line = manifest::line_of(content, dep);
    Violation {
        rule: APPROVAL_ID.into(),
        level: Level::Error,
        file: rel.into(),
        line,
        column: usize::from(line > 0),
        message: format!("New dependency `{dep}` ({eco}) has not been approved."),
        note: Some(format!(
            "A new dependency needs a human's approval. Solve the task without it, or stop and \
ask the user to approve it: they add `{eco}:{dep}` to `dependencies.approved` in .larpcop.yaml."
        )),
        snippet: None,
    }
}

/// Direct dependencies of every manifest at the base commit. A dependency the repo
/// already declares somewhere is not new, even in a new workspace package.
pub(super) fn known(view: &View) -> Direct {
    let Some(base) = view.base.as_deref() else {
        return Direct::new();
    };
    files::tree(view.root, base)
        .iter()
        .filter(|rel| manifest::is_manifest(file_name(rel)))
        .filter_map(|rel| {
            let content = files::show(view.root, base, rel)?;
            manifest::parse(file_name(rel), &content)?.ok()
        })
        .flatten()
        .collect()
}

/// For the agent hook: what HEAD declares, plus uncommitted manifest edits from
/// `cwd` up to the root (a human may have added the dependency already).
pub(super) fn known_now(root: &Path, cwd: &Path) -> Direct {
    let view = View {
        root,
        staged: false,
        base: files::base(root, &Scope::Changed),
    };
    let cwd = dunce::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    let nearby = cwd
        .ancestors()
        .take_while(|dir| dir.starts_with(root))
        .flat_map(|dir| fs::read_dir(dir).into_iter().flatten().flatten())
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !manifest::is_manifest(&name) {
                return None;
            }
            let content = fs::read_to_string(entry.path()).ok()?;
            manifest::parse(&name, &content)?.ok()
        })
        .flatten();
    let mut out = known(&view);
    out.extend(nearby);
    out
}
