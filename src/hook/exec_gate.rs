//! Blocks commands that may run dependency code while the uncommitted
//! lockfiles/manifests fail the dependency rules.

use super::inert;
use super::shell_run::Dirty;
use crate::config::Config;
use crate::deps::Deps;
use crate::files::{self, Scope};
use crate::rules::Level;
use crate::shell_ast::Script;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// A verdict on unchanged dependency files and an unchanged policy is reused this long.
const GATE_TTL: Duration = Duration::from_secs(600);

/// `dirty`: the uncommitted files, from the snapshot the hook already took, or why
/// it could not be taken: which dependency files changed is then unknown, and
/// code that may run them does not run.
pub fn check(
    cfg: &Config,
    deps: &Deps,
    script: &Script,
    dirty: Result<&Dirty, &anyhow::Error>,
) -> Option<String> {
    if !inert::runs_code(script) {
        return None;
    }
    let dirty = match dirty {
        Ok(dirty) => dirty,
        Err(e) => {
            return Some(format!(
                "could not list the uncommitted files ({e:#}), so the dependency files cannot be \
checked; dependency code does not run until `git status` works."
            ));
        }
    };
    let changed: Vec<&str> = dirty
        .iter()
        .map(|(rel, _)| rel.as_str())
        .filter(|rel| crate::deps::is_dependency_file(rel.rsplit('/').next().unwrap_or(rel)))
        .collect();
    if changed.is_empty() {
        return None;
    }
    let cache = cache_file(cfg, &changed);
    if let Some(verdict) = cache.as_ref().and_then(|c| fresh(c)) {
        return (!verdict.is_empty()).then_some(verdict);
    }
    let paths = changed.iter().map(|r| cfg.root.join(r)).collect();
    let found = match deps.check(&cfg.root, &Scope::Touched(paths)) {
        Ok(found) => found,
        Err(e) => {
            return Some(format!(
                "could not check the changed dependency files ({e:#}); dependency code does not run \
until they pass."
            ));
        }
    };
    let errors: Vec<_> = found
        .violations
        .iter()
        .filter(|v| v.level == Level::Error)
        .collect();
    let verdict = if errors.is_empty() {
        String::new()
    } else {
        let lines: Vec<String> = errors
            .iter()
            .map(|v| {
                let note = v
                    .note
                    .as_deref()
                    .map(|n| format!("\n  {n}"))
                    .unwrap_or_default();
                format!("{}:{} {} {}{note}", v.file, v.line, v.rule, v.message)
            })
            .collect();
        format!(
            "this command can run dependency code, and the uncommitted dependency changes fail \
the dependency rules:\n- {}\nFix the lockfile or manifest first (the notes say how), then run it \
again. Commands that only read or resolve (git, cat, `cargo update --precise`, `npm i \
--ignore-scripts`, `poetry lock`, …) still work.",
            lines.join("\n- ")
        )
    };
    // A failed lookup (deps.dev, OSV) makes the verdict describe the network, not
    // the files: it is asked for again next time.
    if let Some(c) = cache.filter(|_| !found.lookup_failed) {
        let saved = c
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(&c, &verdict));
        if let Err(e) = saved {
            eprintln!(
                "larpcop: warning: cannot cache the dependency verdict at {}: {e}",
                c.display()
            );
        }
    }
    (!verdict.is_empty()).then_some(verdict)
}

/// Keyed by HEAD, the dependency files' current content and the policy they are
/// judged by: changing `min_release_age`, the approved list, … must take effect at once.
fn cache_file(cfg: &Config, rels: &[&str]) -> Option<PathBuf> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    env!("CARGO_PKG_VERSION").hash(&mut h);
    format!("{:?}", cfg.deps).hash(&mut h);
    cfg.disabled.hash(&mut h);
    cfg.exclude.hash(&mut h);
    files::base(&cfg.root, &Scope::Changed).hash(&mut h);
    for rel in rels {
        rel.hash(&mut h);
        std::fs::read(cfg.root.join(rel)).ok().hash(&mut h);
    }
    let dir = crate::config::cache_root().ok()?.join("exec-gate");
    Some(dir.join(format!("{:016x}", h.finish())))
}

fn fresh(file: &Path) -> Option<String> {
    let age = std::fs::metadata(file)
        .ok()?
        .modified()
        .ok()?
        .elapsed()
        .ok()?;
    (age < GATE_TTL)
        .then(|| std::fs::read_to_string(file).ok())
        .flatten()
}
