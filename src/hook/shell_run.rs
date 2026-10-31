//! Shell commands an agent runs. Before: dependency code may not run while a
//! lockfile holds versions that failed the dependency checks. After: whatever
//! the command changed (`sed -i`, `cp`, generators, scripts, installs) is
//! checked at once, like a file edit.

use super::inert;
use crate::config::Config;
use crate::files::{self, Scope};
use crate::rules::{Engine, Level};
use crate::shell_ast::Script;
use serde_json::Value;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, UNIX_EPOCH};

/// More files than this changed by one command: only dependency files are checked
/// (a build or vendoring step), the rest waits for the Stop hook and the commit.
const MAX_FILES: usize = 300;
/// The exec gate's verdict on unchanged dependency files is reused this long.
const GATE_TTL: Duration = Duration::from_secs(600);

fn marker(input: &Value) -> Option<PathBuf> {
    let field = |k: &str| {
        input
            .get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
    };
    let session = field("session_id").unwrap_or("unknown");
    let call = ["tool_use_id", "tool_call_id", "call_id"]
        .iter()
        .find_map(|k| field(k))
        .unwrap_or("last");
    let safe: String = format!("{session}-{call}")
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(crate::config::cache_root().ok()?.join("shell").join(safe))
}

/// Snapshot of the uncommitted files (path → modification time) before an
/// allowed shell command runs, so afterwards exactly what it changed is known,
/// whatever the file system's timestamp granularity.
pub fn record(input: &Value, cwd: &Path) {
    let (Some(m), Ok(root)) = (marker(input), crate::context::find_root(cwd)) else {
        return;
    };
    let snapshot: serde_json::Map<String, Value> = dirty(&root)
        .into_iter()
        .map(|(rel, stamp)| (rel, Value::from(stamp)))
        .collect();
    let _ = m.parent().map(std::fs::create_dir_all);
    let _ = std::fs::write(m, Value::Object(snapshot).to_string());
}

/// The snapshot taken before the command that just finished.
pub fn take(input: &Value) -> Option<Snapshot> {
    let m = marker(input)?;
    let text = std::fs::read_to_string(&m).ok()?;
    let _ = std::fs::remove_file(&m);
    let map: serde_json::Map<String, Value> = serde_json::from_str(&text).ok()?;
    Some(Snapshot(
        map.into_iter()
            .filter_map(|(k, v)| Some((k, v.as_str()?.to_string())))
            .collect(),
    ))
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot(std::collections::BTreeMap<String, String>);

/// Files the command created or modified (ignored files are left out, as git
/// leaves them out), most recent first.
pub fn changed_since(root: &Path, before: &Snapshot) -> Vec<PathBuf> {
    let mut found: Vec<(String, PathBuf)> = dirty(root)
        .into_iter()
        .filter(|(rel, stamp)| before.0.get(rel) != Some(stamp))
        .map(|(rel, stamp)| (stamp, root.join(rel)))
        .collect();
    found.sort_by(|a, b| b.0.cmp(&a.0));
    let dependency = |p: &PathBuf| {
        p.file_name()
            .and_then(|n| n.to_str())
            .is_some_and(crate::deps::is_dependency_file)
    };
    if found.len() > MAX_FILES {
        found.retain(|(_, p)| dependency(p));
    }
    found.into_iter().map(|(_, p)| p).collect()
}

/// Uncommitted, existing files with a stamp of their modification time and size.
fn dirty(root: &Path) -> Vec<(String, String)> {
    let Ok(out) = Command::new("git")
        .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
        .current_dir(root)
        .output()
    else {
        return Vec::new();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut fields = text.split('\0');
    let mut found = Vec::new();
    while let Some(entry) = fields.next() {
        let (Some(status), Some(rel)) = (entry.get(..2), entry.get(3..)) else {
            continue;
        };
        if status.contains(['R', 'C']) {
            fields.next(); // the original path of a rename/copy
        }
        let Ok(meta) = std::fs::metadata(root.join(rel)) else {
            continue; // deleted
        };
        let nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        found.push((rel.to_string(), format!("{nanos:030}-{}", meta.len())));
    }
    found
}

/// Blocks commands that may run dependency code while the uncommitted
/// lockfiles/manifests fail the dependency rules.
pub fn exec_gate(cfg: &Config, engine: &Engine, script: &Script) -> Option<String> {
    if !inert::runs_code(script) {
        return None;
    }
    let deps = engine.deps()?;
    let changed: Vec<String> = files::list(&cfg.root, &Scope::Changed)
        .ok()?
        .into_iter()
        .filter(|rel| crate::deps::is_dependency_file(rel.rsplit('/').next().unwrap_or(rel)))
        .collect();
    if changed.is_empty() {
        return None;
    }
    let cache = cache_file(&cfg.root, &changed);
    if let Some(verdict) = cache.as_ref().and_then(|c| fresh(c)) {
        return (!verdict.is_empty()).then_some(verdict);
    }
    let paths = changed.iter().map(|r| cfg.root.join(r)).collect();
    let violations = match deps.check(&cfg.root, &Scope::Touched(paths)) {
        Ok(v) => v,
        Err(e) => {
            return Some(format!(
                "could not check the changed dependency files ({e:#}); dependency code does not run \
until they pass."
            ));
        }
    };
    let errors: Vec<String> = violations
        .iter()
        .filter(|v| v.level == Level::Error)
        .map(|v| {
            let note = v
                .note
                .as_deref()
                .map(|n| format!("\n  {n}"))
                .unwrap_or_default();
            format!("{}:{} {} {}{note}", v.file, v.line, v.rule, v.message)
        })
        .collect();
    let verdict = if errors.is_empty() {
        String::new()
    } else {
        format!(
            "this command can run dependency code, and the uncommitted dependency changes fail \
the dependency rules:\n- {}\nFix the lockfile or manifest first (the notes say how), then run it \
again. Commands that only read or resolve (git, cat, `cargo update --precise`, `npm i \
--ignore-scripts`, `poetry lock`, …) still work.",
            errors.join("\n- ")
        )
    };
    if let Some(c) = cache {
        let _ = c.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(c, &verdict);
    }
    (!verdict.is_empty()).then_some(verdict)
}

/// Keyed by HEAD and the dependency files' current content.
fn cache_file(root: &Path, rels: &[String]) -> Option<PathBuf> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    files::base(root, &Scope::Changed).hash(&mut h);
    for rel in rels {
        rel.hash(&mut h);
        std::fs::read(root.join(rel)).ok().hash(&mut h);
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
