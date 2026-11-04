//! What a shell command changed. Before it runs, a snapshot of the uncommitted
//! files is taken; afterwards exactly what the command touched (`sed -i`, `cp`,
//! generators, scripts, installs) is checked at once, like a file edit, whatever
//! the file system's timestamp granularity.

use anyhow::{Context, Result};
use serde_json::Value;
use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

/// More files than this changed by one command: only dependency files are checked
/// (a build or vendoring step), the rest waits for the Stop hook and the commit.
const MAX_FILES: usize = 300;

/// Uncommitted files under the root: (root-relative path, stamp of its time and size).
pub type Dirty = Vec<(String, String)>;

/// Where the snapshot of one tool call lives. Calls may overlap (parallel tool
/// calls), so it is keyed by the call's id, else by what the call runs.
fn marker(input: &Value) -> Result<PathBuf> {
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
        .map(str::to_string)
        .or_else(|| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            input.get("tool_input")?.to_string().hash(&mut h);
            Some(format!("h{:016x}", h.finish()))
        })
        .unwrap_or_else(|| "last".to_string());
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
    Ok(crate::config::cache_root()?.join("shell").join(safe))
}

/// Saves the snapshot taken before an allowed shell command runs. When it cannot
/// be saved, the files the command changes will not be checked afterwards: say so.
pub fn record(input: &Value, dirty: &[(String, String)]) {
    let snapshot: serde_json::Map<String, Value> = dirty
        .iter()
        .map(|(rel, stamp)| (rel.clone(), Value::from(stamp.as_str())))
        .collect();
    let saved = marker(input).and_then(|m| {
        if let Some(dir) = m.parent() {
            std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        }
        std::fs::write(&m, Value::Object(snapshot).to_string())
            .with_context(|| format!("writing {}", m.display()))
    });
    if let Err(e) = saved {
        eprintln!(
            "larpcop: warning: the files this command changes will not be checked afterwards: {e:#}"
        );
    }
}

/// The snapshot taken before the command that just finished, if there is one.
pub fn take(input: &Value) -> Option<Snapshot> {
    let loaded = marker(input).and_then(|m| {
        let text = match std::fs::read_to_string(&m) {
            Ok(text) => text,
            // No snapshot: the command was not recorded (or not by this agent).
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("reading {}", m.display())),
        };
        std::fs::remove_file(&m).with_context(|| format!("removing {}", m.display()))?;
        let map: BTreeMap<String, String> = serde_json::from_str(&text)
            .with_context(|| format!("{} is not a snapshot", m.display()))?;
        Ok(Some(Snapshot(map)))
    });
    loaded.unwrap_or_else(|e| {
        eprintln!("larpcop: warning: the files this command changed are not checked: {e:#}");
        None
    })
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot(BTreeMap<String, String>);

/// Files the command created or modified (ignored files are left out, as git
/// leaves them out), most recent first.
pub fn changed_since(root: &Path, before: &Snapshot) -> Result<Vec<PathBuf>> {
    let mut found: Vec<(String, PathBuf)> = dirty(root)?
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
    Ok(found.into_iter().map(|(_, p)| p).collect())
}

/// Uncommitted, existing files under `root` with a stamp of their modification
/// time and size, from one `git status`. Empty outside a git repository: nothing
/// is tracked there.
pub fn dirty(root: &Path) -> Result<Dirty> {
    let Some(top) = root.ancestors().find(|dir| dir.join(".git").exists()) else {
        return Ok(Vec::new());
    };
    // Porcelain paths are relative to the repository top, not to `root`.
    let prefix = root
        .strip_prefix(top)
        .map(|p| {
            p.components()
                .map(|c| format!("{}/", c.as_os_str().to_string_lossy()))
                .collect::<String>()
        })
        .unwrap_or_default();
    let out = crate::files::git(
        root,
        &[
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            ".",
        ],
    )?;
    let text = String::from_utf8_lossy(&out);
    let mut fields = text.split('\0');
    let mut found = Vec::new();
    while let Some(entry) = fields.next() {
        let (Some(status), Some(rel)) = (entry.get(..2), entry.get(3..)) else {
            continue;
        };
        if status.contains(['R', 'C']) {
            fields.next(); // the original path of a rename/copy
        }
        let Some(local) = rel.strip_prefix(&prefix) else {
            continue;
        };
        let meta = match std::fs::metadata(root.join(local)) {
            Ok(meta) => meta,
            Err(e) if matches!(e.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
                continue;
            } // deleted
            Err(e) => return Err(e).with_context(|| format!("reading {local}")),
        };
        let nanos = meta
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_nanos());
        found.push((local.to_string(), format!("{nanos:030}-{}", meta.len())));
    }
    Ok(found)
}
