//! A shell command before it runs: attempts to switch enforcement off, the files
//! it is going to write (judged as if the agent had written them with its edit
//! tool), and dependency code that must not run while the dependency files fail
//! the rules.

use super::respond::Verdict;
use super::shell_run::{self, Dirty};
use super::{blocked, ctx_at, exec_gate, guard, inert, predict, proposed, start_dir};
use crate::context::Ctx;
use crate::deps::Deps;
use crate::shell_ast::Script;
use anyhow::Result;
use serde_json::Value;
use std::path::{Path, PathBuf};

/// `script` is `command`, parsed once by the caller for every check below.
pub fn before(
    command: &str,
    script: &Script,
    input: &Value,
    cwd: &Path,
    extends: &[String],
    refresh: bool,
) -> Result<Verdict> {
    if let Some(reason) = guard::bash_bypass(command, script) {
        return Ok(blocked(Some(reason)));
    }
    // Files written by the shell skip the agent's edit hooks: check them here.
    let dir = script
        .cd()
        .map_or_else(|| cwd.to_path_buf(), |d| cwd.join(d));
    let mut ctxs = Vec::new();
    for (path, content) in writes(script, &dir) {
        let at = ctx_at(&mut ctxs, start_dir(&path, cwd), extends, refresh)?;
        if let Some(v) = proposed(&ctxs[at], &path, &content)? {
            return Ok(v);
        }
    }
    let installs = crate::deps::concerns(command, script);
    // One `git status` is both the snapshot the after-shell check compares with and
    // the list of dependency files the exec gate looks at.
    let dirty = crate::context::find_root(cwd).and_then(|root| shell_run::dirty(&root));
    if let Err(e) = &dirty {
        eprintln!(
            "larpcop: warning: the files this command changes will not be checked afterwards: {e:#}"
        );
    }
    let reason = if installs || inert::runs_code(script) {
        // A broken config must not wedge the agent: commit and CI still enforce.
        let gate = ctx_at(&mut ctxs, cwd, extends, refresh)
            .and_then(|at| dependency_gate(&ctxs[at], script, installs, cwd, dirty.as_ref()));
        gate.unwrap_or_else(|e| {
            eprintln!("larpcop: warning: the dependency gate is off for this command: {e:#}");
            None
        })
    } else {
        None
    };
    let verdict = blocked(reason);
    if let (Verdict::Allow, Ok(dirty)) = (&verdict, &dirty) {
        shell_run::record(input, dirty);
    }
    Ok(verdict)
}

/// (file, content it will have) for every write the script is known to make.
fn writes(script: &Script, dir: &Path) -> Vec<(PathBuf, String)> {
    let mut writes: Vec<(PathBuf, String)> = script
        .file_writes
        .iter()
        .map(|w| {
            let path = dir.join(&w.path);
            let content = match (w.append, std::fs::read_to_string(&path)) {
                (true, Ok(old)) => old + &w.content,
                _ => w.content.clone(),
            };
            (path, content)
        })
        .collect();
    writes.extend(predict::predicted(script, dir));
    writes
}

/// Why the dependency rules stop this command, if they do. Only the configuration
/// and the dependency rules are needed: the engine's other rules stay unparsed.
fn dependency_gate(
    ctx: &Ctx,
    script: &Script,
    installs: bool,
    cwd: &Path,
    dirty: Result<&Dirty, &anyhow::Error>,
) -> Result<Option<String>> {
    let cfg = ctx.config()?;
    let Some(deps) = Deps::new(cfg)? else {
        return Ok(None);
    };
    Ok(installs
        .then_some(&deps)
        .and_then(|d| d.gate_command(&cfg.root, cwd, script))
        .or_else(|| exec_gate::check(cfg, &deps, script, dirty)))
}
