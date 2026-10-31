//! Agent hook adapters. They only shorten the feedback loop; the git hook and
//! CI enforce the same rules for agents without hook support.
//!
//! One decision core, four wire protocols: `event` parses each agent's payload,
//! `respond` encodes the verdict the way that agent expects.

mod event;
pub mod guard;
mod inert;
mod predict;
mod respond;
mod shell_run;

use crate::context::Ctx;
use crate::files::Scope;
use crate::report;
use anyhow::{Context, Result};
use event::Event;
use respond::Verdict;
use std::io::{self, Read};
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Agent {
    ClaudeCode,
    Codex,
    Gemini,
    Cursor,
    /// GitHub Copilot CLI (Claude-compatible payloads, JSON verdicts).
    Copilot,
    /// Factory Droid.
    Droid,
    /// Kiro CLI / IDE.
    Kiro,
}

pub fn run(agent: Agent, extends: Vec<String>, refresh: bool) -> Result<i32> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let input: serde_json::Value = serde_json::from_str(&raw).context("invalid hook input JSON")?;
    let cwd = match event::session_dir(&input) {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };
    let mut event = event::parse(agent, &input, &cwd);
    if let Event::AfterShell(since) = &mut event {
        *since = shell_run::take(&input);
    }
    // Kiro reports no "already continued" flag: remember our own blocks per session.
    let marker = (agent == Agent::Kiro)
        .then(|| stop_marker(&input))
        .flatten();
    if let (Event::Stop { continued }, Some(m)) = (&mut event, &marker) {
        *continued = std::fs::remove_file(m).is_ok();
    }
    let verdict = decide(&event, &cwd, &extends, refresh)?;
    if let (Event::Shell(_), Verdict::Allow) = (&event, &verdict) {
        shell_run::record(&input, &cwd);
    }
    if let (Event::Stop { .. }, Verdict::Block(_), Some(m)) = (&event, &verdict, &marker) {
        let _ = m.parent().map(std::fs::create_dir_all);
        let _ = std::fs::write(m, b"");
    }
    let hook_event = input
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(respond::emit(agent, &event, hook_event, &verdict))
}

fn stop_marker(input: &serde_json::Value) -> Option<std::path::PathBuf> {
    let session = input
        .get("session_id")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let safe: String = session
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect();
    Some(crate::config::cache_root().ok()?.join("stop").join(safe))
}

fn decide(event: &Event, cwd: &Path, extends: &[String], refresh: bool) -> Result<Verdict> {
    let ctx = |start: &Path| Ctx::new(start, extends.to_vec(), refresh);
    match event {
        Event::Ignore => Ok(Verdict::Allow),
        Event::Shell(command) => {
            if let Some(reason) = guard::bash_bypass(command) {
                return Ok(blocked(Some(reason)));
            }
            // Files written by the shell skip the agent's edit hooks: check them here.
            let script = crate::shell_ast::parse(command);
            let dir = script
                .cd()
                .map_or_else(|| cwd.to_path_buf(), |d| cwd.join(d));
            let mut writes: Vec<(std::path::PathBuf, String)> = script
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
            writes.extend(predict::predicted(&script, &dir));
            for (path, content) in &writes {
                if let Some(v) = proposed(&ctx(start_dir(path, cwd))?, path, content)? {
                    return Ok(v);
                }
            }
            let installs = crate::deps::concerns(command);
            if !installs && !inert::runs_code(&script) {
                return Ok(Verdict::Allow);
            }
            // A broken config must not wedge the agent: commit and CI still enforce.
            let Ok((cfg, engine)) = ctx(cwd).and_then(|c| c.load()) else {
                return Ok(Verdict::Allow);
            };
            let reason = engine
                .deps()
                .filter(|_| installs)
                .and_then(|d| d.gate_command(&cfg.root, cwd, command))
                .or_else(|| shell_run::exec_gate(&cfg, &engine, &script));
            Ok(blocked(reason))
        }
        Event::AfterShell(None) => Ok(Verdict::Allow),
        Event::AfterShell(Some(since)) => {
            let root = crate::context::find_root(cwd)?;
            let changed = shell_run::changed_since(&root, since);
            if changed.is_empty() {
                return Ok(Verdict::Allow);
            }
            let header = "larpcop: the command you just ran changed files that break enforced \
rules. Fix them now.";
            check(&ctx(cwd)?, Scope::Touched(changed), header)
        }
        Event::BeforeEdit(paths) => {
            for path in paths {
                let rule_dirs = ctx(start_dir(path, cwd))?
                    .load()
                    .map(|(cfg, _)| cfg.rule_dirs)
                    .unwrap_or_default();
                if let Some(reason) = guard::protected_path(path, &rule_dirs) {
                    return Ok(blocked(Some(reason)));
                }
            }
            Ok(Verdict::Allow)
        }
        Event::AfterEdit(paths) if paths.is_empty() => Ok(Verdict::Allow),
        Event::Proposed(path, content) => {
            let ctx = ctx(start_dir(path, cwd))?;
            Ok(proposed(&ctx, path, content)?.unwrap_or(Verdict::Allow))
        }
        Event::AfterEdit(paths) => {
            let header = "larpcop: the file you just edited breaks enforced rules. Fix them now.";
            check(
                &ctx(start_dir(&paths[0], cwd))?,
                Scope::Touched(paths.clone()),
                header,
            )
        }
        // Block the first stop only. If the agent still stops (e.g. to ask the human
        // about a conflicting instruction), re-blocking just loops: observed live,
        // 8 identical blocks until max-turns. The commit/CI gates keep enforcing.
        Event::Stop { continued: true } => Ok(Verdict::Allow),
        Event::Stop { continued: false } => {
            let header = "larpcop: you cannot finish yet: your uncommitted changes break enforced \
rules. Fix every error below, then finish.";
            check(&ctx(cwd)?, Scope::Changed, header)
        }
    }
}

/// Verdict on content about to be written to `path`, if it must be blocked.
fn proposed(ctx: &Ctx, path: &Path, content: &str) -> Result<Option<Verdict>> {
    let rule_dirs = ctx.load().map(|(cfg, _)| cfg.rule_dirs).unwrap_or_default();
    if let Some(reason) = guard::protected_path(path, &rule_dirs) {
        return Ok(Some(blocked(Some(reason))));
    }
    let outcome = ctx.check_content(path, content)?;
    if outcome.errors() == 0 {
        return Ok(None);
    }
    let header = "larpcop: this write was not applied: the content breaks enforced rules. \
Write it again without these violations.";
    Ok(Some(Verdict::Block(format!(
        "{header}\n\n{}",
        report::text(&outcome)
    ))))
}

fn start_dir<'a>(file: &'a Path, cwd: &'a Path) -> &'a Path {
    file.parent().filter(|p| p.is_dir()).unwrap_or(cwd)
}

fn blocked(reason: Option<String>) -> Verdict {
    match reason {
        Some(reason) => Verdict::Block(format!(
            "larpcop: blocked: {reason}\n\n{}",
            report::NO_BYPASS
        )),
        None => Verdict::Allow,
    }
}

fn check(ctx: &Ctx, scope: Scope, header: &str) -> Result<Verdict> {
    let outcome = ctx.check(&scope)?;
    if outcome.errors() == 0 {
        return Ok(Verdict::Allow);
    }
    Ok(Verdict::Block(format!(
        "{header}\n\n{}",
        report::text(&outcome)
    )))
}
