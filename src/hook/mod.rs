//! Agent hook adapters. They only shorten the feedback loop; the git hook and
//! CI enforce the same rules for agents without hook support.
//!
//! One decision core, four wire protocols: `event` parses each agent's payload,
//! `respond` encodes the verdict the way that agent expects.

mod event;
mod exec_gate;
pub mod guard;
mod guard_cache;
mod inert;
mod predict;
mod respond;
mod shell_gate;
mod shell_run;

use crate::context::Ctx;
use crate::files::Scope;
use crate::report;
use anyhow::{Context, Result};
use event::Event;
use respond::Verdict;
use serde_json::Value;
use std::io::{self, ErrorKind, Read};
use std::path::{Path, PathBuf};

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
    let input: Value = serde_json::from_str(&raw).context("invalid hook input JSON")?;
    let cwd = match event::session_dir(&input) {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };
    let mut event = event::parse(agent, &input, &cwd);
    if let Event::AfterShell(since) = &mut event {
        *since = shell_run::take(&input);
    }
    // Kiro reports no "already continued" flag: remember our own blocks per session.
    let marker = (agent == Agent::Kiro && matches!(event, Event::Stop { .. }))
        .then(|| stop_marker(&input))
        .transpose()?;
    if let (Event::Stop { continued }, Some(m)) = (&mut event, &marker) {
        *continued = match std::fs::remove_file(m) {
            Ok(()) => true,
            Err(e) if e.kind() == ErrorKind::NotFound => false,
            Err(e) => return Err(e).with_context(|| format!("removing {}", m.display())),
        };
    }
    let mut verdict = decide(&event, &input, &cwd, &extends, refresh)?;
    if let (Event::Stop { .. }, Verdict::Block(_), Some(m)) = (&event, &verdict, &marker) {
        let written = m
            .parent()
            .map_or(Ok(()), std::fs::create_dir_all)
            .and_then(|()| std::fs::write(m, b""));
        if let Err(e) = written {
            // Without the flag every later stop would be blocked again, until the
            // agent runs out of turns: let this one through instead.
            eprintln!(
                "larpcop: warning: cannot write {} ({e}); not blocking this stop",
                m.display()
            );
            verdict = Verdict::Allow;
        }
    }
    let hook_event = input
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(respond::emit(agent, &event, hook_event, &verdict))
}

fn stop_marker(input: &Value) -> Result<PathBuf> {
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
    Ok(crate::config::cache_root()?.join("stop").join(safe))
}

fn decide(
    event: &Event,
    input: &Value,
    cwd: &Path,
    extends: &[String],
    refresh: bool,
) -> Result<Verdict> {
    let ctx = |start: &Path| Ctx::new(start, extends.to_vec(), refresh);
    match event {
        Event::Ignore => Ok(Verdict::Allow),
        // Parsed once: every check of the command reads the same tree.
        Event::Shell(command) => {
            let script = crate::shell_ast::parse(command);
            shell_gate::before(command, &script, input, cwd, extends, refresh)
        }
        Event::AfterShell(None) => Ok(Verdict::Allow),
        Event::AfterShell(Some(since)) => {
            let ctx = ctx(cwd)?;
            let changed = shell_run::changed_since(&ctx.root, since)?;
            if changed.is_empty() {
                return Ok(Verdict::Allow);
            }
            let header = "larpcop: the command you just ran changed files that break enforced \
rules. Fix them now.";
            check(&ctx, Scope::Touched(changed), header)
        }
        Event::BeforeEdit(paths) => {
            let mut ctxs = Vec::new();
            for path in paths {
                let at = ctx_at(&mut ctxs, start_dir(path, cwd), extends, refresh)?;
                if let Some(reason) = guard::protected_path(path, &rule_dirs(&ctxs[at])) {
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

/// The context of the project `dir` belongs to, as an index into `ctxs`: a hook
/// call touching several files of one project loads its configuration once.
fn ctx_at(ctxs: &mut Vec<Ctx>, dir: &Path, extends: &[String], refresh: bool) -> Result<usize> {
    let fresh = Ctx::new(dir, extends.to_vec(), refresh)?;
    if let Some(at) = ctxs.iter().position(|c| c.root == fresh.root) {
        return Ok(at);
    }
    ctxs.push(fresh);
    Ok(ctxs.len() - 1)
}

/// Rule files are protected from edits. When the configuration cannot be read
/// they cannot be found: the edit goes on (a broken config must not wedge the
/// agent; commit and CI still enforce), and the stderr line says so.
fn rule_dirs(ctx: &Ctx) -> Vec<PathBuf> {
    match ctx.config() {
        Ok(cfg) => cfg.rule_dirs.clone(),
        Err(e) => {
            eprintln!("larpcop: warning: rule files are not protected from this edit: {e:#}");
            Vec::new()
        }
    }
}

/// Verdict on content about to be written to `path`, if it must be blocked.
fn proposed(ctx: &Ctx, path: &Path, content: &str) -> Result<Option<Verdict>> {
    if let Some(reason) = guard::protected_path(path, &rule_dirs(ctx)) {
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
