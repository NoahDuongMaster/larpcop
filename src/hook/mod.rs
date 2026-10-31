//! Agent hook adapters. They only shorten the feedback loop; the git hook and
//! CI enforce the same rules for agents without hook support.
//!
//! One decision core, four wire protocols: `event` parses each agent's payload,
//! `respond` encodes the verdict the way that agent expects.

mod event;
pub mod guard;
mod respond;

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
}

pub fn run(agent: Agent, extends: Vec<String>, refresh: bool) -> Result<i32> {
    let mut raw = String::new();
    io::stdin().read_to_string(&mut raw)?;
    let input: serde_json::Value = serde_json::from_str(&raw).context("invalid hook input JSON")?;
    let cwd = match event::session_dir(&input) {
        Some(dir) => dir,
        None => std::env::current_dir()?,
    };
    let event = event::parse(agent, &input, &cwd);
    let verdict = decide(&event, &cwd, &extends, refresh)?;
    let hook_event = input
        .get("hook_event_name")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    Ok(respond::emit(agent, &event, hook_event, &verdict))
}

fn decide(event: &Event, cwd: &Path, extends: &[String], refresh: bool) -> Result<Verdict> {
    let ctx = |start: &Path| Ctx::new(start, extends.to_vec(), refresh);
    match event {
        Event::Ignore => Ok(Verdict::Allow),
        Event::Shell(command) => Ok(blocked(guard::bash_bypass(command))),
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
        Event::AfterEdit(paths) => {
            let header = "agentkit: the file you just edited breaks enforced rules. Fix them now.";
            check(
                &ctx(start_dir(&paths[0], cwd))?,
                Scope::Paths(paths.clone()),
                header,
            )
        }
        // Block the first stop only. If the agent still stops (e.g. to ask the human
        // about a conflicting instruction), re-blocking just loops: observed live,
        // 8 identical blocks until max-turns. The commit/CI gates keep enforcing.
        Event::Stop { continued: true } => Ok(Verdict::Allow),
        Event::Stop { continued: false } => {
            let header = "agentkit: you cannot finish yet: your uncommitted changes break enforced \
rules. Fix every error below, then finish.";
            check(&ctx(cwd)?, Scope::Changed, header)
        }
    }
}

fn start_dir<'a>(file: &'a Path, cwd: &'a Path) -> &'a Path {
    file.parent().filter(|p| p.is_dir()).unwrap_or(cwd)
}

fn blocked(reason: Option<String>) -> Verdict {
    match reason {
        Some(reason) => Verdict::Block(format!(
            "agentkit: blocked: {reason}\n\n{}",
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
