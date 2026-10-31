//! Output formats. `text` is written so an LLM agent can act on it directly.

use crate::context::Outcome;
use crate::rules::{Level, Violation};
use std::fmt::Write;

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum Format {
    Text,
    Json,
    /// GitHub Actions annotations followed by the text report.
    Github,
}

pub const NO_BYPASS: &str = "These rules are enforced by the pre-commit hook and CI: violating code cannot be \
committed or merged, whoever wrote it. Fix what the rule is about, not its wording: rewriting the same \
construct in another form to dodge a check (aliases, computed property access, eval, indirection) is a \
violation too. Do not add suppression comments, use `--no-verify`, or edit `.agentkit.yaml`; if a rule \
looks wrong, stop and ask a human.";

pub fn render(outcome: &Outcome, format: Format) -> String {
    match format {
        Format::Text => text(outcome),
        Format::Json => json(outcome),
        Format::Github => github(outcome) + &text(outcome),
    }
}

fn summary(outcome: &Outcome) -> String {
    let count = |l: Level| outcome.violations.iter().filter(|v| v.level == l).count();
    let (errors, warnings) = (count(Level::Error), count(Level::Warning));
    let others = outcome.violations.len() - errors - warnings;
    let mut s = format!("{errors} error(s), {warnings} warning(s)");
    if others > 0 {
        let _ = write!(s, ", {others} hint(s)");
    }
    format!("{s} in {} checked file(s)", outcome.files)
}

pub fn text(outcome: &Outcome) -> String {
    if outcome.unconfigured {
        return "agentkit: no rules configured (no .agentkit.yaml and no --extends); nothing enforced.\n".into();
    }
    if outcome.violations.is_empty() {
        return format!(
            "agentkit: ✓ no violations in {} checked file(s){}\n",
            outcome.files,
            hidden(outcome)
        );
    }
    let mut out = format!("agentkit: ✗ {}{}\n", summary(outcome), hidden(outcome));
    let mut current: Option<&str> = None;
    for v in &outcome.violations {
        if current != Some(v.file.as_str()) {
            current = Some(v.file.as_str());
            let header = if v.file.is_empty() {
                "(project)"
            } else {
                v.file.as_str()
            };
            let _ = write!(out, "\n{header}\n");
        }
        write_violation(&mut out, v);
    }
    if outcome.errors() > 0 {
        let _ = write!(out, "\n{NO_BYPASS}\n");
    }
    out
}

fn hidden(outcome: &Outcome) -> String {
    match outcome.baselined {
        0 => String::new(),
        n => format!(
            " ({n} known violation(s) hidden by {})",
            crate::baseline::FILE
        ),
    }
}

fn write_violation(out: &mut String, v: &Violation) {
    let pos = if v.line > 0 {
        format!("{}:{}", v.line, v.column)
    } else {
        "-".into()
    };
    let _ = writeln!(
        out,
        "  {pos:<7} {:<7} {}  {}",
        v.level.as_str(),
        v.rule,
        v.message
    );
    if let Some(snippet) = &v.snippet {
        let _ = writeln!(out, "          │ {snippet}");
    }
    if let Some(note) = &v.note {
        for (i, line) in note.lines().enumerate() {
            let lead = if i == 0 { "└ fix:" } else { "      " };
            let _ = writeln!(out, "          {lead} {line}");
        }
    }
}

fn json(outcome: &Outcome) -> String {
    let value = serde_json::json!({
        "files_checked": outcome.files,
        "errors": outcome.errors(),
        "baselined": outcome.baselined,
        "violations": outcome.violations,
    });
    serde_json::to_string_pretty(&value).unwrap_or_default() + "\n"
}

fn github(outcome: &Outcome) -> String {
    let mut out = String::new();
    for v in &outcome.violations {
        let kind = match v.level {
            Level::Error => "error",
            Level::Warning => "warning",
            Level::Info | Level::Hint => "notice",
        };
        let mut props = format!("title={}", escape_prop(&v.rule));
        if !v.file.is_empty() {
            let _ = write!(
                props,
                ",file={},line={},col={}",
                escape_prop(&v.file),
                v.line,
                v.column
            );
        }
        let body = match &v.note {
            Some(note) => format!("{}\n{note}", v.message),
            None => v.message.clone(),
        };
        let _ = writeln!(out, "::{kind} {props}::{}", escape_data(&body));
    }
    out
}

fn escape_data(s: &str) -> String {
    s.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

fn escape_prop(s: &str) -> String {
    escape_data(s).replace(':', "%3A").replace(',', "%2C")
}
