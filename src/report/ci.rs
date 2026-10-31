//! Machine formats for CI systems: SARIF (GitHub code scanning, Azure DevOps,
//! most security dashboards), GitLab Code Quality, and a Markdown PR summary.

use super::summary;
use crate::context::Outcome;
use crate::rules::{Level, Violation};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fmt::Write;

const INFO_URI: &str = "https://github.com/NoahDuongMaster/larpcop";

fn sarif_level(level: Level) -> &'static str {
    match level {
        Level::Error => "error",
        Level::Warning => "warning",
        Level::Info | Level::Hint => "note",
    }
}

/// Project-wide findings (linters, dependency rules without a file) still need
/// a location in SARIF: they point at the repository root.
fn location(v: &Violation) -> Value {
    let uri = if v.file.is_empty() { "." } else { &v.file };
    let mut physical = json!({ "artifactLocation": { "uri": uri, "uriBaseId": "%SRCROOT%" } });
    if v.line > 0 {
        physical["region"] = json!({ "startLine": v.line, "startColumn": v.column.max(1) });
    }
    json!({ "physicalLocation": physical })
}

pub fn sarif(outcome: &Outcome) -> String {
    let mut rules: BTreeMap<&str, &Violation> = BTreeMap::new();
    for v in &outcome.violations {
        rules.entry(&v.rule).or_insert(v);
    }
    let descriptors: Vec<Value> = rules
        .values()
        .map(|v| {
            let mut d = json!({
                "id": v.rule,
                "shortDescription": { "text": v.message },
                "defaultConfiguration": { "level": sarif_level(v.level) },
            });
            if let Some(note) = &v.note {
                d["help"] = json!({ "text": note });
            }
            d
        })
        .collect();
    let results: Vec<Value> = outcome
        .violations
        .iter()
        .map(|v| {
            json!({
                "ruleId": v.rule,
                "level": sarif_level(v.level),
                "message": { "text": v.message },
                "locations": [location(v)],
                // Stable across line moves, like the baseline.
                "partialFingerprints": { "larpcop/v1": fingerprint(v) },
            })
        })
        .collect();
    let doc = json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": { "driver": {
                "name": "larpcop",
                "version": env!("CARGO_PKG_VERSION"),
                "informationUri": INFO_URI,
                "rules": descriptors,
            }},
            "results": results,
        }],
    });
    serde_json::to_string_pretty(&doc).unwrap_or_default() + "\n"
}

fn fingerprint(v: &Violation) -> String {
    let text = v.snippet.as_deref().unwrap_or(&v.message);
    format!(
        "{}:{}:{}",
        v.rule,
        v.file,
        text.split_whitespace().collect::<Vec<_>>().join(" ")
    )
}

/// https://docs.gitlab.com/ci/testing/code_quality/#code-quality-report-format
pub fn gitlab(outcome: &Outcome) -> String {
    let issues: Vec<Value> = outcome
        .violations
        .iter()
        .enumerate()
        .map(|(i, v)| {
            let severity = match v.level {
                Level::Error => "major",
                Level::Warning => "minor",
                Level::Info | Level::Hint => "info",
            };
            json!({
                "description": v.message,
                "check_name": v.rule,
                // Unique per issue: identical violations get an occurrence index.
                "fingerprint": format!("{}#{i}", fingerprint(v)),
                "severity": severity,
                "location": {
                    "path": if v.file.is_empty() { "." } else { &v.file },
                    "lines": { "begin": v.line.max(1) },
                },
            })
        })
        .collect();
    serde_json::to_string_pretty(&issues).unwrap_or_default() + "\n"
}

/// Sticky PR comment: counts per rule, then each finding with its fix.
pub fn markdown(outcome: &Outcome) -> String {
    let mut out = String::from("<!-- larpcop-report -->\n### larpcop\n\n");
    if outcome.violations.is_empty() {
        let _ = writeln!(
            out,
            "✅ No violations in {} changed file(s).",
            outcome.files
        );
        return out;
    }
    let mark = if outcome.errors() > 0 {
        "❌"
    } else {
        "⚠️"
    };
    let _ = writeln!(out, "{mark} {}\n", summary(outcome));
    let mut per_rule: BTreeMap<&str, usize> = BTreeMap::new();
    for v in &outcome.violations {
        *per_rule.entry(&v.rule).or_default() += 1;
    }
    out.push_str("| Rule | Count |\n|---|---|\n");
    for (rule, n) in &per_rule {
        let _ = writeln!(out, "| `{rule}` | {n} |");
    }
    out.push_str("\n<details><summary>Findings</summary>\n\n");
    for v in outcome.violations.iter().take(100) {
        let at = match (v.file.as_str(), v.line) {
            ("", _) => "(project)".to_string(),
            (f, 0) => format!("`{f}`"),
            (f, l) => format!("`{f}:{l}`"),
        };
        let _ = writeln!(out, "- {at} **{}** {}", v.rule, v.message);
        if let Some(note) = &v.note {
            let _ = writeln!(out, "  - fix: {}", note.lines().next().unwrap_or(""));
        }
    }
    if outcome.violations.len() > 100 {
        let _ = writeln!(out, "- … and {} more", outcome.violations.len() - 100);
    }
    out.push_str("\n</details>\n");
    out
}
