//! `agentkit test`: rule fixtures in ast-grep's format (`rule-tests/<id>-test.yml`
//! with `valid` / `invalid` snippets), plus `fixed` pairs for rules with a `fix:`.
//! A rule that only ever matched what its author imagined is how a standard rots.

use super::ast::{self, TESTS_DIR};
use anyhow::{Context, Result, anyhow};
use ast_grep_config::RuleConfig;
use ast_grep_language::{LanguageExt, SupportLang};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct Fixture {
    id: String,
    #[serde(default)]
    valid: Vec<String>,
    #[serde(default)]
    invalid: Vec<String>,
    #[serde(default)]
    fixed: Vec<Fixed>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixed {
    before: String,
    after: String,
}

pub struct Report {
    pub text: String,
    pub failures: usize,
    pub untested: Vec<String>,
}

pub fn run(rule_dirs: &[PathBuf]) -> Result<Report> {
    let rules: BTreeMap<String, RuleConfig<SupportLang>> = ast::load_all(rule_dirs)?
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
    let mut text = String::new();
    let mut failures = 0;
    let mut tested = Vec::new();
    for path in fixture_files(rule_dirs) {
        let raw = fs::read_to_string(&path)?;
        let fixture: Fixture = serde_saphyr::from_str(&raw)
            .with_context(|| format!("invalid fixture {}", path.display()))?;
        let rule = rules
            .get(&fixture.id)
            .ok_or_else(|| anyhow!("{}: no rule with id `{}`", path.display(), fixture.id))?;
        let errors = check(rule, &fixture);
        let cases = fixture.valid.len() + fixture.invalid.len() + fixture.fixed.len();
        if errors.is_empty() {
            let _ = writeln!(text, "✓ {:<28} {cases} case(s)", fixture.id);
        } else {
            let _ = writeln!(
                text,
                "✗ {:<28} {} of {cases} case(s) failed",
                fixture.id,
                errors.len()
            );
            for e in &errors {
                let _ = writeln!(text, "    {e}");
            }
        }
        failures += errors.len();
        tested.push(fixture.id);
    }
    let untested = rules
        .keys()
        .filter(|id| !tested.contains(id))
        .cloned()
        .collect();
    Ok(Report {
        text,
        failures,
        untested,
    })
}

fn check(rule: &RuleConfig<SupportLang>, fixture: &Fixture) -> Vec<String> {
    let lang = rule.language;
    let hits = |src: &str| lang.ast_grep(src).root().find_all(&rule.matcher).count();
    let mut errors = Vec::new();
    for case in &fixture.invalid {
        if hits(case) == 0 {
            errors.push(format!("invalid but not reported: {}", one_line(case)));
        }
    }
    for case in &fixture.valid {
        if hits(case) > 0 {
            errors.push(format!("valid but reported: {}", one_line(case)));
        }
    }
    for case in &fixture.fixed {
        if rule.fixer.is_empty() {
            errors.push("`fixed` cases given but the rule has no `fix:`".into());
            break;
        }
        let (out, _) = ast::apply_fixes(lang, &case.before, &[rule]);
        if out.trim_end() != case.after.trim_end() {
            errors.push(format!(
                "fix of {} gave {}, expected {}",
                one_line(&case.before),
                one_line(&out),
                one_line(&case.after)
            ));
        }
    }
    errors
}

/// Valid / invalid snippets of one rule's fixture, for explaining it to an agent.
pub fn examples(rule_dirs: &[PathBuf], id: &str) -> String {
    let mut out = String::new();
    for path in fixture_files(rule_dirs) {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        let Ok(f) = serde_saphyr::from_str::<Fixture>(&raw) else {
            continue;
        };
        if f.id != id {
            continue;
        }
        for (label, cases) in [("Violates", &f.invalid), ("Complies", &f.valid)] {
            for case in cases {
                let _ = writeln!(out, "\n{label}:\n{}", case.trim_end());
            }
        }
    }
    out
}

/// `rule-tests/` inside each rule dir, or beside it (ast-grep's project layout).
fn fixture_files(rule_dirs: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = rule_dirs
        .iter()
        .flat_map(|d| {
            [
                Some(d.join(TESTS_DIR)),
                d.parent().map(|p| p.join(TESTS_DIR)),
            ]
        })
        .flatten()
        .filter(|d| d.is_dir())
        .collect();
    dirs.sort();
    dirs.dedup();
    let mut files: Vec<PathBuf> = dirs.iter().flat_map(|d| yaml_in(d)).collect();
    files.sort();
    files.dedup();
    files
}

fn yaml_in(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "yml" || e == "yaml"))
        .collect()
}

fn one_line(s: &str) -> String {
    let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
    match flat.char_indices().nth(80) {
        Some((cut, _)) => format!("`{}…`", &flat[..cut]),
        None => format!("`{flat}`"),
    }
}
