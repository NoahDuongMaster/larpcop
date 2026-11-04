//! `larpcop stats`: which rules fire in this repository, which apply but
//! caught nothing, and which apply to no file here. A rule that never fires
//! may be dead, wrong, or about code this repository does not have; a rule
//! that fires on most files is either a bad rule or a real habit to fix.

use crate::files::SourceFile;
use crate::rules::{Engine, Level, RuleInfo, Violation};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write;

/// One rule and what it did here.
#[derive(serde::Serialize)]
pub struct RuleUse {
    pub id: String,
    pub level: String,
    pub scope: String,
    /// Findings, before the baseline: a rule whose findings are all baselined still fires.
    pub count: usize,
    /// Files the rule applies to.
    pub files: usize,
    /// Files it reported in.
    pub hit_files: usize,
}

#[derive(serde::Serialize, Default)]
pub struct Stats {
    pub files: usize,
    pub findings: usize,
    pub errors: usize,
    pub warnings: usize,
    /// Rules that reported, most first.
    pub fired: Vec<RuleUse>,
    /// Rules that apply to files here and reported nothing.
    pub silent: Vec<RuleUse>,
    /// Rules that apply to no file of this repository.
    pub unused: Vec<RuleUse>,
}

/// Rule → (what it says, how many files of this repository it covers).
type Applied = BTreeMap<String, (RuleInfo, usize)>;

/// Counts for `files`, from `violations` (all rules, before the baseline).
pub fn collect(engine: &Engine, files: &[SourceFile], violations: &[Violation]) -> Stats {
    let applied: Applied = files
        .par_iter()
        .fold(Applied::new, |mut applied, file| {
            for info in engine.rules_for(&file.rel) {
                match applied.get_mut(&info.id) {
                    Some((_, n)) => *n += 1,
                    None => {
                        applied.insert(info.id.clone(), (info, 1));
                    }
                }
            }
            applied
        })
        .reduce(Applied::new, |mut all, part| {
            for (id, (info, n)) in part {
                match all.get_mut(&id) {
                    Some((_, total)) => *total += n,
                    None => {
                        all.insert(id, (info, n));
                    }
                }
            }
            all
        });
    // Rule → (findings, files it reported in, its level).
    let mut counts: BTreeMap<String, (usize, BTreeSet<String>, Level)> = BTreeMap::new();
    for v in violations {
        let entry = counts
            .entry(v.rule.clone())
            .or_insert_with(|| (0, BTreeSet::new(), v.level));
        entry.0 += 1;
        entry.1.insert(v.file.clone());
    }
    let mut fired = Vec::new();
    let mut silent = Vec::new();
    let mut unused = Vec::new();
    for (id, (info, applies)) in applied {
        let (count, hit_files) = counts
            .remove(&id)
            .map_or((0, 0), |(count, hit, _)| (count, hit.len()));
        let use_ = RuleUse {
            id: info.id,
            level: info.level.as_str().to_string(),
            scope: info.scope,
            count,
            files: applies,
            hit_files,
        };
        if count > 0 {
            fired.push(use_);
        } else if applies > 0 {
            silent.push(use_);
        } else {
            unused.push(use_);
        }
    }
    // Reported by something other than a rule of this engine: a dependency
    // rule, which covers the project and not a file's language.
    for (id, (count, hit, level)) in counts {
        fired.push(RuleUse {
            id,
            level: level.as_str().to_string(),
            scope: "dependencies".to_string(),
            count,
            files: files.len(),
            hit_files: hit.len(),
        });
    }
    fired.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.id.cmp(&b.id)));
    silent.sort_by(|a, b| a.id.cmp(&b.id));
    unused.sort_by(|a, b| a.id.cmp(&b.id));
    Stats {
        files: files.len(),
        findings: violations.len(),
        errors: violations
            .iter()
            .filter(|v| v.level == Level::Error)
            .count(),
        warnings: violations
            .iter()
            .filter(|v| v.level == Level::Warning)
            .count(),
        fired,
        silent,
        unused,
    }
}

/// The table, `top` rules of it.
pub fn render(stats: &Stats, top: usize) -> String {
    let mut out = format!(
        "{} file(s), {} finding(s): {} error, {} warning\n\n",
        stats.files, stats.findings, stats.errors, stats.warnings
    );
    let _ = writeln!(
        out,
        "{:>7} {:>6} {:>8}  {:<26} {:<8} applies to",
        "count", "files", "hit", "rule", "level"
    );
    for r in stats.fired.iter().take(top) {
        let _ = writeln!(
            out,
            "{:>7} {:>6} {:>8}  {:<26} {:<8} {}",
            r.count,
            r.files,
            r.hit_files,
            r.id,
            r.level,
            short(&r.scope)
        );
    }
    if stats.fired.len() > top {
        let _ = writeln!(out, "… {} more rule(s) reported", stats.fired.len() - top);
    }
    if !stats.silent.is_empty() {
        let _ = write!(
            out,
            "\n{} rule(s) apply to files here and caught nothing:\n  {}\n",
            stats.silent.len(),
            names(&stats.silent)
        );
    }
    if !stats.unused.is_empty() {
        let _ = write!(
            out,
            "\n{} rule(s) apply to no file of this repository:\n  {}\n",
            stats.unused.len(),
            names(&stats.unused)
        );
    }
    out
}

/// A rule's scope, cut to fit the table (`files:` globs are long).
fn short(scope: &str) -> String {
    match scope.char_indices().nth(44) {
        Some((cut, _)) => format!("{}…", &scope[..cut]),
        None => scope.to_string(),
    }
}

fn names(rules: &[RuleUse]) -> String {
    let ids: Vec<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    match ids.len() {
        0 => String::new(),
        n if n > 12 => format!("{} …", ids[..12].join(", ")),
        _ => ids.join(", "),
    }
}
