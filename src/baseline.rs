//! Baseline: accepted legacy violations. `check` hides them so a rule can be
//! adopted on an old codebase before everything is fixed, while anything new
//! still fails. Entries match on rule, file and the offending line's text, not its
//! number, so edits elsewhere in the file do not resurface them.

use crate::rules::Violation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

pub const FILE: &str = ".larpcop-baseline.json";

type Key = (String, String, String);

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    version: u32,
    entries: Vec<Entry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Entry {
    rule: String,
    file: String,
    /// The offending source line (or the message, for findings without one).
    text: String,
    count: usize,
}

fn key(v: &Violation) -> Key {
    let text = v.snippet.clone().unwrap_or_else(|| v.message.clone());
    (v.rule.clone(), v.file.clone(), text)
}

fn counts(violations: &[Violation]) -> BTreeMap<Key, usize> {
    let mut out = BTreeMap::new();
    for v in violations {
        *out.entry(key(v)).or_insert(0) += 1;
    }
    out
}

impl Baseline {
    pub fn parse(text: &str) -> Result<Self> {
        serde_json::from_str(text).with_context(|| format!("invalid {FILE}"))
    }

    /// The baseline a check sees: the staged copy for pre-commit, else the worktree.
    pub fn load(root: &Path, staged: bool) -> Result<Option<Self>> {
        crate::files::read(root, FILE, staged)
            .map(|t| Self::parse(&t))
            .transpose()
    }

    /// Locked rules are the organization's: a repo may record their legacy
    /// violations once (the rule had no entries at `base`), but never add more.
    pub fn grown(&self, base: &Self, locked: &BTreeMap<String, String>) -> Vec<Violation> {
        let sum = |b: &Self, rule: &str| -> usize {
            b.entries
                .iter()
                .filter(|e| e.rule == rule)
                .map(|e| e.count)
                .sum()
        };
        locked
            .iter()
            .filter(|(rule, _)| {
                let before = sum(base, rule);
                before > 0 && sum(self, rule) > before
            })
            .map(|(rule, by)| Violation {
                rule: "baseline".into(),
                level: crate::rules::Level::Error,
                file: FILE.into(),
                line: 0,
                column: 0,
                message: format!(
                    "the baseline grew for `{rule}`, which is locked by {by}: new violations of a locked rule cannot be baselined."
                ),
                note: Some("Fix the new violations instead, and restore the baseline entries.".into()),
                snippet: None,
            })
            .collect()
    }

    pub fn of(violations: &[Violation]) -> Self {
        Self::from_counts(counts(violations))
    }

    fn from_counts(counts: BTreeMap<Key, usize>) -> Self {
        let entries = counts
            .into_iter()
            .filter(|(_, n)| *n > 0)
            .map(|((rule, file, text), count)| Entry {
                rule,
                file,
                text,
                count,
            })
            .collect();
        Self {
            version: 1,
            entries,
        }
    }

    fn counts(&self) -> BTreeMap<Key, usize> {
        self.entries
            .iter()
            .map(|e| ((e.rule.clone(), e.file.clone(), e.text.clone()), e.count))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.count).sum()
    }

    /// Known violations per rule id.
    pub fn per_rule(&self) -> BTreeMap<String, usize> {
        let mut out = BTreeMap::new();
        for e in &self.entries {
            *out.entry(e.rule.clone()).or_insert(0) += e.count;
        }
        out
    }

    /// Removes baselined violations; returns how many were hidden.
    pub fn apply(&self, violations: &mut Vec<Violation>) -> usize {
        let mut left = self.counts();
        let before = violations.len();
        violations.retain(|v| match left.get_mut(&key(v)) {
            Some(n) if *n > 0 => {
                *n -= 1;
                false
            }
            _ => true,
        });
        before - violations.len()
    }

    /// Keeps only entries that still occur: fixed violations leave the baseline,
    /// and nothing new is ever added.
    pub fn prune(&self, current: &[Violation]) -> Self {
        let now = counts(current);
        let kept = self
            .counts()
            .into_iter()
            .map(|(k, n)| {
                let still = now.get(&k).copied().unwrap_or(0);
                (k, n.min(still))
            })
            .collect();
        Self::from_counts(kept)
    }

    pub fn write(&self, root: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self)? + "\n";
        fs::write(root.join(FILE), text).with_context(|| format!("writing {FILE}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::Level;

    fn v(rule: &str, line: usize, text: &str) -> Violation {
        Violation {
            rule: rule.into(),
            level: Level::Error,
            file: "a.ts".into(),
            line,
            column: 1,
            message: "m".into(),
            note: None,
            snippet: Some(text.into()),
        }
    }

    #[test]
    fn hides_known_violations_wherever_they_move() {
        let base = Baseline::of(&[v("no-any", 3, "let x: any"), v("no-any", 9, "let x: any")]);
        // Lines moved, and one more identical violation appeared: only it remains.
        let mut now = vec![
            v("no-any", 13, "let x: any"),
            v("no-any", 19, "let x: any"),
            v("no-any", 30, "let x: any"),
            v("no-console", 5, "console.log(x)"),
        ];
        assert_eq!(base.apply(&mut now), 2);
        assert_eq!(now.len(), 2);
        let pruned = base.prune(&[v("no-any", 1, "let x: any")]);
        assert_eq!(pruned.len(), 1);
    }
}
