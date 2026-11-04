//! Baseline: accepted legacy violations. `check` hides them so a rule can be
//! adopted on an old codebase before everything is fixed, while anything new
//! still fails. Entries match on rule, file and the offending line's text, not its
//! number, so edits elsewhere in the file do not resurface them.

use crate::rules::Violation;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::Path;

pub const FILE: &str = ".larpcop-baseline.json";

/// (rule, file, offending text), borrowed from the violation or entry it names.
type Key<'a> = (&'a str, &'a str, &'a str);

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

fn key(v: &Violation) -> Key<'_> {
    let text = v.snippet.as_deref().unwrap_or(&v.message);
    (&v.rule, &v.file, text)
}

fn counts(violations: &[Violation]) -> BTreeMap<Key<'_>, usize> {
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
        crate::files::try_read(root, FILE, staged)?
            .map(|t| Self::parse(&t))
            .transpose()
    }

    /// Locked rules are the organization's: a repo may record their legacy
    /// violations once (the rule had no entries at `base`), but never add more.
    pub fn grown(&self, base: &Self, locked: &BTreeMap<String, String>) -> Vec<Violation> {
        let (now, before) = (self.per_rule(), base.per_rule());
        locked
            .iter()
            .filter(|(rule, _)| {
                let before = before.get(rule.as_str()).copied().unwrap_or(0);
                before > 0 && now.get(rule.as_str()).copied().unwrap_or(0) > before
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

    fn from_counts(counts: BTreeMap<Key<'_>, usize>) -> Self {
        let entries = counts
            .into_iter()
            .filter(|(_, n)| *n > 0)
            .map(|((rule, file, text), count)| Entry {
                rule: rule.to_string(),
                file: file.to_string(),
                text: text.to_string(),
                count,
            })
            .collect();
        Self {
            version: 1,
            entries,
        }
    }

    fn counts(&self) -> HashMap<Key<'_>, usize> {
        self.entries
            .iter()
            .map(|e| ((e.rule.as_str(), e.file.as_str(), e.text.as_str()), e.count))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.entries.iter().map(|e| e.count).sum()
    }

    /// Known violations per rule id.
    pub fn per_rule(&self) -> BTreeMap<&str, usize> {
        let mut out = BTreeMap::new();
        for e in &self.entries {
            *out.entry(e.rule.as_str()).or_insert(0) += e.count;
        }
        out
    }

    /// Removes baselined violations; returns how many were hidden.
    pub fn apply(&self, violations: &mut Vec<Violation>) -> usize {
        if violations.is_empty() {
            return 0;
        }
        let mut left = self.counts();
        let all = std::mem::take(violations);
        let hidden: Vec<bool> = all
            .iter()
            .map(|v| match left.get_mut(&key(v)) {
                Some(n) if *n > 0 => {
                    *n -= 1;
                    true
                }
                _ => false,
            })
            .collect();
        let before = all.len();
        *violations = all
            .into_iter()
            .zip(&hidden)
            .filter_map(|(v, hidden)| (!hidden).then_some(v))
            .collect();
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

    #[test]
    fn a_locked_rule_may_only_shrink_its_baseline() {
        let locked = BTreeMap::from([("no-any".to_string(), "acme".to_string())]);
        let two = Baseline::of(&[v("no-any", 1, "a"), v("no-any", 2, "b")]);
        let three = Baseline::of(&[
            v("no-any", 1, "a"),
            v("no-any", 2, "b"),
            v("no-any", 3, "c"),
        ]);
        let empty = Baseline::default();
        assert_eq!(three.grown(&two, &locked).len(), 1);
        assert!(two.grown(&three, &locked).is_empty());
        // The rule had no entries at the base: recording its legacy violations once is allowed.
        assert!(three.grown(&empty, &locked).is_empty());
        // Only locked rules are policed.
        assert!(three.grown(&two, &BTreeMap::new()).is_empty());
    }
}
