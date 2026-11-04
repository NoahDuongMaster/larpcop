//! What a batch's rules know of the functions a file calls, one entry per
//! callee name with the rules each fact holds for.

use super::lambdas::Condition;
use super::multi_mask::{RuleId, RuleMask, bit};
use super::summary::{Summaries, Summary};
use std::collections::{HashMap, HashSet};

/// The summaries of one callee name, over the rules that have one.
#[derive(Clone, Debug, Default)]
pub struct MultiSummary {
    /// The rules that have a summary under this name.
    pub present: RuleMask,
    pub returns_source: RuleMask,
    /// Parameter → the rules whose summary returns it.
    pub returns: HashMap<usize, RuleMask>,
    pub sinks: HashMap<usize, Vec<(RuleId, String)>>,
    pub fills: Vec<(usize, usize, RuleMask)>,
    pub statics: Vec<(String, String, RuleId)>,
    pub conditions: HashMap<usize, Vec<(RuleId, Condition)>>,
}

impl MultiSummary {
    /// The summary rule `rule` has.
    pub fn of_rule(rule: RuleId, s: &Summary) -> Self {
        let mut out = Self::default();
        out.add(rule, s);
        out
    }

    fn add(&mut self, rule: RuleId, s: &Summary) {
        let mask = bit(rule);
        self.present |= mask;
        if s.returns_source {
            self.returns_source |= mask;
        }
        for &param in &s.returns {
            *self.returns.entry(param).or_default() |= mask;
        }
        for (param, into) in &s.sinks {
            self.sinks
                .entry(*param)
                .or_default()
                .push((rule, into.clone()));
        }
        for &(from, to) in &s.fills {
            match self.fills.iter_mut().find(|f| f.0 == from && f.1 == to) {
                Some(known) => known.2 |= mask,
                None => self.fills.push((from, to, mask)),
            }
        }
        for (key, into) in &s.statics {
            self.statics.push((key.clone(), into.clone(), rule));
        }
        for (param, condition) in &s.conditions {
            self.conditions
                .entry(*param)
                .or_default()
                .push((rule, *condition));
        }
    }
}

/// The summaries of every rule of a batch, by callee name.
#[derive(Default)]
pub struct MultiSummaries {
    by_name: HashMap<String, MultiSummary>,
    /// Last segment of a name (`run` of `Store.run`) → the rules that have a
    /// summary under a name ending so.
    last: HashMap<String, RuleMask>,
    /// Names that other keys specialize (`f#1`, `f!0=true`).
    specialized: HashSet<String>,
    /// The rules some summary of which returns source data.
    sourcing: RuleMask,
}

impl MultiSummaries {
    /// Merges the summaries of the rules of a batch, rule `k` being the
    /// `k`th of `per_rule`.
    pub fn merge(per_rule: &[&Summaries]) -> Self {
        let mut out = Self::default();
        for (k, summaries) in per_rule.iter().enumerate() {
            let rule = k as RuleId;
            for (name, s) in summaries.iter() {
                out.by_name.entry(name.clone()).or_default().add(rule, s);
                if s.returns_source {
                    out.sourcing |= bit(rule);
                }
                *out.last
                    .entry(name.rsplit('.').next().unwrap_or(name).to_string())
                    .or_default() |= bit(rule);
                for (i, c) in name.char_indices() {
                    if c == '#' || c == '!' {
                        out.specialized.insert(name[..i].to_string());
                    }
                }
            }
        }
        out
    }

    pub fn get(&self, name: &str) -> Option<&MultiSummary> {
        self.by_name.get(name)
    }

    /// The rules that have a summary whose name ends in `last`.
    pub fn ending_in(&self, last: &str) -> RuleMask {
        self.last.get(last).copied().unwrap_or(0)
    }

    /// Does some rule have a variant of the summary of `name` for particular
    /// arguments?
    pub fn is_specialized(&self, name: &str) -> bool {
        self.specialized.contains(name)
    }

    /// The rules some known function of which returns source data.
    pub fn sourcing(&self) -> RuleMask {
        self.sourcing
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_merge_by_callee_name() {
        let mut s0 = Summary {
            returns_source: true,
            ..Default::default()
        };
        s0.returns.insert(0);
        s0.sinks.push((1, "sink0".to_string()));
        s0.fills.insert((0, 1));

        let mut s1 = Summary::default();
        s1.returns.insert(0);
        s1.returns.insert(2);
        s1.sinks.push((1, "sink1".to_string()));
        s1.fills.insert((0, 1));

        let mut map0 = Summaries::new();
        map0.insert("fn1".to_string(), s0);
        let mut map1 = Summaries::new();
        map1.insert("Cls.fn1".to_string(), s1);
        map1.insert("fn1#0".to_string(), Summary::default());

        let merged = MultiSummaries::merge(&[&map0, &map1]);
        let fn1 = merged.get("fn1").unwrap();
        assert_eq!(fn1.present, 0b01);
        assert_eq!(fn1.returns_source, 0b01);
        let other = merged.get("Cls.fn1").unwrap();
        assert_eq!(other.present, 0b10);
        assert_eq!(other.returns.get(&2).copied(), Some(0b10));
        assert_eq!(other.sinks.get(&1).unwrap(), &[(1, "sink1".to_string())]);
        assert_eq!(merged.ending_in("fn1"), 0b11);
        assert_eq!(merged.sourcing(), 0b01);
        assert!(merged.is_specialized("fn1"));
        assert!(!merged.is_specialized("Cls.fn1"));
    }

    #[test]
    fn a_fill_two_rules_share_is_kept_once() {
        let mut s = Summary::default();
        s.fills.insert((0, 1));
        let mut summaries = Summaries::new();
        summaries.insert("f".to_string(), s);
        let merged = MultiSummaries::merge(&[&summaries, &summaries]);
        assert_eq!(merged.get("f").unwrap().fills, [(0, 1, 0b11)]);
    }
}
