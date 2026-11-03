//! Interprocedural function summaries merged across multiple active taint rules.

use super::multi_mask::{RuleId, RuleMask};
use super::summary::Summaries;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

#[derive(Clone, Debug, Default)]
pub struct MultiSummary {
    pub returns_source: RuleMask,
    pub returns: HashMap<usize, RuleMask>,
    pub sinks: HashMap<usize, Vec<(RuleId, String)>>,
    pub fills: Vec<(usize, usize, RuleMask)>,
    pub validates: HashMap<usize, RuleMask>,
    pub statics: Vec<(String, String, RuleId)>,
}

#[derive(Clone, Debug, Default)]
pub struct MultiSummaries(pub HashMap<String, MultiSummary>);

impl Deref for MultiSummaries {
    type Target = HashMap<String, MultiSummary>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for MultiSummaries {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl MultiSummaries {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self(HashMap::new())
    }

    pub fn merge(summaries_per_rule: &[(RuleMask, &Summaries)]) -> Self {
        let mut map: HashMap<String, MultiSummary> = HashMap::new();
        for &(mask, summaries) in summaries_per_rule {
            let rule_id = mask.trailing_zeros() as u8;
            for (callee, s) in summaries.iter() {
                let entry = map.entry(callee.clone()).or_default();
                if s.returns_source {
                    entry.returns_source |= mask;
                }
                for &ret_idx in &s.returns {
                    *entry.returns.entry(ret_idx).or_default() |= mask;
                }
                for &(param_idx, ref into) in &s.sinks {
                    entry
                        .sinks
                        .entry(param_idx)
                        .or_default()
                        .push((rule_id, into.clone()));
                }
                for &(from, to) in &s.fills {
                    if let Some(existing) =
                        entry.fills.iter_mut().find(|f| f.0 == from && f.1 == to)
                    {
                        existing.2 |= mask;
                    } else {
                        entry.fills.push((from, to, mask));
                    }
                }
                for &val_idx in &s.validates {
                    *entry.validates.entry(val_idx).or_default() |= mask;
                }
                for (key, into) in &s.statics {
                    entry.statics.push((key.clone(), into.clone(), rule_id));
                }
            }
        }
        Self(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rules::taint::summary::Summary;

    #[test]
    fn test_merge_summaries() {
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
        map1.insert("fn1".to_string(), s1);

        let merged = MultiSummaries::merge(&[(1u128 << 0, &map0), (1u128 << 1, &map1)]);
        let fn1 = merged.get("fn1").unwrap();
        assert_eq!(fn1.returns_source, 1u128 << 0);
        assert_eq!(fn1.returns.get(&0).copied(), Some(0b11));
        assert_eq!(fn1.returns.get(&2).copied(), Some(0b10));
        assert_eq!(fn1.sinks.get(&1).unwrap().len(), 2);
        assert_eq!(fn1.fills.len(), 1);
        assert_eq!(fn1.fills[0], (0, 1, 0b11));
    }
}
