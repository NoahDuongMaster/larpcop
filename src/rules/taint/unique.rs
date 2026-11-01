//! `*.method`: a method name every known class defining it defines alike
//! stands for them all, for calls on objects of unknown class.

use super::summary::Summaries;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Adds `*.method` for every method name the known classes define alike
/// (one class, or several that behave the same: the same method seen as
/// `Class.m` and `module.Class.m`).
pub fn with_unique_methods(mut s: Summaries) -> Summaries {
    type Behaviour = (
        Vec<usize>,
        BTreeSet<usize>,
        bool,
        BTreeSet<usize>,
        BTreeSet<(usize, usize)>,
    );
    let mut seen: HashMap<String, (HashSet<Behaviour>, String)> = HashMap::new();
    for (key, summary) in s.iter().filter(|(_, v)| v.method) {
        if let Some((_, method)) = key.rsplit_once('.') {
            let behaviour = (
                summary.sinks.iter().map(|(i, _)| *i).collect(),
                summary.returns.clone(),
                summary.returns_source,
                summary.validates.clone(),
                summary.fills.clone(),
            );
            let entry = seen.entry(method.to_string()).or_default();
            entry.0.insert(behaviour);
            entry.1 = key.clone();
        }
    }
    for (method, (behaviours, key)) in seen {
        if behaviours.len() == 1
            && let Some(summary) = s.get(&key).cloned()
        {
            s.insert(format!("*.{method}"), summary);
        }
    }
    s
}
