//! `*.method`: a method name every known class defining it defines alike
//! stands for them all, for calls on objects of unknown class.
//! `Super.method`: an interface's or base class's method stands for every
//! known class extending or implementing it, joined (calls on a name
//! declared with that type: `Store s; s.save(x)`).

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
    implemented(&mut s);
    for (method, (behaviours, key)) in seen {
        if behaviours.len() == 1
            && let Some(summary) = s.get(&key).cloned()
        {
            s.insert(format!("*.{method}"), summary);
        }
    }
    s
}

/// Adds `Super.method` for the methods of every class with supertypes: what
/// any implementation does (a sink, a returned parameter), and validation
/// only when all of them validate.
fn implemented(s: &mut Summaries) {
    let mut joined: HashMap<String, super::summary::Summary> = HashMap::new();
    for (key, summary) in s.iter().filter(|(_, v)| v.method && !v.supers.is_empty()) {
        let Some((_, method)) = key.rsplit_once('.') else {
            continue;
        };
        for sup in &summary.supers {
            let k = format!("{sup}.{method}");
            match joined.get_mut(&k) {
                None => {
                    let mut first = summary.clone();
                    first.supers = Vec::new();
                    joined.insert(k, first);
                }
                Some(j) => {
                    for sink in &summary.sinks {
                        if !j.sinks.iter().any(|(i, _)| *i == sink.0) {
                            j.sinks.push(sink.clone());
                        }
                    }
                    j.sinks.sort();
                    j.returns.extend(summary.returns.iter().copied());
                    j.returns_source |= summary.returns_source;
                    j.validates = j
                        .validates
                        .intersection(&summary.validates)
                        .copied()
                        .collect();
                    j.fills.extend(summary.fills.iter().copied());
                    if j.conditions != summary.conditions {
                        j.conditions.clear();
                    }
                }
            }
        }
    }
    for (k, v) in joined {
        // A concrete method of the base class itself is what runs unless
        // overridden: keep it, with what overrides add.
        match s.get_mut(&k) {
            Some(own) => {
                for sink in v.sinks {
                    if !own.sinks.iter().any(|(i, _)| *i == sink.0) {
                        own.sinks.push(sink);
                    }
                }
                own.returns.extend(v.returns);
                own.returns_source |= v.returns_source;
                own.fills.extend(v.fills);
            }
            None => {
                s.insert(k, v);
            }
        }
    }
}
