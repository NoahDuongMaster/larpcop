//! The state of one scope's walk besides its tainted names: branches that
//! cleaned a name for a while, guards that clean names within a range, what
//! each `if` proved, where a name's taint came from.

use super::multi_mask::{RuleId, RuleMask, TaintEnv, bit, rules_in};
use super::origins::Origins;
use std::collections::{HashMap, HashSet};
use std::ops::Range;

/// An `if` every branch of which assigns `names` (joins.rs), and the names an
/// assignment inside tainted for some rules.
struct Joined<'e> {
    range: Range<usize>,
    names: &'e HashSet<String>,
    dirty: HashMap<String, RuleMask>,
}

pub struct Scope<'e> {
    pub env: TaintEnv,
    /// Do guards in the scope clean names, so that where a name's taint came
    /// from matters (origins.rs)?
    pub track: bool,
    /// Per group of rules with the same guards: the names each open guard
    /// range cleaned, to taint again where it ends.
    cleaned: Vec<Vec<Vec<(String, RuleMask)>>>,
    /// (end of the branch, name, rules): cleaned by a branch, tainted again
    /// where the branch ends.
    pub until: Vec<(usize, String, RuleMask)>,
    /// Names whose value starts safely (`url = reverse(…)`), per rule:
    /// appending to them cannot change where they lead.
    pub prefixed: HashMap<String, RuleMask>,
    /// (end of an `if`, names its untaken path proved safe, rules).
    pub settled: Vec<(usize, &'e HashSet<String>, RuleMask)>,
    joined: Vec<Joined<'e>>,
    /// Objects this scope builds (`req = new PayRequest()`).
    pub built: HashSet<String>,
    /// What each rule's tainted locals were built from, for checks made after.
    pub origins: HashMap<RuleId, Origins>,
}

impl<'e> Scope<'e> {
    pub fn new(env: TaintEnv, track: bool, groups: usize) -> Self {
        Self {
            env,
            track,
            cleaned: vec![Vec::new(); groups],
            until: Vec::new(),
            prefixed: HashMap::new(),
            settled: Vec::new(),
            joined: Vec::new(),
            built: HashSet::new(),
            origins: HashMap::new(),
        }
    }

    /// C `p = &data`: `p` and `data` are one place.
    pub fn spread(&mut self, groups: &[HashSet<String>]) {
        if groups.is_empty() || self.env.is_empty() {
            return;
        }
        for group in groups {
            let rules = group.iter().fold(0, |acc, n| acc | self.env.get(n));
            if rules != 0 {
                for n in group {
                    self.env.or_mask(n, rules);
                }
            }
        }
    }

    /// Taints again the names a branch cleaned, where it ends before `at`
    /// (unless a check proved them safe, or the branches all assign them).
    pub fn expire(&mut self, at: usize) {
        let Self {
            until,
            settled,
            joined,
            env,
            ..
        } = self;
        until.retain(|(end, name, rules)| {
            if *end > at {
                return true;
            }
            let mut kept = settled
                .iter()
                .filter(|(e, set, _)| e == end && set.contains(name))
                .fold(0, |acc, (_, _, r)| acc | r);
            for j in joined.iter() {
                if j.range.start < *end && *end <= j.range.end && j.names.contains(name) {
                    kept |= !j.dirty.get(name).copied().unwrap_or(0);
                }
            }
            env.or_mask(name, rules & !kept);
            false
        });
    }

    pub fn both(&mut self, range: Range<usize>, names: &'e HashSet<String>) {
        self.joined.push(Joined {
            range,
            names,
            dirty: HashMap::new(),
        });
    }

    /// An assignment at `at` tainted `name` for `rules`: inside an `if` whose
    /// branches all assign it, the name is no longer clean whatever the
    /// branches end with.
    pub fn mark(&mut self, at: usize, name: &str, rules: RuleMask) {
        for j in &mut self.joined {
            if j.range.contains(&at) && j.names.contains(name) {
                *j.dirty.entry(name.to_string()).or_default() |= rules;
            }
        }
    }

    /// The guarded names with the rules each is pinned for: `guarded`, and for
    /// rules whose tainted names were built from them alone, those too.
    fn pinned(&self, guarded: &HashSet<String>, rules: RuleMask) -> Vec<(String, RuleMask)> {
        let widening: Vec<RuleId> = rules_in(rules)
            .filter(|k| self.origins.get(k).is_some_and(Origins::derives))
            .collect();
        let plain = widening.iter().fold(rules, |acc, k| acc & !bit(*k));
        let mut out: Vec<(String, RuleMask)> = Vec::new();
        if plain != 0 {
            out.extend(guarded.iter().map(|g| (g.clone(), plain)));
        }
        for k in widening {
            let tainted = self.env.names_of(k);
            for name in self.origins[&k].widen(guarded, &tainted) {
                out.push((name, bit(k)));
            }
        }
        out
    }

    /// Names clean from here on.
    pub fn clean(&mut self, guarded: &HashSet<String>, rules: RuleMask) {
        for (name, rules) in self.pinned(guarded, rules) {
            self.env.mask_out(&name, rules);
        }
    }

    /// Names clean until the matching `restore` of the same `group`.
    pub fn enter(&mut self, group: usize, guarded: &HashSet<String>, rules: RuleMask) {
        let mut was = Vec::new();
        for (name, rules) in self.pinned(guarded, rules) {
            let taken = self.env.get(&name) & rules;
            if taken != 0 {
                self.env.mask_out(&name, taken);
                was.push((name, taken));
            }
        }
        self.cleaned[group].push(was);
    }

    pub fn restore(&mut self, group: usize) {
        for (name, rules) in self.cleaned[group].pop().unwrap_or_default() {
            self.env.or_mask(&name, rules);
        }
    }
}
