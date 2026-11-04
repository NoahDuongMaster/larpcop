//! Multi-taint lattice state: for each name, the set of rules (a bitmask) that
//! find it tainted. One walk of a scope then does the work of one walk per rule.

use std::cell::Cell;
use std::collections::{HashMap, HashSet};

/// Bitmask over the rules of a batch.
pub type RuleMask = u128;

/// Index of a rule in its batch.
pub type RuleId = u8;

/// Rules a batch holds: the bits of a [`RuleMask`].
pub const BATCH: usize = RuleMask::BITS as usize;

/// The bit of rule `id`.
pub fn bit(id: RuleId) -> RuleMask {
    1 << id
}

/// The rules in `mask`, in order.
pub fn rules_in(mut mask: RuleMask) -> impl Iterator<Item = RuleId> {
    std::iter::from_fn(move || {
        if mask == 0 {
            return None;
        }
        let first = mask.trailing_zeros();
        mask &= mask - 1;
        Some(first as RuleId)
    })
}

/// Names (and map entries, `m[k]`) mapped to the rules that find them tainted.
#[derive(Clone, Default, Debug)]
pub struct TaintEnv {
    vars: HashMap<String, RuleMask>,
    /// Was a map entry (a name ending in `]`) ever stored?
    has_entries: bool,
    /// The rules holding a map entry, worked out when asked and dropped when
    /// an entry changes.
    entries: Cell<Option<RuleMask>>,
}

impl TaintEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> RuleMask {
        self.vars.get(name).copied().unwrap_or(0)
    }

    pub fn or_mask(&mut self, name: &str, add: RuleMask) {
        if add == 0 {
            return;
        }
        self.changed(name);
        match self.vars.get_mut(name) {
            Some(mask) => *mask |= add,
            None => {
                self.vars.insert(name.to_string(), add);
            }
        }
    }

    pub fn mask_out(&mut self, name: &str, clear: RuleMask) {
        let Some(mask) = self.vars.get_mut(name) else {
            return;
        };
        *mask &= !clear;
        if *mask == 0 {
            self.vars.remove(name);
        }
        self.changed(name);
    }

    fn changed(&mut self, name: &str) {
        if name.ends_with(']') {
            self.has_entries = true;
            self.entries.set(None);
        }
    }

    /// The rules that hold some map entry.
    pub fn entry_rules(&self) -> RuleMask {
        if !self.has_entries {
            return 0;
        }
        if let Some(known) = self.entries.get() {
            return known;
        }
        let rules = self
            .vars
            .iter()
            .filter(|(name, _)| name.ends_with(']'))
            .fold(0, |acc, (_, mask)| acc | mask);
        self.entries.set(Some(rules));
        rules
    }

    /// The rules that hold an entry of map `base` (`base[…]`).
    pub fn entries_of(&self, base: &str) -> RuleMask {
        if !self.has_entries {
            return 0;
        }
        self.vars
            .iter()
            .filter(|(name, _)| {
                name.strip_prefix(base)
                    .is_some_and(|rest| rest.starts_with('['))
            })
            .fold(0, |acc, (_, mask)| acc | mask)
    }

    /// The rules that hold a name `text` spells (an entry `m[k]` is spelled
    /// through its map's name).
    pub fn spelled_in(&self, text: &str) -> RuleMask {
        self.vars
            .iter()
            .filter(|(name, _)| text.contains(name.split('[').next().unwrap_or(name)))
            .fold(0, |acc, (_, mask)| acc | mask)
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    /// Adds what `other` holds.
    pub fn absorb(&mut self, other: TaintEnv) {
        for (name, mask) in other.vars {
            self.changed(&name);
            *self.vars.entry(name).or_default() |= mask;
        }
    }

    /// The names a nested function may see: those it mentions and does not
    /// shadow with a parameter.
    pub fn visible_to(&self, text: &str, params: &HashSet<String>) -> TaintEnv {
        let mut out = TaintEnv::new();
        for (name, &mask) in &self.vars {
            if !params.contains(name) && text.contains(name.as_str()) {
                out.or_mask(name, mask);
            }
        }
        out
    }

    /// This environment with the given rules' names cleaned (`holds`: name →
    /// the rules a guard cleans it for).
    pub fn with_cleared(&self, holds: &HashMap<String, RuleMask>) -> TaintEnv {
        let mut next = self.clone();
        for (name, &clear) in holds {
            next.mask_out(name, clear);
        }
        next
    }

    /// The names rule `id` finds tainted.
    pub fn names_of(&self, id: RuleId) -> HashSet<String> {
        let rule = bit(id);
        self.vars
            .iter()
            .filter(|(_, mask)| **mask & rule != 0)
            .map(|(name, _)| name.clone())
            .collect()
    }

    pub fn iter(&self) -> impl Iterator<Item = (&String, &RuleMask)> {
        self.vars.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_tainted_for_the_rules_that_set_it() {
        let mut env = TaintEnv::new();
        assert_eq!(env.get("x"), 0);
        env.or_mask("x", 0b101);
        env.or_mask("x", 0b010);
        assert_eq!(env.get("x"), 0b111);
        env.or_mask("y", 0);
        assert!(env.names_of(1).contains("x"));
        assert!(!env.names_of(1).contains("y"));
    }

    #[test]
    fn masking_out_drops_a_name_no_rule_holds() {
        let mut env = TaintEnv::new();
        env.or_mask("v", 0b111);
        env.mask_out("v", 0b010);
        assert_eq!(env.get("v"), 0b101);
        env.mask_out("v", 0b101);
        assert!(env.is_empty());
    }

    #[test]
    fn entries_are_found_by_map_and_by_rule() {
        let mut env = TaintEnv::new();
        env.or_mask("m[a]", 0b01);
        env.or_mask("m[b]", 0b10);
        env.or_mask("plain", 0b100);
        assert_eq!(env.entries_of("m"), 0b11);
        assert_eq!(env.entries_of("mm"), 0);
        assert_eq!(env.entry_rules(), 0b11);
        env.mask_out("m[a]", 0b01);
        assert_eq!(env.entry_rules(), 0b10);
    }

    #[test]
    fn a_nested_function_sees_what_it_mentions_and_does_not_shadow() {
        let mut env = TaintEnv::new();
        env.or_mask("seen", 0b1);
        env.or_mask("unseen", 0b1);
        env.or_mask("shadowed", 0b1);
        let params: HashSet<String> = ["shadowed".to_string()].into();
        let nested = env.visible_to("seen + shadowed", &params);
        assert_eq!(nested.get("seen"), 0b1);
        assert_eq!(nested.get("unseen"), 0);
        assert_eq!(nested.get("shadowed"), 0);
    }

    #[test]
    fn absorb_and_clear_combine_rules() {
        let mut a = TaintEnv::new();
        a.or_mask("common", 0b01);
        let mut b = TaintEnv::new();
        b.or_mask("common", 0b10);
        b.or_mask("only_b", 0b10);
        a.absorb(b);
        assert_eq!(a.get("common"), 0b11);
        let cleared = a.with_cleared(&[("common".to_string(), 0b01)].into());
        assert_eq!(cleared.get("common"), 0b10);
        assert_eq!(a.get("common"), 0b11);
    }

    #[test]
    fn rules_in_lists_set_bits() {
        let ids: Vec<RuleId> = rules_in(0b1010_0001).collect();
        assert_eq!(ids, [0, 5, 7]);
    }
}
