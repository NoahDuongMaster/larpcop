#![allow(dead_code)]
//! Multi-Taint Lattice bitvector state and environment.

use std::collections::HashMap;

/// Bitmask over active taint rules (up to 128 active rules).
pub type RuleMask = u128;

/// Zero-based identifier of an active taint rule.
pub type RuleId = u8;

/// Sparse mapping from variable and map-entry names to rule bitmasks.
#[derive(Clone, Default, Debug, PartialEq, Eq)]
pub struct TaintEnv {
    pub vars: HashMap<String, RuleMask>,
    pub has_entries: bool,
}

impl TaintEnv {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get(&self, name: &str) -> RuleMask {
        self.vars.get(name).copied().unwrap_or(0)
    }

    pub fn set(&mut self, name: impl Into<String>, mask: RuleMask) {
        let key = name.into();
        if key.contains('[') {
            self.has_entries = true;
        }
        if mask == 0 {
            self.vars.remove(&key);
        } else {
            self.vars.insert(key, mask);
        }
    }

    pub fn or_mask(&mut self, name: impl Into<String>, add: RuleMask) {
        if add != 0 {
            let key = name.into();
            if key.contains('[') {
                self.has_entries = true;
            }
            *self.vars.entry(key).or_default() |= add;
        }
    }

    pub fn mask_out(&mut self, name: &str, clear: RuleMask) {
        if let Some(entry) = self.vars.get_mut(name) {
            *entry &= !clear;
            if *entry == 0 {
                self.vars.remove(name);
            }
        }
    }

    pub fn entries_of(&self, base: &str) -> RuleMask {
        if !self.has_entries {
            return 0;
        }
        let prefix = format!("{base}[");
        self.vars
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .fold(0, |acc, (_, v)| acc | *v)
    }

    pub fn join(&self, other: &Self) -> Self {
        let mut result = self.clone();
        result.has_entries |= other.has_entries;
        for (var, mask) in &other.vars {
            *result.vars.entry(var.clone()).or_default() |= *mask;
        }
        result
    }

    pub fn with_guards_cleared(&self, holds: &HashMap<String, RuleMask>) -> Self {
        let mut next = self.clone();
        for (var, clear_mask) in holds {
            next.mask_out(var, *clear_mask);
        }
        next
    }

    pub fn is_empty(&self) -> bool {
        self.vars.is_empty()
    }

    pub fn to_hash_set(&self, mask: RuleMask) -> std::collections::HashSet<String> {
        self.vars
            .iter()
            .filter(|(_, m)| (*m & mask) != 0)
            .map(|(k, _)| k.clone())
            .collect()
    }

    pub fn clear(&mut self) {
        self.vars.clear();
        self.has_entries = false;
    }

    pub fn rule_bit(rule_id: usize) -> RuleMask {
        if rule_id < 128 { 1u128 << rule_id } else { 0 }
    }

    pub fn contains_rule(mask: RuleMask, rule_id: usize) -> bool {
        (mask & Self::rule_bit(rule_id)) != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_and_get_default() {
        let env = TaintEnv::new();
        assert_eq!(env.get("x"), 0);
        assert!(!env.has_entries);
        assert!(env.is_empty());
    }

    #[test]
    fn test_set_and_remove_zero() {
        let mut env = TaintEnv::new();
        env.set("x", 0b101);
        assert_eq!(env.get("x"), 0b101);
        assert!(!env.has_entries);

        env.set("x", 0);
        assert_eq!(env.get("x"), 0);
        assert!(env.is_empty());
    }

    #[test]
    fn test_or_mask_and_entries() {
        let mut env = TaintEnv::new();
        env.or_mask("m[a]", 0b01);
        env.or_mask("m[b]", 0b10);
        assert!(env.has_entries);
        assert_eq!(env.get("m[a]"), 0b01);
        assert_eq!(env.get("m[b]"), 0b10);
        assert_eq!(env.entries_of("m"), 0b11);
        assert_eq!(env.entries_of("other"), 0);
    }

    #[test]
    fn test_mask_out() {
        let mut env = TaintEnv::new();
        env.set("v", 0b111);
        env.mask_out("v", 0b010);
        assert_eq!(env.get("v"), 0b101);

        env.mask_out("v", 0b101);
        assert_eq!(env.get("v"), 0);
        assert!(!env.vars.contains_key("v"));
    }

    #[test]
    fn test_join() {
        let mut a = TaintEnv::new();
        a.set("x", 0b01);
        a.set("common", 0b01);

        let mut b = TaintEnv::new();
        b.set("y", 0b10);
        b.set("common", 0b10);

        let joined = a.join(&b);
        assert_eq!(joined.get("x"), 0b01);
        assert_eq!(joined.get("y"), 0b10);
        assert_eq!(joined.get("common"), 0b11);
    }

    #[test]
    fn test_with_guards_cleared() {
        let mut env = TaintEnv::new();
        env.set("x", 0b11);
        env.set("y", 0b11);

        let mut guards = HashMap::new();
        guards.insert("x".to_string(), 0b01);
        guards.insert("y".to_string(), 0b11);

        let cleared = env.with_guards_cleared(&guards);
        assert_eq!(cleared.get("x"), 0b10);
        assert_eq!(cleared.get("y"), 0);
        // Original unchanged
        assert_eq!(env.get("x"), 0b11);
        assert_eq!(env.get("y"), 0b11);
    }

    #[test]
    fn test_rule_bit_and_contains() {
        assert_eq!(TaintEnv::rule_bit(0), 1);
        assert_eq!(TaintEnv::rule_bit(3), 8);
        assert_eq!(TaintEnv::rule_bit(128), 0);
        assert!(TaintEnv::contains_rule(0b1010, 1));
        assert!(!TaintEnv::contains_rule(0b1010, 0));
    }
}
