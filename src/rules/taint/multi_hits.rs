//! The sinks, sources, sanitizers and guards of all the rules of a batch,
//! aggregated by position so that one walk serves them all.

use super::events::{Hits, Key, Skeletons, key};
use super::flow::{Ctx, enclosing};
use super::guards::Check;
use super::multi_events::MultiEvents;
use super::multi_mask::{RuleId, RuleMask, bit};
use super::multi_spans::SpanMasks;
use ast_grep_core::{Doc, Node};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

/// A sink argument for the typed metavariables a rule matched with it.
pub type TypedNodes<'a, D> = Vec<(usize, Node<'a, D>)>;

/// A sink argument matched at `at` by the rules in `rules`.
pub struct MultiSink<'a, D: Doc> {
    pub at: usize,
    pub node: Node<'a, D>,
    pub rules: RuleMask,
    pub typed: Vec<(RuleId, TypedNodes<'a, D>)>,
}

/// Names a condition makes safe when it holds and when it fails, for the
/// rules it does so for.
#[derive(Default)]
pub struct CondGuards {
    pub holds: HashMap<String, RuleMask>,
    pub fails: HashMap<String, RuleMask>,
}

pub struct MultiHits<'a, D: Doc> {
    pub sinks: Vec<MultiSink<'a, D>>,
    /// Scope → its sinks (indexes into `sinks`).
    pub(super) by_scope: HashMap<Key, Vec<usize>>,
    pub sources: SpanMasks,
    pub sanitizers: SpanMasks,
    /// The rules of the batch.
    pub active: RuleMask,
    /// Rules with the same guard checks, with those checks.
    pub(super) guard_groups: Vec<(RuleMask, Vec<Check>)>,
    pub(super) skeletons: Skeletons<'a, D>,
    pub(super) events: RefCell<HashMap<Key, Rc<MultiEvents<'a, D>>>>,
    conditions: RefCell<HashMap<Key, Rc<CondGuards>>>,
}

impl<'a, D: Doc> MultiHits<'a, D> {
    /// The hits of rule `k` being `file_hits[k]`, prepared with `contexts[k]`.
    pub(super) fn from_prepared(
        contexts: &[&Ctx],
        file_hits: &[Hits<'a, D>],
        root: &Node<'a, D>,
        skeletons: Skeletons<'a, D>,
    ) -> Self {
        let mut at: HashMap<(usize, usize, usize), usize> = HashMap::new();
        let mut sinks: Vec<MultiSink<'a, D>> = Vec::new();
        for (k, hits) in file_hits.iter().enumerate() {
            let rule = k as RuleId;
            for (start, node, typed) in &hits.list {
                let range = node.range();
                let i = *at
                    .entry((*start, range.start, range.end))
                    .or_insert_with(|| {
                        sinks.push(MultiSink {
                            at: *start,
                            node: node.clone(),
                            rules: 0,
                            typed: Vec::new(),
                        });
                        sinks.len() - 1
                    });
                sinks[i].rules |= bit(rule);
                if !typed.is_empty() {
                    sinks[i].typed.push((rule, typed.clone()));
                }
            }
        }
        sinks.sort_by_key(|s| (s.at, s.node.range().start, s.node.range().end));
        let mut by_scope: HashMap<Key, Vec<usize>> = HashMap::new();
        for (i, sink) in sinks.iter().enumerate() {
            by_scope
                .entry(key(&enclosing(&sink.node, root)))
                .or_default()
                .push(i);
        }
        let mut guard_groups: Vec<(RuleMask, Vec<Check>)> = Vec::new();
        for (k, ctx) in contexts.iter().enumerate() {
            let rule = bit(k as RuleId);
            match guard_groups
                .iter_mut()
                .find(|(_, checks)| *checks == ctx.guards)
            {
                Some((mask, _)) => *mask |= rule,
                None => guard_groups.push((rule, ctx.guards.clone())),
            }
        }
        Self {
            sinks,
            by_scope,
            sources: SpanMasks::new(contexts.iter().map(|c| &c.sources)),
            sanitizers: SpanMasks::new(contexts.iter().map(|c| &c.sanitizers)),
            active: contexts
                .iter()
                .enumerate()
                .fold(0, |acc, (k, _)| acc | bit(k as RuleId)),
            guard_groups,
            skeletons,
            events: RefCell::default(),
            conditions: RefCell::default(),
        }
    }

    /// What the condition `cond` of a ternary makes safe, per rule.
    pub fn condition(&self, cond: &Node<D>) -> Rc<CondGuards> {
        let at = key(cond);
        if let Some(known) = self.conditions.borrow().get(&at) {
            return known.clone();
        }
        let mut out = CondGuards::default();
        for (rules, checks) in &self.guard_groups {
            let (holds, fails) = super::guards::safe(cond, checks);
            for name in holds {
                *out.holds.entry(name).or_default() |= rules;
            }
            for name in fails {
                *out.fails.entry(name).or_default() |= rules;
            }
        }
        let out = Rc::new(out);
        self.conditions.borrow_mut().insert(at, out.clone());
        out
    }
}

#[cfg(test)]
#[path = "multi_hits_tests.rs"]
mod tests;
