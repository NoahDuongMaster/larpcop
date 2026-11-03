#![allow(dead_code)]
//! Multi-Taint Lattice aggregated hits across active rules.

use super::TaintRule;
use super::events::{Hits, Skeletons};
use super::flow::Ctx;
use super::guards::Check;
use super::multi_mask::{RuleId, RuleMask};
use ast_grep_core::{Doc, Node};
use std::collections::HashMap;
use std::fmt;
use std::ops::Range;

/// An aggregated multi-rule hit at an AST node.
#[derive(Clone)]
pub struct MultiHit<'a, D: Doc> {
    pub node: Node<'a, D>,
    pub sink_mask: RuleMask,
    pub sanitizer_mask: RuleMask,
    pub guard_checks: Vec<(RuleMask, Check)>,
}

impl<'a, D: Doc> fmt::Debug for MultiHit<'a, D> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MultiHit")
            .field("range", &self.node.range())
            .field("sink_mask", &self.sink_mask)
            .finish()
    }
}

impl<'a, D: Doc> MultiHit<'a, D> {
    pub fn new(
        node: Node<'a, D>,
        sink_mask: RuleMask,
        sanitizer_mask: RuleMask,
        guard_checks: Vec<(RuleMask, Check)>,
    ) -> Self {
        Self {
            node,
            sink_mask,
            sanitizer_mask,
            guard_checks,
        }
    }
    pub fn at(&self) -> usize {
        self.node.range().start
    }
}

pub type TypedNode<'a, D> = (usize, Node<'a, D>);
pub type TypedRuleArg<'a, D> = (RuleId, Vec<TypedNode<'a, D>>);
pub type TypedMap<'a, D> = HashMap<(usize, usize), Vec<TypedRuleArg<'a, D>>>;
type SpanEntry<'a, D> = (Node<'a, D>, RuleMask, RuleMask, Vec<(RuleMask, Check)>);

/// Aggregated hits, per-span masks, and guard checks across active taint rules.
pub struct MultiHits<'a, D: Doc> {
    pub list: Vec<MultiHit<'a, D>>,
    pub sinks_by_span: HashMap<Range<usize>, RuleMask>,
    pub sanitizers_by_span: HashMap<Range<usize>, RuleMask>,
    pub sources_by_span: HashMap<Range<usize>, RuleMask>,
    pub guard_checks: Vec<(RuleMask, Check)>,
    pub by_scope: HashMap<(usize, usize), Vec<usize>>,
    pub skeletons: Skeletons<'a, D>,
    pub typed: TypedMap<'a, D>,
}

impl<'a, D: Doc> MultiHits<'a, D> {
    pub fn empty() -> Self {
        Self {
            list: Vec::new(),
            sinks_by_span: HashMap::new(),
            sanitizers_by_span: HashMap::new(),
            sources_by_span: HashMap::new(),
            guard_checks: Vec::new(),
            by_scope: HashMap::new(),
            skeletons: Default::default(),
            typed: HashMap::new(),
        }
    }

    pub fn from_rules(rules: &[&TaintRule], file_hits: &[Hits<'a, D>]) -> Self {
        Self::from_prepared(rules, &[], file_hits)
    }

    pub(super) fn from_prepared(
        rules: &[&TaintRule],
        contexts: &[&Ctx],
        file_hits: &[Hits<'a, D>],
    ) -> Self {
        let mut by_span: HashMap<(usize, usize), SpanEntry<'a, D>> = HashMap::new();
        let mut sinks_by_span: HashMap<Range<usize>, RuleMask> = HashMap::new();
        let mut sanitizers_by_span: HashMap<Range<usize>, RuleMask> = HashMap::new();
        let mut sources_by_span: HashMap<Range<usize>, RuleMask> = HashMap::new();
        let mut guard_checks: Vec<(RuleMask, Check)> = Vec::new();
        let mut typed: TypedMap<'a, D> = HashMap::new();

        for (rule_idx, ctx) in contexts.iter().enumerate() {
            if rule_idx >= 128 {
                continue;
            }
            let rule_mask = 1u128 << rule_idx;
            for s in ctx.sources.spans() {
                *sources_by_span.entry(s.clone()).or_default() |= rule_mask;
            }
            for s in ctx.sanitizers.spans() {
                *sanitizers_by_span.entry(s.clone()).or_default() |= rule_mask;
            }
            for g in &ctx.guards {
                guard_checks.push((rule_mask, g.clone()));
            }
        }

        for (rule_idx, hits) in file_hits.iter().enumerate() {
            if rule_idx >= 128 {
                continue;
            }
            let rule_mask = 1u128 << rule_idx;
            let rule = rules.get(rule_idx).copied();
            for (_at, node, node_typed) in &hits.list {
                let range = node.range();
                let key = (range.start, range.end);
                let entry = by_span
                    .entry(key)
                    .or_insert_with(|| (node.clone(), 0, 0, Vec::new()));
                entry.1 |= rule_mask;
                if let Some(re) = rule.and_then(|r| r.sanitizer_names.as_ref()) {
                    if re.is_match(node.text().as_ref()) {
                        entry.2 |= rule_mask;
                    }
                }
                *sinks_by_span.entry(range.clone()).or_default() |= rule_mask;
                if entry.2 != 0 {
                    *sanitizers_by_span.entry(range.clone()).or_default() |= entry.2;
                }
                if !node_typed.is_empty() {
                    typed
                        .entry(key)
                        .or_default()
                        .push((rule_idx as RuleId, node_typed.clone()));
                }
            }
        }

        let mut sorted_keys: Vec<(usize, usize)> = by_span.keys().copied().collect();
        sorted_keys.sort_by_key(|&(start, end)| (start, end));
        let mut list = Vec::with_capacity(sorted_keys.len());
        let mut scope_map: HashMap<(usize, usize), Vec<usize>> = HashMap::new();

        for (idx, key) in sorted_keys.iter().enumerate() {
            let (node, sink_mask, sanitizer_mask, g_checks) = by_span.remove(key).unwrap();
            let scope_key = node
                .ancestors()
                .find(|a| crate::rules::complexity::is_function(a))
                .map(|a| (a.range().start, a.range().end))
                .unwrap_or_else(|| {
                    let top = node.ancestors().last().unwrap_or_else(|| node.clone());
                    (top.range().start, top.range().end)
                });
            scope_map.entry(scope_key).or_default().push(idx);
            list.push(MultiHit {
                node,
                sink_mask,
                sanitizer_mask,
                guard_checks: g_checks,
            });
        }

        let skeletons = file_hits
            .first()
            .map(|h| h.skeletons.clone())
            .unwrap_or_default();
        Self {
            list,
            sinks_by_span,
            sanitizers_by_span,
            sources_by_span,
            guard_checks,
            by_scope: scope_map,
            skeletons,
            typed,
        }
    }

    pub fn sink_mask_at(&self, range: &Range<usize>) -> RuleMask {
        self.sinks_by_span.get(range).copied().unwrap_or(0)
    }

    pub fn sanitizer_mask_at(&self, range: &Range<usize>) -> RuleMask {
        let mut mask = self.sanitizers_by_span.get(range).copied().unwrap_or(0);
        for (s, m) in &self.sanitizers_by_span {
            if s.start <= range.start && range.end <= s.end {
                mask |= *m;
            }
        }
        mask
    }

    pub fn source_mask_at(&self, range: &Range<usize>) -> RuleMask {
        let mut mask = self.sources_by_span.get(range).copied().unwrap_or(0);
        for (s, m) in &self.sources_by_span {
            if s.start <= range.start && range.end <= s.end {
                mask |= *m;
            }
        }
        mask
    }

    pub fn hits(&self) -> &[MultiHit<'a, D>] {
        &self.list
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn add_source_span(&mut self, span: Range<usize>, mask: RuleMask) {
        *self.sources_by_span.entry(span).or_default() |= mask;
    }

    pub fn add_sanitizer_span(&mut self, span: Range<usize>, mask: RuleMask) {
        *self.sanitizers_by_span.entry(span).or_default() |= mask;
    }

    pub fn add_sink_span(&mut self, span: Range<usize>, mask: RuleMask) {
        *self.sinks_by_span.entry(span).or_default() |= mask;
    }

    pub fn add_guard_check(&mut self, mask: RuleMask, check: Check) {
        self.guard_checks.push((mask, check));
    }

    pub fn guards_for(&self, range: &Range<usize>) -> Vec<(RuleMask, Check)> {
        self.guard_checks
            .iter()
            .filter(|(_, (r, ..))| r == range || (range.start <= r.start && r.end <= range.end))
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ast_grep_language::{LanguageExt, SupportLang};

    #[test]
    fn test_multi_hits_empty() {
        let grep = SupportLang::JavaScript.ast_grep("function foo() {}");
        let root = grep.root();
        let hits0 = Hits::new(vec![], &root, Default::default());
        let empty = MultiHits::from_rules(&[], &[hits0]);
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert_eq!(empty.sink_mask_at(&(0..10)), 0);
    }

    #[test]
    fn test_multi_hits_from_rules_aggregates_masks() {
        let grep = SupportLang::JavaScript.ast_grep("function foo() { sink1(a); sink2(b); }");
        let root = grep.root();
        let calls: Vec<_> = root
            .dfs()
            .filter(|n| n.kind() == "call_expression")
            .collect();
        assert_eq!(calls.len(), 2);
        let (na, nb) = (calls[0].clone(), calls[1].clone());
        let hits0 = Hits::new(
            vec![(na.range().start, na.clone(), Vec::new())],
            &root,
            Default::default(),
        );
        let hits1 = Hits::new(
            vec![
                (na.range().start, na.clone(), Vec::new()),
                (nb.range().start, nb.clone(), Vec::new()),
            ],
            &root,
            Default::default(),
        );
        let multi = MultiHits::from_rules(&[], &[hits0, hits1]);
        assert_eq!(multi.len(), 2);
        assert_eq!(multi.hits()[0].sink_mask, 0b11);
        assert_eq!(multi.hits()[1].sink_mask, 0b10);
        assert_eq!(multi.sink_mask_at(&na.range()), 0b11);
        assert_eq!(multi.sink_mask_at(&nb.range()), 0b10);
    }

    #[test]
    fn test_multi_hits_spans_and_guards() {
        let grep = SupportLang::JavaScript.ast_grep("function foo() {}");
        let root = grep.root();
        let hits0 = Hits::new(vec![], &root, Default::default());
        let mut multi = MultiHits::from_rules(&[], &[hits0]);
        multi.add_source_span(10..20, 0b01);
        multi.add_sanitizer_span(15..25, 0b10);
        multi.add_sink_span(20..30, 0b11);
        multi.add_guard_check(0b01, (12..18, true, 1));

        assert_eq!(multi.source_mask_at(&(10..20)), 0b01);
        assert_eq!(multi.sanitizer_mask_at(&(15..25)), 0b10);
        assert_eq!(multi.sink_mask_at(&(20..30)), 0b11);

        let guards = multi.guards_for(&(10..30));
        assert_eq!(guards.len(), 1);
        assert_eq!(guards[0].0, 0b01);
        assert_eq!(guards[0].1.0, 12..18);
    }
}
