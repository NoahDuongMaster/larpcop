//! Expression evaluation and call dispatch for the unified multi-taint lattice.

use super::fields::is_field;
use super::flow::CALLS;
use super::kotlin::Part;
use super::multi_mask::{RuleMask, TaintEnv};
use super::multi_walk::{MultiCtx, MultiReached};
use super::summary::args;
use super::NAMES;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashMap;

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    pub fn tainted_mask(&self, node: &Node<D>, env: &TaintEnv) -> RuleMask {
        if is_function(node) {
            return 0;
        }
        let r = node.range();
        let san_mask = self.hits.sanitizer_mask_at(&r);
        let src_mask = self.hits.source_mask_at(&r);
        let (kind, text) = (node.kind(), node.text());
        let mut mask: RuleMask = 0;

        if NAMES.contains(&kind.as_ref()) || is_field(node) {
            mask |= env.get(text.as_ref());
            if env.has_entries {
                mask |= env.entries_of(text.as_ref());
            }
            if self.bare_calls && kind == "identifier" {
                if let Some(s) = self.summaries.get(text.as_ref()) {
                    mask |= s.returns_source;
                }
            }
            if super::declared::scalar(node) {
                mask = 0;
            }
            if node.is_leaf() || mask != 0 {
                return ((mask | src_mask) & !san_mask) & self.active_rules;
            }
        }
        if env.has_entries {
            if let Some(entry) = super::entries::entry(node) {
                let base = entry.split('[').next().unwrap_or_default();
                return ((env.get(&entry) | env.get(base) | src_mask) & !san_mask)
                    & self.active_rules;
            }
        }
        if (self.numbers && kind == "binary_expression" && super::numeric::arithmetic(node))
            || super::numeric::counted(node)
        {
            return 0;
        }
        if matches!(
            kind.as_ref(),
            "ternary_expression" | "conditional_expression" | "conditional"
        ) {
            if let Some((cond, a, b)) = super::deadcode::sides(node) {
                let (mut holds_map, mut fails_map) = (HashMap::new(), HashMap::new());
                for (g_mask, check) in &self.hits.guard_checks {
                    let (holds, fails) = super::guards::safe(&cond, std::slice::from_ref(check));
                    for h in holds {
                        *holds_map.entry(h).or_default() |= *g_mask;
                    }
                    for f in fails {
                        *fails_map.entry(f).or_default() |= *g_mask;
                    }
                }
                let ma = self.tainted_mask(&a, &env.with_guards_cleared(&holds_map));
                let mb = self.tainted_mask(&b, &env.with_guards_cleared(&fails_map));
                return (((ma | mb) | src_mask) & !san_mask) & self.active_rules;
            }
        }
        if let Some(results) = super::choices::results(node) {
            mask = results
                .iter()
                .fold(0, |acc, res| acc | self.tainted_mask(res, env));
            return ((mask | src_mask) & !san_mask) & self.active_rules;
        }
        if CALLS.contains(&kind.as_ref()) {
            if let Some(s) = super::summary::called_name(node).and_then(|c| self.summaries.get(&c))
            {
                mask |= s.returns_source;
                let cargs = args(node);
                for (&idx, &ret_mask) in &s.returns {
                    if let Some(arg) = cargs.get(idx) {
                        mask |= self.tainted_mask(arg, env) & ret_mask;
                    }
                }
            }
            let cargs = args(node);
            if cargs.is_empty()
                && super::summary::called_name(node).is_some_and(|m| {
                    m.len() > 3 && m.starts_with("get") && m[3..].starts_with(char::is_uppercase)
                })
            {
                let rec = node
                    .part("function")
                    .and_then(|f| f.part("object"))
                    .or_else(|| node.part("object"))
                    .or_else(|| node.part("receiver"));
                if let Some(rec) = rec {
                    mask |= self.tainted_mask(&rec, env);
                }
            }
        }
        if mask == 0 {
            mask = node
                .children()
                .fold(0, |acc, c| acc | self.tainted_mask(&c, env));
        }
        ((mask | src_mask) & !san_mask) & self.active_rules
    }

    pub(super) fn run_call<F: FnMut(MultiReached<'a, D>)>(
        &self,
        node: &Node<'a, D>,
        env: &TaintEnv,
        on: &mut F,
    ) {
        let cargs = args(node);
        if let Some(called) = super::summary::called_name(node) {
            if let Some(s) = self.summaries.get(&called) {
                for (rule_id, single_s) in s.rules() {
                    let rule_mask = 1u128 << rule_id;
                    for (idx, into) in &single_s.calls {
                        if let Some(arg) = cargs.get(*idx) {
                            let mask = self.tainted_mask(arg, env) & rule_mask;
                            if mask != 0 {
                                on(MultiReached::Call {
                                    arg: arg.clone(),
                                    mask,
                                    into: into.clone(),
                                    rule_id,
                                });
                            }
                        }
                    }
                }
                for &(src_idx, fill_idx, fill_mask) in &s.fills {
                    if let (Some(sa), Some(fa)) = (cargs.get(src_idx), cargs.get(fill_idx)) {
                        let m = self.tainted_mask(sa, env) & fill_mask;
                        if m != 0 {
                            let fm = self.tainted_mask(fa, env) & fill_mask;
                            if fm != 0 {
                                on(MultiReached::Field(fa.clone(), fm));
                            }
                        }
                    }
                }
            }
        }
        for arg in cargs {
            let am = self.tainted_mask(&arg, env);
            if am != 0 {
                on(MultiReached::Sink {
                    arg: arg.clone(),
                    mask: am,
                    sink_mask: self.active_rules,
                    typed: Vec::new(),
                });
            }
        }
    }
}
