//! Expression evaluation and call stepping for the unified multi-taint lattice.

use super::fields::is_field;
use super::flow::CALLS;
use super::kotlin::Part;
use super::multi_mask::{RuleMask, TaintEnv};
use super::multi_walk::{MultiCtx, MultiReached, MultiSeen};
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
                let summary = self.summaries.get(text.as_ref());
                if let Some(s) = summary {
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
            let entry = super::entries::entry(node);
            if let Some(entry) = entry {
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
        let is_cond = matches!(
            kind.as_ref(),
            "ternary_expression" | "conditional_expression" | "conditional"
        );
        if is_cond {
            let sides = super::deadcode::sides(node);
            if let Some((cond, a, b)) = sides {
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

    pub(super) fn step_call(
        &self,
        call: &Node<'a, D>,
        env: &mut TaintEnv,
        on: &mut impl FnMut(MultiSeen<'a, D>),
    ) {
        if let (Some(val), Some(entry)) =
            (super::entries::stored(call), super::entries::entry(call))
        {
            let m = self.tainted_mask(&val, env);
            if m != 0 {
                env.or_mask(entry, m);
            } else {
                env.mask_out(&entry, self.active_rules);
            }
        } else if let Some(cnt) = super::containers::filled(call)
            .filter(|_| !(self.numbers && super::containers::writes(call)))
        {
            let m = args(call)
                .iter()
                .fold(0, |acc, a| acc | self.tainted_mask(a, env));
            if m != 0 {
                env.or_mask(cnt, m);
            }
        }
        if let Some(s) = super::summary::called_name(call).and_then(|c| self.summaries.get(&c)) {
            let cargs = args(call);
            for &(from, to, fill_mask) in &s.fills {
                if let (Some(fa), Some(ta)) = (cargs.get(from), cargs.get(to)) {
                    let is_name = NAMES.contains(&ta.kind().as_ref());
                    if is_name {
                        let m = self.tainted_mask(fa, env) & fill_mask;
                        if m != 0 {
                            env.or_mask(ta.text().as_ref(), m);
                        }
                    }
                }
            }
            for (&i, sinks) in &s.sinks {
                if let Some(arg) = cargs.get(i) {
                    let am = self.tainted_mask(arg, env);
                    for (rule_id, into) in sinks {
                        let bit = 1u128 << *rule_id;
                        if (am & bit & self.active_rules) != 0 {
                            on(MultiSeen::Reached(MultiReached::Call {
                                arg: arg.clone(),
                                mask: bit,
                                into: into.clone(),
                                rule_id: *rule_id,
                            }));
                        }
                    }
                }
            }
            for (key, into, rule_id) in &s.statics {
                let bit = 1u128 << *rule_id;
                if (self.active_rules & bit) != 0
                    && super::statics::held(call, key, &env.to_hash_set(bit))
                {
                    on(MultiSeen::Reached(MultiReached::Call {
                        arg: call.clone(),
                        mask: bit,
                        into: into.clone(),
                        rule_id: *rule_id,
                    }));
                }
            }
        }
    }
}
