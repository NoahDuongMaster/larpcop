//! Functions nested in a scope (callbacks, closures): walked after it with
//! the tainted names they see, plus what they write back to the scope.

use super::flow::Ctx;
use super::multi_hits::MultiHits;
use super::multi_mask::{RuleMask, TaintEnv, bit};
use super::multi_scope::Scope;
use super::multi_summary::MultiSummaries;
use super::multi_walk::{MultiCtx, MultiReached, MultiSeen};
use crate::rules::taint::TaintRule;
use ast_grep_core::{Doc, Node};
use std::cell::RefCell;

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    /// The batch: rule `k` being `rules[k]`, prepared as `ctxs[k]`.
    pub fn new(
        hits: &'h MultiHits<'a, D>,
        summaries: &'h MultiSummaries,
        ctxs: &'h [&'h Ctx],
        rules: &[&TaintRule],
    ) -> Self {
        let among = |holds: &dyn Fn(usize) -> bool| {
            (0..ctxs.len())
                .filter(|k| holds(*k))
                .fold(0, |acc: RuleMask, k| acc | bit(k as u8))
        };
        Self {
            hits,
            summaries,
            ctxs,
            bare_calls: ctxs.iter().any(|c| c.bare_calls),
            numbers: ctxs.iter().any(|c| c.numbers),
            responds: among(&|k| rules[k].responds.is_some()),
            safe_prefix: among(&|k| ctxs[k].safe_prefix.is_some()),
            writes_clean: among(&|k| ctxs[k].writes_clean),
            writing: among(&|k| !ctxs[k].writes.is_empty()),
            resolved: RefCell::default(),
        }
    }

    /// Walks `scope` from `env`, then each function nested in it with the
    /// tainted names it sees plus `own(nested)`, reporting what tainted data
    /// reaches. `nested`: `scope` is itself a nested function.
    pub fn run(
        &self,
        scope: &Node<'a, D>,
        env: TaintEnv,
        own: &impl Fn(&Node<'a, D>) -> TaintEnv,
        nested: bool,
        on: &mut dyn FnMut(MultiReached<'a, D>),
    ) {
        let mut inside = Vec::new();
        self.run_scope(scope, env, nested, &mut |s| match s {
            MultiSeen::Reached(r) => on(r),
            MultiSeen::Nested(f, seen) => inside.push((f, seen)),
        });
        for (f, mut env) in inside {
            env.absorb(own(&f));
            // A nested function's `return` is not this scope's.
            self.run(&f, env, own, true, &mut |reached| match reached {
                MultiReached::Return(value, mask) => on(MultiReached::Responds {
                    f: f.clone(),
                    value,
                    mask,
                }),
                other => on(other),
            });
        }
    }

    /// A function nested at this point of `scope`: it will be walked with
    /// the tainted names it mentions, and what it writes to the names
    /// around it is tainted from here on (`rows.forEach(r -> out.append(r))`).
    pub(super) fn nested(
        &self,
        scope: &Node<'a, D>,
        f: &Node<'a, D>,
        st: &mut Scope<'_>,
        on: &mut dyn FnMut(MultiSeen<'a, D>),
    ) {
        let params = super::summary::param_names(f);
        let mut seen = st.env.visible_to(&f.text(), &params);
        // The element a callback is run on.
        if let Some((receiver, param)) = super::callbacks::element_of(f) {
            let tainted = self.tainted_mask(&receiver, &st.env, self.hits.active);
            seen.or_mask(&param, tainted);
        }
        if !seen.is_empty() {
            let end = self.run_scope(f, seen.clone(), false, &mut |_| {});
            let outer = scope.text();
            let base = scope.range().start;
            let (from, to) = (f.range().start - base, f.range().end - base);
            let around = |n: &str| outer[..from].contains(n) || outer[to..].contains(n);
            for (name, &mask) in end.iter() {
                let written = mask & !seen.get(name);
                if written != 0 && !params.contains(name) && around(name) {
                    st.env.or_mask(name, written);
                }
            }
        }
        on(MultiSeen::Nested(f.clone(), seen));
    }
}
