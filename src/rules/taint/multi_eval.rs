//! Which rules find a node tainted: `Ctx::tainted` (flow.rs) for all the rules
//! of a batch at once, each branch of it narrowing the rules still to judge.

use super::NAMES;
use super::fields::is_field;
use super::flow::CALLS;
use super::kotlin::Part;
use super::multi_mask::{RuleMask, TaintEnv, bit, rules_in};
use super::multi_walk::MultiCtx;
use super::summary::{args, called_name};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    /// Of `rules`, those that find `node` tainted given `env`.
    pub fn tainted_mask(&self, node: &Node<D>, env: &TaintEnv, rules: RuleMask) -> RuleMask {
        // A function value is code, not data; what it captures is followed
        // when its body is walked.
        if rules == 0 || is_function(node) {
            return 0;
        }
        let r = node.range();
        let rules = rules & !self.hits.sanitizers.covers(&r, rules);
        let covered = self.hits.sources.covers(&r, rules);
        let rules = rules & !covered;
        if rules == 0 {
            return covered;
        }
        // A bare name token: only the name's own entry, a map read whole and
        // a bare call can decide it.
        if node.is_leaf() && NAMES.contains(&node.kind().as_ref()) {
            return covered | self.name_mask(node, env, rules);
        }
        covered | self.expression_mask(node, env, rules)
    }

    fn name_mask(&self, node: &Node<D>, env: &TaintEnv, rules: RuleMask) -> RuleMask {
        let text = node.text();
        let own = env.get(&text) & rules;
        // `int n = rs.getInt(1)`: a number holds no injected text.
        let mut found = if own != 0 && !super::declared::scalar(node) {
            own
        } else {
            0
        };
        let rest = rules & !own;
        if rest == 0 {
            return found;
        }
        // A map read whole holds its tainted entries.
        let mapped = env.entry_rules() & rest;
        if mapped != 0 {
            found |= env.entries_of(&text) & mapped;
        }
        // Ruby: `custom_fields` alone may be a call of a method returning
        // request data.
        if self.bare_calls
            && node.kind() == "identifier"
            && let Some(s) = self.summaries.get(&text)
        {
            found |= s.returns_source & rest;
        }
        found
    }

    fn expression_mask(&self, node: &Node<D>, env: &TaintEnv, mut rules: RuleMask) -> RuleMask {
        let r = node.range();
        let (kind, text) = (node.kind(), node.text());
        let overlapping = self.hits.sources.overlaps(&r, rules);
        let entry_rules = env.entry_rules() & rules;
        let mut found: RuleMask = 0;
        // `m['k']`, `m.get("k")`: that entry, or the whole map.
        let direct = entry_rules & !overlapping;
        if direct != 0
            && let Some(entry) = super::entries::entry(node)
        {
            let base = entry.split('[').next().unwrap_or_default();
            let held = super::entries::read_as(&entry)
                .iter()
                .fold(env.get(base), |acc, e| acc | env.get(e));
            found |= held & direct;
            rules &= !direct;
        }
        // A map read whole holds its tainted entries.
        if NAMES.contains(&kind.as_ref()) && entry_rules & rules != 0 {
            let whole = env.entries_of(&text) & entry_rules & rules;
            found |= whole;
            rules &= !whole;
        }
        // Nothing below can be tainted: no source in it, no tainted name
        // spelled in it, no call that could return source data.
        let calls = text.contains('(') || self.bare_calls;
        let sourcing = if calls { self.summaries.sourcing() } else { 0 };
        rules &= overlapping | env.spelled_in(&text) | sourcing;
        if rules == 0 {
            return found;
        }
        if NAMES.contains(&kind.as_ref()) || is_field(node) {
            let own = env.get(&text) & rules;
            if own != 0 {
                if !super::declared::scalar(node) {
                    found |= own;
                }
                rules &= !own;
            }
        }
        // `len(keys)`, `buf.size()`: a count, whatever was counted.
        if (self.numbers && kind == "binary_expression" && super::numeric::arithmetic(node))
            || super::numeric::counted(node)
        {
            return found;
        }
        // `c ? a : b` is `a` or `b`, never `c`; a guard in `c` cleans the
        // side it protects (`isLocal(u) ? u : "/"`).
        if matches!(
            kind.as_ref(),
            "ternary_expression" | "conditional_expression" | "conditional"
        ) && let Some((cond, a, b)) = super::deadcode::sides(node)
        {
            let guards = self.hits.condition(&cond);
            let (held, failed);
            let on_a = if guards.holds.is_empty() {
                env
            } else {
                held = env.with_cleared(&guards.holds);
                &held
            };
            let on_b = if guards.fails.is_empty() {
                env
            } else {
                failed = env.with_cleared(&guards.fails);
                &failed
            };
            let first = self.tainted_mask(&a, on_a, rules);
            return found | first | self.tainted_mask(&b, on_b, rules & !first);
        }
        // `case x when "a" then "/a"`: a branch's result, not the subject.
        if let Some(results) = super::choices::results(node) {
            return found | self.any_of(results.iter(), env, rules);
        }
        // Ruby: `custom_fields` alone may be a call of a method returning
        // request data.
        if self.bare_calls
            && kind == "identifier"
            && let Some(s) = self.summaries.get(&text)
        {
            found |= s.returns_source & s.present & rules;
            rules &= !s.present;
            if rules == 0 {
                return found;
            }
        }
        // A mapped collection carries what its callback returns.
        if super::iteration::is_mapping(node) {
            for k in rules_in(rules) {
                let names = env.names_of(k);
                if let Some(tainted) = super::iteration::mapped(self.ctxs[k as usize], node, &names)
                {
                    found |= bit(k) * tainted as RuleMask;
                    rules &= !bit(k);
                }
            }
            if rules == 0 {
                return found;
            }
        }
        if CALLS.contains(&kind.as_ref()) {
            let called = self.called(node, env, rules);
            found |= called.0;
            rules &= !called.1;
            if rules == 0 {
                return found;
            }
            // `sprintf("… id=%d", $t)`: what `%d` writes is a number.
            if let Some(numbers) = super::numeric::formatted(node) {
                let given = args(node);
                let given = given.iter().filter(|a| !numbers.contains(&a.range()));
                return found | self.any_of(given, env, rules);
            }
        }
        found | self.any_of(node.children(), env, rules)
    }

    /// Of `rules`, those that find one of `nodes` tainted.
    fn any_of<'n>(
        &self,
        nodes: impl IntoIterator<Item = impl std::borrow::Borrow<Node<'n, D>>>,
        env: &TaintEnv,
        rules: RuleMask,
    ) -> RuleMask {
        let mut found = 0;
        for n in nodes {
            found |= self.tainted_mask(n.borrow(), env, rules & !found);
            if found == rules {
                break;
            }
        }
        found
    }

    /// A call of a function we have a summary for: only what it really
    /// passes through. The rules that find it tainted, and the rules that
    /// have such a summary.
    fn called(&self, call: &Node<D>, env: &TaintEnv, rules: RuleMask) -> (RuleMask, RuleMask) {
        let resolved = self.resolve(call);
        let (mut found, mut known) = (0, 0);
        if resolved.is_empty() {
            return (found, known);
        }
        let cargs = args(call);
        // `obj.get(k)` matched to the project's only `get` by name is a
        // guess: request data it is called on (`request.GET.get('q')`) still
        // flows out. `order.getNote()` on an order holding request data: a
        // getter reads the object's state, which its summary does not follow.
        let getter = cargs.is_empty()
            && called_name(call).is_some_and(|m| {
                m.len() > 3 && m.starts_with("get") && m[3..].starts_with(char::is_uppercase)
            });
        for res in resolved.iter() {
            let here = res.rules & rules;
            if here == 0 {
                continue;
            }
            known |= here;
            let mut passed = res.summary.returns_source & here;
            for (&i, &by) in &res.summary.returns {
                if let Some(a) = cargs.get(i) {
                    passed |= self.tainted_mask(a, env, by & here & !passed);
                }
            }
            if (res.guessed || getter) && here & !passed != 0 {
                let receiver = call
                    .part("function")
                    .and_then(|f| f.part("object"))
                    .or_else(|| call.part("object"))
                    .or_else(|| call.part("receiver"));
                if let Some(receiver) = receiver {
                    passed |= self.tainted_mask(&receiver, env, here & !passed);
                }
            }
            found |= passed;
        }
        (found, known)
    }
}
