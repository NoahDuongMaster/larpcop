//! Which function a call calls, for every rule of a batch at once: the keys
//! resolve.rs tries one after the other, each looked up among all the rules'
//! summaries, the rules that found one there dropping out.

use super::multi_mask::{RuleMask, bit, rules_in};
use super::multi_summary::MultiSummary;
use super::multi_walk::MultiCtx;
use super::summary::{called_name, callee};
use ast_grep_core::{Doc, Node};
use std::borrow::Cow;
use std::rc::Rc;

/// A function a call may call, for the `rules` that know it.
pub struct Resolved<'h> {
    pub summary: Cow<'h, MultiSummary>,
    pub rules: RuleMask,
    /// Found by method name alone (`*.run`): a guess.
    pub guessed: bool,
}

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    /// What `call` may call, once per call whatever asks.
    pub fn resolve(&self, call: &Node<D>) -> Rc<Vec<Resolved<'h>>> {
        let at = super::events::key(call);
        if let Some(known) = self.resolved.borrow().get(&at) {
            return known.clone();
        }
        let found = Rc::new(self.resolve_uncached(call));
        self.resolved.borrow_mut().insert(at, found.clone());
        found
    }

    fn resolve_uncached(&self, call: &Node<D>) -> Vec<Resolved<'h>> {
        let mut out = Vec::new();
        let Some(lead) = self.ctxs.first() else {
            return out;
        };
        let mut left = self.hits.active;
        // Most calls are of nothing summarized: tell by the called name
        // before building the whole callee.
        if let Some(last) = called_name(call) {
            let known = self.summaries.ending_in(&last);
            let unknown = left & !known;
            // `void (*fp)(char *) = sink; fp(data)`: the function it holds.
            if unknown != 0
                && let Some(held) = callee(call)
                    .filter(|c| *c == last)
                    .and_then(|_| lead.built_as(call, &format!("(*){last}")))
                && let Some(s) = self.summaries.get(&held)
                && s.present & unknown != 0
            {
                out.push(Resolved {
                    rules: s.present & unknown,
                    summary: Cow::Borrowed(s),
                    guessed: false,
                });
            }
            left &= known;
            if left == 0 {
                return out;
            }
        }
        lead.resolve_with(call, |key, guessed| {
            left = self.pick_into(&mut out, key, call, left, guessed);
            (left == 0).then_some(())
        });
        out
    }

    /// Resolves the rules of `left` that have a summary under `key`; the
    /// rules still to resolve.
    fn pick_into(
        &self,
        out: &mut Vec<Resolved<'h>>,
        key: &str,
        call: &Node<D>,
        left: RuleMask,
        guessed: bool,
    ) -> RuleMask {
        let Some(found) = self.summaries.get(key) else {
            return left;
        };
        let here = found.present & left;
        if here == 0 {
            return left;
        }
        if self.summaries.is_specialized(key) {
            // `render(rows, escape)`: each rule's variant for these arguments.
            for k in rules_in(here) {
                if let Some(s) = self.ctxs[k as usize].pick(key, call) {
                    out.push(Resolved {
                        summary: Cow::Owned(MultiSummary::of_rule(k, s)),
                        rules: bit(k),
                        guessed,
                    });
                }
            }
        } else {
            out.push(Resolved {
                summary: Cow::Borrowed(found),
                rules: here,
                guessed,
            });
        }
        left & !here
    }
}
