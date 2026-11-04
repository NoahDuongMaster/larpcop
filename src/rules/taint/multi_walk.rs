//! Walking one scope for a whole batch of rules at once: its events in source
//! order change which rules find which names tainted; sinks, calls and
//! returns are judged with the state at that point. The single-rule walk
//! (walk.rs) is the reference: each rule's results are the ones it gives.

use super::events::Key;
use super::flow::Ctx;
use super::multi_events::MultiEvent;
use super::multi_hits::MultiHits;
use super::multi_mask::{RuleId, RuleMask, TaintEnv};
use super::multi_resolve::Resolved;
use super::multi_scope::Scope;
use super::multi_summary::MultiSummaries;
use ast_grep_core::{Doc, Node};
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

pub enum MultiReached<'a, D: Doc> {
    /// Tainted data at sink `sink` of the batch's hits, for these rules.
    Sink {
        arg: Node<'a, D>,
        rules: RuleMask,
        sink: usize,
    },
    /// Tainted argument into a function that sinks that parameter.
    Call {
        arg: Node<'a, D>,
        into: String,
        rule: RuleId,
    },
    /// A tainted value is returned.
    Return(Node<'a, D>, RuleMask),
    /// A function nested in the walked scope returns a tainted value.
    Responds {
        f: Node<'a, D>,
        value: Node<'a, D>,
        mask: RuleMask,
    },
    /// A tainted value is stored in a field of the object.
    Field(Node<'a, D>, RuleMask),
}

/// What a walk of one scope found, before its nested functions are walked.
pub enum MultiSeen<'a, D: Doc> {
    Reached(MultiReached<'a, D>),
    /// A nested function and the tainted names it sees.
    Nested(Node<'a, D>, TaintEnv),
}

/// What each call, by its range, may call.
pub(super) type Resolutions<'h> = RefCell<HashMap<Key, Rc<Vec<Resolved<'h>>>>>;

/// A batch of rules (the `k`th being `rules[k]`, prepared as `ctxs[k]`)
/// walked together.
pub struct MultiCtx<'a, 'h, D: Doc> {
    pub hits: &'h MultiHits<'a, D>,
    pub summaries: &'h MultiSummaries,
    pub ctxs: &'h [&'h Ctx],
    /// Ruby: a bare name may call a method.
    pub bare_calls: bool,
    /// PHP: `+ - * / % **` make numbers.
    pub numbers: bool,
    /// The rules that judge what nested functions return.
    pub responds: RuleMask,
    /// The rules with a `safe_prefix`.
    pub safe_prefix: RuleMask,
    /// The rules whose stream writes do not carry taint.
    pub writes_clean: RuleMask,
    /// The rules with calls that write into an argument.
    pub writing: RuleMask,
    /// What each call (by range) may call, worked out once.
    pub(super) resolved: Resolutions<'h>,
}

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    pub fn run_scope(
        &self,
        scope: &Node<'a, D>,
        env: TaintEnv,
        returns: bool,
        on: &mut dyn FnMut(MultiSeen<'a, D>),
    ) -> TaintEnv {
        let events = self.hits.events(scope);
        let mut st = Scope::new(env, events.guarded, self.hits.guard_groups.len() + 1);
        for (at, e) in events.list.iter() {
            st.spread(&events.pointers);
            st.expire(*at);
            match e {
                MultiEvent::Clean(guarded, rules) => st.clean(guarded, *rules),
                MultiEvent::Enter(group, guarded, rules) => st.enter(*group, guarded, *rules),
                MultiEvent::Restore(group) => st.restore(*group),
                MultiEvent::Settle(end, safe, rules) => st.settled.push((*end, safe, *rules)),
                MultiEvent::Both(range, set) => st.both(range.clone(), set),
                MultiEvent::Assign(left, right, branch, field) => {
                    self.assign(&mut st, *at, (left, right), *branch, *field, on)
                }
                MultiEvent::Sink(i) => {
                    let sink = &self.hits.sinks[*i];
                    let rules = self.tainted_mask(&sink.node, &st.env, sink.rules);
                    if rules != 0 {
                        on(MultiSeen::Reached(MultiReached::Sink {
                            arg: sink.node.clone(),
                            rules,
                            sink: *i,
                        }));
                    }
                }
                MultiEvent::Call(call) => self.step_call(call, &mut st, on),
                MultiEvent::Nested(f) => self.nested(scope, f, &mut st, on),
                MultiEvent::Return(r) if returns && self.responds != 0 => {
                    let rules = self.tainted_mask(r, &st.env, self.responds);
                    if rules != 0 {
                        on(MultiSeen::Reached(MultiReached::Return(r.clone(), rules)));
                    }
                }
                MultiEvent::Return(_) => {}
            }
        }
        st.env
    }
}
