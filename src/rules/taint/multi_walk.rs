//! AST traversal for the multi-taint lattice evaluating all rules simultaneously.

use super::events::Shape;
use super::fields::is_field;
use super::guards::Guard;
use super::multi_hits::MultiHits;
use super::multi_mask::{RuleId, RuleMask, TaintEnv};
use super::multi_summary::MultiSummaries;
use super::VARIABLES;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

pub type TypedNode<'a, D> = (usize, Node<'a, D>);
pub type TypedRuleArg<'a, D> = (RuleId, Vec<TypedNode<'a, D>>);
pub type TypedSpanMap<'a, D> = Vec<TypedRuleArg<'a, D>>;

#[derive(Clone)]
pub enum MultiReached<'a, D: Doc> {
    Sink {
        arg: Node<'a, D>,
        mask: RuleMask,
        sink_mask: RuleMask,
        typed: TypedSpanMap<'a, D>,
    },
    Call {
        arg: Node<'a, D>,
        #[allow(dead_code)]
        mask: RuleMask,
        into: String,
        rule_id: RuleId,
    },
    Return(Node<'a, D>, RuleMask),
    Responds {
        f: Node<'a, D>,
        value: Node<'a, D>,
        mask: RuleMask,
    },
    Field(Node<'a, D>, RuleMask),
}

pub enum MultiSeen<'a, D: Doc> {
    Reached(MultiReached<'a, D>),
    Nested(Node<'a, D>, TaintEnv),
}

enum MultiEvent<'a, D: Doc> {
    Assign(Node<'a, D>, Node<'a, D>, Option<usize>, bool),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    Sink(Node<'a, D>, RuleMask),
    Clean(HashSet<String>, RuleMask),
    Enter(HashSet<String>, RuleMask),
    Restore,
    Settle(usize, HashSet<String>, RuleMask),
    #[allow(dead_code)]
    Both(std::ops::Range<usize>, HashSet<String>),
}

pub struct MultiCtx<'a, 'h, D: Doc> {
    pub active_rules: RuleMask,
    pub hits: &'h MultiHits<'a, D>,
    pub summaries: &'h MultiSummaries,
    pub bare_calls: bool,
    pub numbers: bool,
}

impl<'a, 'h, D: Doc> MultiCtx<'a, 'h, D> {
    pub fn run_scope(
        &self,
        scope: &Node<'a, D>,
        mut env: TaintEnv,
        on: &mut impl FnMut(MultiSeen<'a, D>),
    ) -> TaintEnv {
        let events = self.collect_events(scope);
        let mut cleaned: Vec<Vec<(String, RuleMask)>> = Vec::new();
        let mut until: Vec<(usize, String, RuleMask)> = Vec::new();

        for (at, e) in events {
            until.retain(|(end, name, mask)| {
                let over = *end <= at;
                if over {
                    env.or_mask(name, *mask);
                }
                !over
            });
            match e {
                MultiEvent::Clean(guarded, mask) => {
                    for g in guarded {
                        env.mask_out(&g, mask);
                    }
                }
                MultiEvent::Enter(guarded, mask) => {
                    let mut was = Vec::new();
                    for g in guarded {
                        let m = env.get(&g) & mask;
                        if m != 0 {
                            env.mask_out(&g, m);
                            was.push((g, m));
                        }
                    }
                    cleaned.push(was);
                }
                MultiEvent::Restore => {
                    for (g, m) in cleaned.pop().unwrap_or_default() {
                        env.or_mask(&g, m);
                    }
                }
                MultiEvent::Assign(left, right, branch, is_field_node) => {
                    let mask = self.tainted_mask(&right, &env);
                    let vars: Vec<String> = super::entries::entry(&left)
                        .map(|e| vec![e])
                        .unwrap_or_else(|| {
                            left.dfs()
                                .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
                                .map(|v| v.text().to_string())
                                .collect()
                        });
                    if mask != 0 {
                        if is_field_node || is_field(&left) {
                            on(MultiSeen::Reached(MultiReached::Field(left.clone(), mask)));
                        }
                        for v in vars {
                            env.or_mask(v, mask);
                        }
                    } else {
                        for v in vars {
                            let old = env.get(&v);
                            if old != 0 {
                                env.mask_out(&v, old);
                                if let Some(end) = branch {
                                    until.push((end, v, old));
                                }
                            }
                        }
                    }
                }
                MultiEvent::Sink(arg, sink_mask) => {
                    let reached = self.tainted_mask(&arg, &env) & sink_mask & self.active_rules;
                    if reached != 0 {
                        let r = arg.range();
                        let typed = self
                            .hits
                            .typed
                            .get(&(r.start, r.end))
                            .cloned()
                            .unwrap_or_default();
                        on(MultiSeen::Reached(MultiReached::Sink {
                            arg,
                            mask: reached,
                            sink_mask,
                            typed,
                        }));
                    }
                }
                MultiEvent::Call(call) => self.step_call(&call, &mut env, on),
                MultiEvent::Nested(f) => on(MultiSeen::Nested(f, env.clone())),
                MultiEvent::Return(r) => {
                    let m = self.tainted_mask(&r, &env);
                    if m != 0 {
                        on(MultiSeen::Reached(MultiReached::Return(r, m)));
                    }
                }
                MultiEvent::Settle(end, guarded, mask) => {
                    for g in guarded {
                        let m = env.get(&g) & mask;
                        if m != 0 {
                            until.push((end, g, m));
                        }
                    }
                }
                MultiEvent::Both(..) => {}
            }
        }
        env
    }

    fn collect_events(&self, scope: &Node<'a, D>) -> Vec<(usize, MultiEvent<'a, D>)> {
        let key = (scope.range().start, scope.range().end);
        let existing = self.hits.skeletons.borrow().get(&key).cloned();
        let skeleton = match existing {
            Some(s) => s,
            None => {
                let built = std::rc::Rc::new(super::events::skeleton(scope, None));
                self.hits.skeletons.borrow_mut().insert(key, built.clone());
                built
            }
        };
        let mut events = Vec::new();
        let mut dead = Vec::new();
        for (at, shape) in skeleton.iter() {
            match shape {
                Shape::Dead(s, e) => dead.push(*s..*e),
                Shape::Assign(l, r, c, f) => {
                    events.push((*at, MultiEvent::Assign(l.clone(), r.clone(), *c, *f)))
                }
                Shape::Call(n) => events.push((*at, MultiEvent::Call(n.clone()))),
                Shape::Return(n) => events.push((*at, MultiEvent::Return(n.clone()))),
                Shape::Nested(n) => events.push((*at, MultiEvent::Nested(n.clone()))),
                Shape::If(n, both) => {
                    if let Some(names) = both {
                        events.push((n.range().start, MultiEvent::Both(n.range(), names.clone())));
                    }
                    for (g_mask, check) in &self.hits.guard_checks {
                        for guard in super::guards::of(n, std::slice::from_ref(check)) {
                            match guard {
                                Guard::After(pos, names) => {
                                    events.push((pos, MultiEvent::Clean(names, *g_mask)))
                                }
                                Guard::Settle(r, names) => events
                                    .push((r.start, MultiEvent::Settle(r.end, names, *g_mask)) vast_empty()),
                                Guard::Within(r, names) => {
                                    events.push((r.start, MultiEvent::Enter(names, *g_mask)));
                                    events.push((r.end, MultiEvent::Restore));
                                }
                            }
                        }
                    }
                }
            }
        }
        for &i in self.hits.by_scope.get(&key).into_iter().flatten() {
            let hit = &self.hits.list[i];
            let at = hit.at();
            if !dead.iter().any(|d| d.contains(&at)) {
                events.push((at, MultiEvent::Sink(hit.node.clone(), hit.sink_mask)));
            }
        }
        events.sort_by_key(|(at, _)| *at);
        events
    }

    pub fn run(
        &self,
        scope: &Node<'a, D>,
        env: TaintEnv,
        own: &impl Fn(&Node<'a, D>) -> TaintEnv,
        on: &mut dyn FnMut(MultiReached<'a, D>),
    ) {
        let mut nested = Vec::new();
        self.run_scope(scope, env, &mut |s| match s {
            MultiSeen::Reached(r) => on(r),
            MultiSeen::Nested(f, captured) => nested.push((f, captured)),
        });
        for (f, captured) in nested {
            let f_env = captured.join(&own(&f));
            self.run(&f, f_env, own, &mut |reached| match reached {
                MultiReached::Return(value, mask) => on(MultiReached::Responds {
                    f: f.clone(),
                    value,
                    mask,
                }),
                other => on(other),
            });
        }
    }
}
