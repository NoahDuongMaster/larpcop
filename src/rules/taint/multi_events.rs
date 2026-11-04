//! The events of one scope for a whole batch, in source order: the
//! rule-independent ones (assignments, calls, returns, nested functions) and
//! the sinks and guards that rules share or have each their own.

use super::events::{Shape, key, shared_skeleton};
use super::guards::{Guard, IFS};
use super::multi_hits::MultiHits;
use super::multi_mask::RuleMask;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;
use std::rc::Rc;

pub enum MultiEvent<'a, D: Doc> {
    /// As `Event::Assign` (events.rs).
    Assign(Node<'a, D>, Node<'a, D>, Option<usize>, bool),
    /// Index into the batch's sinks.
    Sink(usize),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    /// Names clean from here on, for these rules.
    Clean(HashSet<String>, RuleMask),
    /// Names clean until the matching `Restore` of the same group of rules.
    Enter(usize, HashSet<String>, RuleMask),
    Restore(usize),
    /// Names whose clean value from the `if` ending there outlives it.
    Settle(usize, HashSet<String>, RuleMask),
    /// Every branch of this `if` assigns these names (joins.rs).
    Both(Range<usize>, HashSet<String>),
}

/// A scope's events, by position, and what its walk needs to know of them.
pub struct MultiEvents<'a, D: Doc> {
    pub list: Vec<(usize, MultiEvent<'a, D>)>,
    /// Groups of names the scope's `&local` assignments join (pointers.rs).
    pub pointers: Vec<HashSet<String>>,
    /// Do guards clean names in this scope, so that where a name's taint
    /// came from matters (origins.rs)?
    pub guarded: bool,
}

impl<'a, D: Doc> MultiHits<'a, D> {
    /// The events of `scope`, built once.
    pub fn events(&self, scope: &Node<'a, D>) -> Rc<MultiEvents<'a, D>> {
        let at = key(scope);
        if let Some(known) = self.events.borrow().get(&at) {
            return known.clone();
        }
        let built = Rc::new(self.build(scope));
        self.events.borrow_mut().insert(at, built.clone());
        built
    }

    fn build(&self, scope: &Node<'a, D>) -> MultiEvents<'a, D> {
        let skeleton = shared_skeleton(&self.skeletons, scope);
        let mut list: Vec<(usize, MultiEvent<'a, D>)> = Vec::new();
        let mut dead = Vec::new();
        for (at, shape) in skeleton.iter() {
            let event = match shape {
                Shape::Dead(start, end) => {
                    dead.push(*start..*end);
                    continue;
                }
                Shape::Assign(l, r, c, f) => MultiEvent::Assign(l.clone(), r.clone(), *c, *f),
                Shape::Call(n) => MultiEvent::Call(n.clone()),
                Shape::Return(n) => MultiEvent::Return(n.clone()),
                Shape::Nested(n) => MultiEvent::Nested(n.clone()),
                Shape::If(n, both) => {
                    if let Some(names) = both {
                        list.push((n.range().start, MultiEvent::Both(n.range(), names.clone())));
                    }
                    if super::switches::SWITCHES.contains(&n.kind().as_ref()) {
                        // Arms read the subject alone, whatever the rule checks.
                        let arms = super::switches::arms(n);
                        self.guard_events(&mut list, arms, self.active, self.guard_groups.len());
                    } else if IFS.contains(&n.kind().as_ref())
                        || super::loops::WHILES.contains(&n.kind().as_ref())
                    {
                        for (g, (rules, checks)) in self.guard_groups.iter().enumerate() {
                            let guards = super::guards::of(n, checks);
                            self.guard_events(&mut list, guards, *rules, g);
                        }
                    }
                    continue;
                }
            };
            list.push((*at, event));
        }
        for &i in self.by_scope.get(&key(scope)).into_iter().flatten() {
            let at = self.sinks[i].at;
            if !dead.iter().any(|d: &Range<usize>| d.contains(&at)) {
                list.push((at, MultiEvent::Sink(i)));
            }
        }
        list.sort_by_key(|(at, _)| *at);
        let pointers = super::pointers::groups(skeleton.iter().filter_map(|(_, s)| match s {
            Shape::Assign(l, r, ..) => Some((l, r)),
            _ => None,
        }));
        let guarded = list
            .iter()
            .any(|(_, e)| matches!(e, MultiEvent::Clean(..) | MultiEvent::Enter(..)));
        MultiEvents {
            list,
            pointers,
            guarded,
        }
    }

    /// The events of guards that hold for `rules`, whose `Within` ranges pair
    /// up as group `group`.
    fn guard_events(
        &self,
        list: &mut Vec<(usize, MultiEvent<'a, D>)>,
        guards: Vec<Guard>,
        rules: RuleMask,
        group: usize,
    ) {
        for guard in guards {
            match guard {
                Guard::After(at, names) => list.push((at, MultiEvent::Clean(names, rules))),
                Guard::Settle(r, names) => {
                    list.push((r.start, MultiEvent::Settle(r.end, names, rules)))
                }
                Guard::Within(r, names) => {
                    list.push((r.start, MultiEvent::Enter(group, names, rules)));
                    list.push((r.end, MultiEvent::Restore(group)));
                }
            }
        }
    }
}
