//! The events of one scope (assignments, calls, returns, sinks, nested
//! functions, guards) in source order. They depend only on the scope, the
//! sinks and the guards, so each scope is walked once per check however many
//! parameters, summary rounds or callers ask about it.

use super::flow::{ASSIGNMENTS, CALLS, enclosing};
use super::guards::Guard;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::rc::Rc;

/// A sink match: (position, sink argument, typed metavariables).
pub(super) type Hit<'a, D> = (usize, Node<'a, D>, Vec<(usize, Node<'a, D>)>);

pub(super) enum Event<'a, D: Doc> {
    Assign(Node<'a, D>, Node<'a, D>),
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    /// Names clean from here on.
    Clean(HashSet<String>),
    /// Names clean until the matching `Restore`.
    Enter(HashSet<String>),
    Restore,
}

/// A scope's events, by position.
pub(super) type Events<'a, D> = Rc<Vec<(usize, Event<'a, D>)>>;

/// The sink matches of a file, and the events of each scope walked so far.
pub(super) struct Hits<'a, D: Doc> {
    pub list: Vec<Hit<'a, D>>,
    events: RefCell<HashMap<(usize, usize), Events<'a, D>>>,
}

impl<'a, D: Doc> Hits<'a, D> {
    pub fn new(list: Vec<Hit<'a, D>>) -> Self {
        Self {
            list,
            events: RefCell::default(),
        }
    }

    pub fn events(
        &self,
        scope: &Node<'a, D>,
        root: &Node<'a, D>,
        guards: &[Range<usize>],
    ) -> Events<'a, D> {
        let key = (scope.range().start, scope.range().end);
        if let Some(known) = self.events.borrow().get(&key) {
            return known.clone();
        }
        let built = Rc::new(self.build(scope, root, guards));
        self.events.borrow_mut().insert(key, built.clone());
        built
    }

    fn build(
        &self,
        scope: &Node<'a, D>,
        root: &Node<'a, D>,
        guards: &[Range<usize>],
    ) -> Vec<(usize, Event<'a, D>)> {
        let mut events: Vec<(usize, Event<D>)> = Vec::new();
        walk(scope, &mut |n| {
            if is_function(n) {
                events.push((n.range().start, Event::Nested(n.clone())));
                return;
            }
            match super::guards::of(n, guards) {
                Some(Guard::After(at, names)) => events.push((at, Event::Clean(names))),
                Some(Guard::Within(r, names)) => {
                    events.push((r.start, Event::Enter(names)));
                    events.push((r.end, Event::Restore));
                }
                None => {}
            }
            let kind = n.kind();
            if let Some((_, l, r)) = ASSIGNMENTS.iter().find(|(k, ..)| kind == *k)
                && let (Some(left), Some(right)) = (n.field(l), n.field(r))
            {
                events.push((n.range().end, Event::Assign(left, right)));
            } else if CALLS.contains(&kind.as_ref()) {
                events.push((n.range().start, Event::Call(n.clone())));
            } else if matches!(kind.as_ref(), "return_statement" | "return_expression") {
                events.push((n.range().end, Event::Return(n.clone())));
            }
        });
        // `(x) => expr`: the body is the return value.
        if let Some(body) = scope
            .field("body")
            .filter(|b| scope.kind() == "arrow_function" && b.kind() != "statement_block")
        {
            events.push((body.range().end, Event::Return(body)));
        }
        for (at, sink, typed) in &self.list {
            if enclosing(sink, root).range() == scope.range() {
                events.push((*at, Event::Sink(sink.clone(), typed.clone())));
            }
        }
        events.sort_by_key(|(at, _)| *at);
        events
    }
}

/// Nodes of a scope in order; nested functions are visited, not descended into.
fn walk<'a, D: Doc>(scope: &Node<'a, D>, f: &mut impl FnMut(&Node<'a, D>)) {
    for c in scope.children() {
        f(&c);
        if !is_function(&c) {
            walk(&c, f);
        }
    }
}
