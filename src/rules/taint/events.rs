//! The events of one scope (assignments, calls, returns, sinks, nested
//! functions, guards) in source order. The rule-independent part (the
//! scope's [`Skeleton`]) is walked once per file and shared by every taint
//! rule; a rule adds its guards and sinks, once per scope however many
//! parameters, summary rounds or callers ask about it.

use super::flow::{ASSIGNMENTS, CALLS, LOOPS, enclosing};
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
    /// Target, value, and whether it runs only on some paths (in a branch,
    /// loop or `try`): such an assignment can taint a name, never clean it.
    Assign(Node<'a, D>, Node<'a, D>, bool),
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

type Key = (usize, usize);

/// What a scope holds whatever the rule, in walk order: `If` stands where the
/// guard events of an `if` go once a rule's guards are known.
pub(super) enum Shape<'a, D: Doc> {
    Assign(Node<'a, D>, Node<'a, D>, bool),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    If(Node<'a, D>),
}

pub(super) type Skeleton<'a, D> = Vec<(usize, Shape<'a, D>)>;

/// Skeletons of a file's scopes, shared by the rules checking it.
pub(super) type Skeletons<'a, D> = Rc<RefCell<HashMap<Key, Rc<Skeleton<'a, D>>>>>;

/// The sink matches of a file, and the events of each scope walked so far.
pub(super) struct Hits<'a, D: Doc> {
    pub list: Vec<Hit<'a, D>>,
    /// Scope → its sinks (indexes into `list`).
    by_scope: HashMap<Key, Vec<usize>>,
    skeletons: Skeletons<'a, D>,
    events: RefCell<HashMap<Key, Events<'a, D>>>,
}

fn key<D: Doc>(n: &Node<D>) -> Key {
    let r = n.range();
    (r.start, r.end)
}

impl<'a, D: Doc> Hits<'a, D> {
    pub fn new(list: Vec<Hit<'a, D>>, root: &Node<'a, D>, skeletons: Skeletons<'a, D>) -> Self {
        let mut by_scope: HashMap<Key, Vec<usize>> = HashMap::new();
        for (i, (_, sink, _)) in list.iter().enumerate() {
            by_scope
                .entry(key(&enclosing(sink, root)))
                .or_default()
                .push(i);
        }
        Self {
            list,
            by_scope,
            skeletons,
            events: RefCell::default(),
        }
    }

    pub fn events(&self, scope: &Node<'a, D>, guards: &[Range<usize>]) -> Events<'a, D> {
        if let Some(known) = self.events.borrow().get(&key(scope)) {
            return known.clone();
        }
        let built = Rc::new(self.build(scope, guards));
        self.events.borrow_mut().insert(key(scope), built.clone());
        built
    }

    fn skeleton(&self, scope: &Node<'a, D>) -> Rc<Skeleton<'a, D>> {
        if let Some(known) = self.skeletons.borrow().get(&key(scope)) {
            return known.clone();
        }
        let built = Rc::new(skeleton(scope));
        self.skeletons
            .borrow_mut()
            .insert(key(scope), built.clone());
        built
    }

    fn build(&self, scope: &Node<'a, D>, guards: &[Range<usize>]) -> Vec<(usize, Event<'a, D>)> {
        let mut events: Vec<(usize, Event<D>)> = Vec::new();
        for (at, shape) in self.skeleton(scope).iter() {
            let event = match shape {
                Shape::Assign(l, r, c) => Event::Assign(l.clone(), r.clone(), *c),
                Shape::Call(n) => Event::Call(n.clone()),
                Shape::Return(n) => Event::Return(n.clone()),
                Shape::Nested(n) => Event::Nested(n.clone()),
                Shape::If(n) => {
                    match super::guards::of(n, guards) {
                        Some(Guard::After(at, names)) => events.push((at, Event::Clean(names))),
                        Some(Guard::Within(r, names)) => {
                            events.push((r.start, Event::Enter(names)));
                            events.push((r.end, Event::Restore));
                        }
                        None => {}
                    }
                    continue;
                }
            };
            events.push((*at, event));
        }
        for &i in self.by_scope.get(&key(scope)).into_iter().flatten() {
            let (at, sink, typed) = &self.list[i];
            events.push((*at, Event::Sink(sink.clone(), typed.clone())));
        }
        events.sort_by_key(|(at, _)| *at);
        events
    }
}

fn skeleton<'a, D: Doc>(scope: &Node<'a, D>) -> Skeleton<'a, D> {
    let mut out: Skeleton<D> = Vec::new();
    walk(scope, false, &mut |n, conditional| {
        if is_function(n) {
            out.push((n.range().start, Shape::Nested(n.clone())));
            return;
        }
        let kind = n.kind();
        if super::guards::IFS.contains(&kind.as_ref()) {
            out.push((n.range().start, Shape::If(n.clone())));
        }
        if let Some((_, l, r)) = ASSIGNMENTS.iter().find(|(k, ..)| kind == *k)
            && let (Some(left), Some(right)) = (n.field(l), n.field(r))
        {
            let at = if LOOPS.contains(&kind.as_ref()) {
                right.range().end
            } else {
                n.range().end
            };
            out.push((at, Shape::Assign(left, right, conditional)));
        } else if CALLS.contains(&kind.as_ref()) {
            out.push((n.range().start, Shape::Call(n.clone())));
        } else if matches!(kind.as_ref(), "return_statement" | "return_expression") {
            out.push((n.range().end, Shape::Return(n.clone())));
        }
    });
    // `(x) => expr`: the body is the return value.
    if let Some(body) = scope
        .field("body")
        .filter(|b| scope.kind() == "arrow_function" && b.kind() != "statement_block")
    {
        out.push((body.range().end, Shape::Return(body)));
    }
    out
}

/// Constructs whose insides run on some paths only.
const CONDITIONAL: [&str; 26] = [
    "if_statement",
    "if_expression",
    "else_clause",
    "elif_clause",
    "switch_statement",
    "switch_expression",
    "expression_switch_statement",
    "type_switch_statement",
    "select_statement",
    "match_expression",
    "conditional_expression",
    "ternary_expression",
    "while_statement",
    "while_expression",
    "do_statement",
    "for_statement",
    "enhanced_for_statement",
    "for_in_statement",
    "for_expression",
    "loop_expression",
    "try_statement",
    "catch_clause",
    "except_clause",
    "case",
    "when",
    "rescue",
];

/// Nodes of a scope in order, each with whether it is inside a conditional
/// construct; nested functions are visited, not descended into.
fn walk<'a, D: Doc>(
    scope: &Node<'a, D>,
    conditional: bool,
    f: &mut impl FnMut(&Node<'a, D>, bool),
) {
    for c in scope.children() {
        f(&c, conditional);
        if !is_function(&c) {
            let inside = conditional || CONDITIONAL.contains(&c.kind().as_ref());
            walk(&c, inside, f);
        }
    }
}
