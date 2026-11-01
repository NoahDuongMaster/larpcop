//! The events of one scope (assignments, calls, returns, sinks, nested
//! functions, guards) in source order. The rule-independent part (the
//! scope's [`Skeleton`]) is walked once per file and shared by every taint
//! rule; a rule adds its guards and sinks, once per scope however many
//! parameters, summary rounds or callers ask about it.

use super::fields::{class_field, is_field};
use super::flow::{CALLS, LOOPS, enclosing};
use super::guards::{Check, Guard};
use super::paths::{CONDITIONAL, compound};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::rc::Rc;

/// A sink match: (position, sink argument, typed metavariables).
pub(super) type Hit<'a, D> = (usize, Node<'a, D>, Vec<(usize, Node<'a, D>)>);

pub(super) enum Event<'a, D: Doc> {
    /// Target, value, and for an assignment that runs on some paths only (in
    /// a branch, loop or `try`), where that construct ends: a clean value
    /// cleans the name up to there, after which it is tainted again. Last,
    /// whether the target is a field of the object (`this.x`, a Java/C#
    /// class field).
    Assign(Node<'a, D>, Node<'a, D>, Option<usize>, bool),
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    /// Names clean from here on.
    Clean(HashSet<String>),
    /// Names clean until the matching `Restore`.
    Enter(HashSet<String>),
    Restore,
    /// Names whose clean value from the `if` ending there outlives it.
    Settle(usize, HashSet<String>),
    /// Every branch of this `if` assigns these names (joins.rs).
    Both(std::ops::Range<usize>, HashSet<String>),
}

/// A scope's events, by position.
pub(super) type Events<'a, D> = Rc<Vec<(usize, Event<'a, D>)>>;

type Key = (usize, usize);

/// A parameter's known value (flags.rs).
type Seed = Option<(String, bool)>;

/// Scope, number of guard matches, seed.
type EventsKey = (Key, usize, Seed);

/// What a scope holds whatever the rule, in walk order: `If` stands where the
/// guard events of an `if` go once a rule's guards are known.
pub(super) enum Shape<'a, D: Doc> {
    /// As `Event::Assign`; whether the target is a field is worked out once
    /// per file here, it is costly.
    Assign(Node<'a, D>, Node<'a, D>, Option<usize>, bool),
    Call(Node<'a, D>),
    Return(Node<'a, D>),
    Nested(Node<'a, D>),
    If(Node<'a, D>),
    /// Code that never runs (a branch decided by known values): its sinks
    /// are not reached.
    Dead(usize, usize),
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
    /// By scope, number of guard matches (validators add some once known)
    /// and seed.
    events: RefCell<HashMap<EventsKey, Events<'a, D>>>,
    /// While set: a scope walked with a parameter's value known (flags.rs).
    seed: RefCell<Option<(Key, String, bool)>>,
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
            seed: RefCell::default(),
        }
    }

    /// Runs `run` with function `f`'s parameter `name` known to be `value`.
    pub fn seeded<R>(
        &self,
        f: &Node<'a, D>,
        name: &str,
        value: bool,
        run: impl FnOnce() -> R,
    ) -> R {
        *self.seed.borrow_mut() = Some((key(f), name.to_string(), value));
        let out = run();
        *self.seed.borrow_mut() = None;
        out
    }

    /// The seed that applies to `scope`.
    fn seed_of(&self, scope: &Node<'a, D>) -> Seed {
        let seed = self.seed.borrow();
        let (_, name, value) = seed.as_ref().filter(|(k, ..)| *k == key(scope))?;
        Some((name.clone(), *value))
    }

    pub fn events(&self, scope: &Node<'a, D>, guards: &[Check]) -> Events<'a, D> {
        let at = (key(scope), guards.len(), self.seed_of(scope));
        if let Some(known) = self.events.borrow().get(&at) {
            return known.clone();
        }
        let built = Rc::new(self.build(scope, guards));
        self.events.borrow_mut().insert(at, built.clone());
        built
    }

    fn skeleton(&self, scope: &Node<'a, D>) -> Rc<Skeleton<'a, D>> {
        // Seeded: built for this summary only, not shared.
        if let Some((name, value)) = self.seed_of(scope) {
            return Rc::new(skeleton(scope, Some((&name, value))));
        }
        if let Some(known) = self.skeletons.borrow().get(&key(scope)) {
            return known.clone();
        }
        let built = Rc::new(skeleton(scope, None));
        self.skeletons
            .borrow_mut()
            .insert(key(scope), built.clone());
        built
    }

    fn build(&self, scope: &Node<'a, D>, guards: &[Check]) -> Vec<(usize, Event<'a, D>)> {
        let mut events: Vec<(usize, Event<D>)> = Vec::new();
        let mut dead = Vec::new();
        for (at, shape) in self.skeleton(scope).iter() {
            let event = match shape {
                Shape::Dead(start, end) => {
                    dead.push(*start..*end);
                    continue;
                }
                Shape::Assign(l, r, c, f) => Event::Assign(l.clone(), r.clone(), *c, *f),
                Shape::Call(n) => Event::Call(n.clone()),
                Shape::Return(n) => Event::Return(n.clone()),
                Shape::Nested(n) => Event::Nested(n.clone()),
                Shape::If(n) => {
                    if let Some(names) = super::joins::both(n) {
                        events.push((n.range().start, Event::Both(n.range(), names)));
                    }
                    for guard in super::guards::of(n, guards) {
                        match guard {
                            Guard::After(at, names) => events.push((at, Event::Clean(names))),
                            Guard::Settle(r, names) => {
                                events.push((r.start, Event::Settle(r.end, names)))
                            }
                            Guard::Within(r, names) => {
                                events.push((r.start, Event::Enter(names)));
                                events.push((r.end, Event::Restore));
                            }
                        }
                    }
                    continue;
                }
            };
            events.push((*at, event));
        }
        for &i in self.by_scope.get(&key(scope)).into_iter().flatten() {
            let (at, sink, typed) = &self.list[i];
            if dead.iter().any(|d| d.contains(at)) {
                continue;
            }
            events.push((*at, Event::Sink(sink.clone(), typed.clone())));
        }
        events.sort_by_key(|(at, _)| *at);
        events
    }
}

fn skeleton<'a, D: Doc>(scope: &Node<'a, D>, seed: Option<(&str, bool)>) -> Skeleton<'a, D> {
    let mut out: Skeleton<D> = Vec::new();
    let branches = super::deadcode::Branches::of(scope, seed);
    let lists = super::lists::Lists::of(scope);
    for d in branches.dead() {
        out.push((d.start, Shape::Dead(d.start, d.end)));
    }
    walk(scope, None, &branches, &mut |n, conditional| {
        if is_function(n) {
            out.push((n.range().start, Shape::Nested(n.clone())));
            return;
        }
        let kind = n.kind();
        if super::guards::IFS.contains(&kind.as_ref())
            || super::loops::WHILES.contains(&kind.as_ref())
            || super::switches::SWITCHES.contains(&kind.as_ref())
        {
            out.push((n.range().start, Shape::If(n.clone())));
        }
        if let Some((left, right)) = super::flow::assignment(n) {
            // `x = c ? a : b` with `c` known: only the side taken.
            let right = lists.resolve(branches.live(right));
            // `x += v` adds to `x`: a clean `v` cleans `x` up to the
            // assignment's own end, that is not at all.
            let conditional = if compound(n, &left, &right) {
                Some(n.range().end)
            } else {
                conditional
            };
            let at = if LOOPS.contains(&kind.as_ref()) {
                right.range().end
            } else {
                n.range().end
            };
            let field = is_field(&left) || class_field(&left);
            out.push((at, Shape::Assign(left, right, conditional, field)));
        } else if CALLS.contains(&kind.as_ref()) {
            out.push((n.range().start, Shape::Call(n.clone())));
        } else if super::kotlin::is_return(n) {
            out.push((n.range().end, Shape::Return(n.clone())));
        }
    });
    // `(x) => expr`, a Ruby method's last statement, a Rust tail expression.
    if let Some(value) = super::returns::implicit(scope) {
        out.push((value.range().end, Shape::Return(value)));
    }
    out
}

/// Nodes of a scope in order, each with the end of the innermost conditional
/// construct it is in; nested functions are visited, not descended into.
fn walk<'a, D: Doc>(
    scope: &Node<'a, D>,
    conditional: Option<usize>,
    branches: &super::deadcode::Branches,
    f: &mut impl FnMut(&Node<'a, D>, Option<usize>),
) {
    for c in scope.children() {
        if branches.is_dead(&c) {
            continue;
        }
        f(&c, conditional);
        if !is_function(&c) {
            let inside = if CONDITIONAL.contains(&c.kind().as_ref()) && !branches.always(&c) {
                Some(c.range().end)
            } else {
                conditional
            };
            walk(&c, inside, branches, f);
        }
    }
}
