//! The flow walk shared by the check and by function summaries: assignments
//! taint or clean names in source order; sinks, calls and returns are judged
//! with the state at that point.

use super::events::{Event, Hits};
use super::summary::{Summaries, args, callee};
use super::{VARIABLES, destructure};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

/// Targets (left) and value (right) of the assignment kinds we follow.
pub(super) const ASSIGNMENTS: [(&str, &str, &str); 9] = [
    ("variable_declarator", "name", "value"),
    ("let_declaration", "pattern", "value"),
    ("var_spec", "name", "value"),
    ("assignment_expression", "left", "right"),
    ("augmented_assignment_expression", "left", "right"),
    ("assignment", "left", "right"),
    ("augmented_assignment", "left", "right"),
    ("short_var_declaration", "left", "right"),
    ("assignment_statement", "left", "right"),
];

pub(super) const CALLS: [&str; 2] = ["call_expression", "call"];

pub(super) enum Reached<'a, D: Doc> {
    /// Tainted data at a sink argument.
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
    /// Tainted argument into a function that sinks that parameter; where it ends up.
    Call(Node<'a, D>, String),
    /// A tainted value is returned.
    Return,
}

/// What a walk of one scope found, before its nested functions are walked.
enum Seen<'a, D: Doc> {
    Reached(Reached<'a, D>),
    /// A nested function (callback, closure) and the tainted names it captures.
    Nested(Node<'a, D>, HashSet<String>),
}

pub(super) struct Ctx {
    pub sources: Vec<Range<usize>>,
    pub sanitizers: Vec<Range<usize>>,
    pub guards: Vec<Range<usize>>,
    pub summaries: Summaries,
    pub source_texts: Vec<String>,
}

fn within(r: &Range<usize>, outer: &Range<usize>) -> bool {
    outer.start <= r.start && r.end <= outer.end
}

impl Ctx {
    /// Does `node` carry source data (not passed through a sanitizer)?
    pub fn tainted<D: Doc>(&self, node: &Node<D>, names: &HashSet<String>) -> bool {
        // A function value is code, not data; what it captures is followed when
        // its body is walked.
        if is_function(node) {
            return false;
        }
        let r = node.range();
        if self.sanitizers.iter().any(|s| within(&r, s)) {
            return false;
        }
        if self.sources.iter().any(|s| within(&r, s)) {
            return true;
        }
        if VARIABLES[..2].contains(&node.kind().as_ref()) && names.contains(node.text().as_ref()) {
            return true;
        }
        // A function we have a summary for: only what it really passes through.
        if CALLS.contains(&node.kind().as_ref())
            && let Some(s) = callee(node).and_then(|c| self.summaries.get(&c))
        {
            return s.returns_source
                || args(node)
                    .iter()
                    .enumerate()
                    .any(|(i, a)| s.returns.contains(&i) && self.tainted(a, names));
        }
        node.children().any(|c| self.tainted(&c, names))
    }

    /// Walks `scope` from `names`, then each function nested in it (callbacks,
    /// closures) with the tainted names it captures plus `own(nested)`, reporting
    /// what tainted data reaches.
    pub fn run<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        root: &Node<'a, D>,
        names: HashSet<String>,
        hits: &Hits<'a, D>,
        own: &impl Fn(&Node<'a, D>) -> HashSet<String>,
        on: &mut dyn FnMut(Reached<'a, D>),
    ) {
        let mut nested = Vec::new();
        self.run_scope(scope, root, names, hits, &mut |s| match s {
            Seen::Reached(r) => on(r),
            Seen::Nested(f, captured) => nested.push((f, captured)),
        });
        for (f, captured) in nested {
            let params = super::summary::param_names(&f);
            let text = f.text();
            // Only what the nested function mentions can reach it.
            let mut names: HashSet<String> = captured
                .into_iter()
                .filter(|n| !params.contains(n) && text.contains(n.as_str()))
                .collect();
            names.extend(own(&f));
            // A nested function's `return` is not this scope's.
            self.run(&f, root, names, hits, own, &mut |reached| {
                if !matches!(reached, Reached::Return) {
                    on(reached)
                }
            });
        }
    }

    fn run_scope<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        root: &Node<'a, D>,
        mut names: HashSet<String>,
        hits: &Hits<'a, D>,
        on: &mut impl FnMut(Seen<'a, D>),
    ) {
        let events = hits.events(scope, root, &self.guards);
        let mut cleaned: Vec<Vec<String>> = Vec::new();
        for (_, e) in events.iter() {
            match e {
                Event::Clean(guarded) => names.retain(|n| !guarded.contains(n)),
                Event::Enter(guarded) => {
                    let was: Vec<String> = guarded
                        .iter()
                        .filter(|g| names.remove(*g))
                        .cloned()
                        .collect();
                    cleaned.push(was);
                }
                Event::Restore => names.extend(cleaned.pop().unwrap_or_default()),
                Event::Assign(left, right) => {
                    let tainted = self.tainted(right, &names);
                    for v in left
                        .dfs()
                        .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
                    {
                        if tainted {
                            names.insert(v.text().to_string());
                        } else if left.kind() == "identifier" {
                            names.remove(v.text().as_ref());
                        }
                    }
                    if !tainted && right.kind() == "identifier" {
                        let object = right.text();
                        names.extend(destructure::from_object(left, &object, &self.source_texts));
                    }
                }
                Event::Sink(arg, typed) if self.tainted(arg, &names) => {
                    on(Seen::Reached(Reached::Sink(arg.clone(), typed.clone())))
                }
                Event::Nested(f) => on(Seen::Nested(f.clone(), names.clone())),
                Event::Call(call) => {
                    // `list.push(x)`, `map.set(k, x)`, `Object.assign(o, x)`: the
                    // container now holds what was put in.
                    if let Some(container) = filled(call)
                        && args(call).iter().any(|a| self.tainted(a, &names))
                    {
                        names.insert(container);
                    }
                    let Some(s) = callee(call).and_then(|c| self.summaries.get(&c)) else {
                        continue;
                    };
                    let args = args(call);
                    for (i, into) in &s.sinks {
                        if let Some(a) = args.get(*i).filter(|a| self.tainted(a, &names)) {
                            on(Seen::Reached(Reached::Call(a.clone(), into.clone())));
                        }
                    }
                }
                Event::Return(r) if self.tainted(r, &names) => on(Seen::Reached(Reached::Return)),
                _ => {}
            }
        }
    }
}

pub(super) fn enclosing<'a, D: Doc>(node: &Node<'a, D>, root: &Node<'a, D>) -> Node<'a, D> {
    node.ancestors()
        .find(|a| is_function(a))
        .unwrap_or_else(|| root.clone())
}

/// Methods that store their arguments in the object they are called on.
const FILLS: [&str; 12] = [
    "push",
    "unshift",
    "splice",
    "set",
    "add",
    "append",
    "appendleft",
    "extend",
    "insert",
    "update",
    "setdefault",
    "concat",
];

/// The variable a call stores its arguments in: the receiver of a filling
/// method, or the first argument of `Object.assign`.
fn filled<D: Doc>(call: &Node<D>) -> Option<String> {
    let name = callee(call)?;
    if name == "Object.assign" {
        let target = args(call).into_iter().next()?;
        return (target.kind() == "identifier").then(|| target.text().to_string());
    }
    let (receiver, method) = name.rsplit_once('.')?;
    let root = receiver.split(['.', '[']).next()?;
    (FILLS.contains(&method)
        && !root.is_empty()
        && root
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$'))
    .then(|| root.to_string())
}
