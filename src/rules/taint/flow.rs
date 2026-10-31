//! The flow walk shared by the check and by function summaries: assignments
//! taint or clean names in source order; sinks, calls and returns are judged
//! with the state at that point.

use super::containers::filled;
use super::events::{Event, Hits};
use super::fields::is_field;
use super::summary::{Summaries, args, callee};
use super::{NAMES, VARIABLES, destructure};
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

/// Targets (left) and value (right) of the assignment kinds we follow.
pub(super) const ASSIGNMENTS: [(&str, &str, &str); 14] = [
    ("variable_declarator", "name", "value"),
    ("let_declaration", "pattern", "value"),
    ("var_spec", "name", "value"),
    ("assignment_expression", "left", "right"),
    ("augmented_assignment_expression", "left", "right"),
    ("assignment", "left", "right"),
    ("augmented_assignment", "left", "right"),
    ("short_var_declaration", "left", "right"),
    ("assignment_statement", "left", "right"),
    ("operator_assignment", "left", "right"),
    // Loops bind each element of the collection: `for (Cookie c : cookies)`,
    // `for (const x of xs)`, `for x in xs:`, `for _, x := range xs`.
    ("enhanced_for_statement", "name", "value"),
    ("for_in_statement", "left", "right"),
    ("for_statement", "left", "right"),
    ("range_clause", "left", "right"),
];

/// Loop kinds among `ASSIGNMENTS`: they bind before the body, not at the end.
pub(super) const LOOPS: [&str; 4] = [
    "enhanced_for_statement",
    "for_in_statement",
    "for_statement",
    "range_clause",
];

/// Call kinds: JS/TS/Go/Rust, Python/Ruby, Java (`m()`, `new T()`), C#, PHP.
pub(super) const CALLS: [&str; 8] = [
    "call_expression",
    "call",
    "method_invocation",
    "object_creation_expression",
    "invocation_expression",
    "function_call_expression",
    "member_call_expression",
    "scoped_call_expression",
];

pub(super) enum Reached<'a, D: Doc> {
    /// Tainted data at a sink argument.
    Sink(Node<'a, D>, Vec<(usize, Node<'a, D>)>),
    /// Tainted argument into a function that sinks that parameter; where it ends up.
    Call(Node<'a, D>, String),
    /// A tainted value is returned.
    Return,
    /// A tainted value is stored in a field of the object (`this.x`, `self.x`),
    /// which the other methods of its class read.
    Field(Node<'a, D>),
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
    pub guards: Vec<super::guards::Check>,
    pub summaries: Summaries,
    pub source_texts: Vec<String>,
    /// Does any known function return source data? (computed on first use)
    pub sourcing: std::cell::OnceCell<bool>,
    /// Ruby: a bare name may call a method (`custom_fields`).
    pub bare_calls: bool,
}

fn within(r: &Range<usize>, outer: &Range<usize>) -> bool {
    outer.start <= r.start && r.end <= outer.end
}

impl Ctx {
    /// What is known of the function a call calls: by its name, or for
    /// `obj.method(…)` on an object of unknown class, the one method of that
    /// name among the known classes (`*.method`).
    pub fn summary<D: Doc>(&self, call: &Node<D>) -> Option<&super::summary::Summary> {
        let name = callee(call)?;
        self.summaries.get(&name).or_else(|| {
            let (_, method) = name.rsplit_once('.')?;
            self.summaries.get(&format!("*.{method}"))
        })
    }

    fn any_sourcing(&self) -> bool {
        *self
            .sourcing
            .get_or_init(|| self.summaries.values().any(|s| s.returns_source))
    }

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
        let text = node.text();
        // Nothing below can be tainted: no source in it, no tainted name
        // spelled in it, no call that could return source data.
        if !self
            .sources
            .iter()
            .any(|s| s.start < r.end && r.start < s.end)
            && !names.iter().any(|n| text.contains(n.as_str()))
            && !((text.contains('(') || self.bare_calls) && self.any_sourcing())
        {
            return false;
        }
        let kind = node.kind();
        if (NAMES.contains(&kind.as_ref()) || is_field(node)) && names.contains(text.as_ref()) {
            return true;
        }
        // Ruby: `custom_fields` alone may be a call of a method returning
        // request data.
        if self.bare_calls
            && kind == "identifier"
            && let Some(s) = self.summaries.get(text.as_ref())
        {
            return s.returns_source;
        }
        // A mapped collection carries what its callback returns.
        if let Some(t) = super::iteration::mapped(self, node, names) {
            return t;
        }
        // A function we have a summary for: only what it really passes through.
        if CALLS.contains(&kind.as_ref())
            && let Some(s) = self.summary(node)
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
        names: HashSet<String>,
        hits: &Hits<'a, D>,
        own: &impl Fn(&Node<'a, D>) -> HashSet<String>,
        on: &mut dyn FnMut(Reached<'a, D>),
    ) {
        let mut nested = Vec::new();
        self.run_scope(scope, names, hits, &mut |s| match s {
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
            self.run(&f, names, hits, own, &mut |reached| {
                if !matches!(reached, Reached::Return) {
                    on(reached)
                }
            });
        }
    }

    fn run_scope<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        mut names: HashSet<String>,
        hits: &Hits<'a, D>,
        on: &mut impl FnMut(Seen<'a, D>),
    ) {
        let events = hits.events(scope, &self.guards);
        let mut cleaned: Vec<Vec<String>> = Vec::new();
        // Names a branch cleaned, tainted again where the branch ends.
        let mut until: Vec<(usize, String)> = Vec::new();
        for (at, e) in events.iter() {
            until.retain(|(end, name)| {
                let over = *end <= *at;
                if over {
                    names.insert(name.clone());
                }
                !over
            });
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
                Event::Assign(left, right, branch, true) => {
                    if self.tainted(right, &names) {
                        names.insert(left.text().to_string());
                        on(Seen::Reached(Reached::Field(left.clone())));
                    } else if names.remove(left.text().as_ref())
                        && let Some(end) = branch
                    {
                        until.push((*end, left.text().to_string()));
                    }
                }
                Event::Assign(left, right, branch, false) => {
                    let tainted = self.tainted(right, &names);
                    for v in left
                        .dfs()
                        .filter(|n| VARIABLES.contains(&n.kind().as_ref()))
                    {
                        if tainted {
                            names.insert(v.text().to_string());
                        } else if NAMES.contains(&left.kind().as_ref())
                            && names.remove(v.text().as_ref())
                            && let Some(end) = branch
                        {
                            until.push((*end, v.text().to_string()));
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
                    let Some(s) = self.summary(call) else {
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
