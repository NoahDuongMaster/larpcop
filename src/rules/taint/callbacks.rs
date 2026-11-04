//! A callback run over a tainted value receives it: `ids.forEach(id => q(id))`,
//! `list.forEach(x -> q(x))`, Kotlin `name?.let { q(it) }`. Its first parameter
//! (Kotlin's implicit `it`) is tainted when the receiver is. What a callback
//! writes into the names it captures (`rows.forEach(r -> out.append(r))`)
//! holds in the scope around it.

use super::events::Hits;
use super::flow::{CALLS, Ctx};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// Methods that call their callback with the receiver or its elements.
const ITERATES: [&str; 17] = [
    "forEach",
    "forEachIndexed",
    "forEachOrdered",
    "onEach",
    "map",
    "mapNotNull",
    "flatMap",
    "filter",
    "find",
    "some",
    "every",
    "ifPresent",
    "let",
    "also",
    "takeIf",
    "takeUnless",
    "use",
];

/// Wrappers between a callback and the call it is passed to.
const BETWEEN: [&str; 5] = [
    "arguments",
    "argument_list",
    "value_argument",
    "value_arguments",
    "annotated_lambda",
];

/// The parameter of nested function `f` that gets the taint of the value it
/// iterates, given the tainted `names` where `f` is written.
pub(super) fn bound<D: Doc>(ctx: &Ctx, f: &Node<D>, names: &HashSet<String>) -> Option<String> {
    let (receiver, param) = element_of(f)?;
    ctx.tainted(&receiver, names).then_some(param)
}

/// The receiver whose elements callback `f` is run on, and the parameter that
/// takes each element, whatever the receiver holds.
pub(super) fn element_of<'a, D: Doc>(f: &Node<'a, D>) -> Option<(Node<'a, D>, String)> {
    let mut at = f.parent()?;
    while BETWEEN.contains(&at.kind().as_ref()) || at.kind() == "call_suffix" {
        at = at.parent()?;
    }
    if !CALLS.contains(&at.kind().as_ref()) {
        return None;
    }
    let method = super::summary::called_name(&at)?;
    if !ITERATES.contains(&method.as_str()) {
        return None;
    }
    // Java `list.forEach(…)` names its receiver `object`; JS and Python
    // calls hold it in the callee (`list.forEach` as a member expression).
    let receiver = at
        .part("object")
        .or_else(|| at.part("function").and_then(|m| m.part("object")))?;
    let params = super::defs::positional_params(f);
    let first = if method == "forEachIndexed" { 1 } else { 0 };
    let param = params.into_iter().nth(first).filter(|p| !p.is_empty())?;
    Some((receiver, param))
}

impl Ctx {
    /// The names of `scope` that callback `f` taints, given the tainted
    /// `names` where it is written: `out` in `rows.forEach(r -> out.append(r))`.
    pub(super) fn captured_writes<'a, D: Doc>(
        &self,
        scope: &Node<'a, D>,
        f: &Node<'a, D>,
        names: &HashSet<String>,
        hits: &Hits<'a, D>,
    ) -> Vec<String> {
        let params = super::summary::param_names(f);
        let text = f.text();
        let start: HashSet<String> = names
            .iter()
            .filter(|n| !params.contains(*n) && text.contains(n.as_str()))
            .cloned()
            .chain(bound(self, f, names))
            .collect();
        if start.is_empty() {
            return Vec::new();
        }
        // The walk of every enclosing callback comes by here again with the
        // same names: without this, once per nesting level.
        let mut sorted: Vec<String> = start.iter().cloned().collect();
        sorted.sort();
        let memo = (super::events::key(f), hits.seeding(), sorted);
        if let Some(known) = self.memo.captured.borrow().get(&memo) {
            return known.clone();
        }
        let end = self.run_scope(f, start.clone(), hits, &mut |_| {});
        // Only names the scope itself uses, outside the callback.
        let outer = scope.text();
        let base = scope.range().start;
        let (from, to) = (f.range().start - base, f.range().end - base);
        let around = |n: &str| outer[..from].contains(n) || outer[to..].contains(n);
        let written: Vec<String> = end
            .into_iter()
            .filter(|n| !start.contains(n) && !params.contains(n) && around(n))
            .collect();
        self.memo
            .captured
            .borrow_mut()
            .insert(memo, written.clone());
        written
    }
}
