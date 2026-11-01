//! Functions that run a function they are given: `render(rows, f)` calling
//! `f.apply(row)` (Java), `f(row)` (JS, Python, Kotlin), `f.invoke(row)`.
//! Such a function gets one more summary per parameter it runs, `name#k`,
//! with those calls counted as sanitizers. A call passing, as argument `k`, a
//! function that returns clean data whatever it is given (`post ->
//! StringEscapeUtils.escapeHtml4(post)`, `HtmlUtils::htmlEscape`) uses it.

use super::flow::{CALLS, Ctx};
use super::kotlin::Part;
use super::summary::{Summaries, Summary};
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;
use std::ops::Range;

/// Methods that run a function object: `Function.apply`, `Consumer.accept`,
/// Kotlin `invoke`, JS `call`.
const RUNS: [&str; 4] = ["apply", "accept", "invoke", "call"];

/// The calls in `f` that run its parameter `p`.
pub(super) fn applications<D: Doc>(f: &Node<D>, p: &str) -> Vec<Range<usize>> {
    f.dfs()
        .filter(|n| CALLS.contains(&n.kind().as_ref()))
        .filter(|call| {
            // Java: `p.apply(x)`.
            if let Some(object) = call.field("object") {
                return object.text() == p
                    && call
                        .field("name")
                        .is_some_and(|m| RUNS.contains(&m.text().as_ref()));
            }
            let Some(callee) = call.part("function") else {
                return false;
            };
            // `p(x)`, or `p.call(x)` / `p.invoke(x)`.
            callee.text() == p
                || callee.part("object").is_some_and(|o| o.text() == p)
                    && callee
                        .part("property")
                        .or_else(|| callee.part("attribute"))
                        .is_some_and(|m| RUNS.contains(&m.text().as_ref()))
        })
        .map(|c| c.range())
        .collect()
}

/// `exported`'s summaries with a function argument clean, named `local#k`.
pub(super) fn import_variants(
    theirs: &Summaries,
    exported: &str,
    local: &str,
    out: &mut Summaries,
) {
    let variants = format!("{exported}#");
    for (name, s) in theirs.iter() {
        if let Some(k) = name.strip_prefix(&variants) {
            out.insert(format!("{local}#{k}"), s.clone());
        }
    }
}

/// The key of `name`'s summary with the calls of its parameter `k` clean.
pub(super) fn key(name: &str, k: usize) -> String {
    format!("{name}#{k}")
}

impl Ctx {
    /// `name`'s summary for `call` when an argument is a function that
    /// cleans and `name` runs it.
    pub(super) fn specialized<D: Doc>(&self, name: &str, call: &Node<D>) -> Option<&Summary> {
        super::summary::args(call)
            .iter()
            .enumerate()
            .find_map(|(k, a)| {
                let s = self.summaries.get(&key(name, k))?;
                let cleans = super::mapping::returns(self, a, true, &HashSet::new()) == Some(false);
                cleans.then_some(s)
            })
    }

    /// A copy that also counts `extra` as sanitized.
    pub(super) fn with_sanitizers(&self, extra: &[Range<usize>]) -> Ctx {
        Ctx {
            sources: self.sources.clone(),
            sanitizers: self.sanitizers.iter().chain(extra).cloned().collect(),
            guards: self.guards.clone(),
            summaries: self.summaries.clone(),
            source_texts: self.source_texts.clone(),
            sourcing: Default::default(),
            bare_calls: self.bare_calls,
            safe_prefix: self.safe_prefix.clone(),
            summarized: Default::default(),
            built: Default::default(),
            cleaners: self.cleaners.clone(),
            writes: self.writes.clone(),
            writes_clean: self.writes_clean,
        }
    }
}
