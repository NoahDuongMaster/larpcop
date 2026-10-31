//! Validators of the project's own: a function that returns a failure value
//! (`null`, `false`, `None`, `nil`) unless its parameter passed a guard, and
//! something else otherwise, guards that argument where it is called, as a
//! `guards:` pattern would: `if (pathFilter(p) == null) return;`,
//! `if (!isSafeName(n)) throw …`, `ok = isLocal(u) && …`. Returning a guard
//! expression itself counts too: `return !name.contains("..");`.

use super::flow::Ctx;
use super::guards::{self, Check, Guard};
use super::scan::FileIndex;
use ast_grep_core::{Doc, Node};
use std::collections::{BTreeSet, HashSet};

const RETURNS: [&str; 3] = ["return_statement", "return", "return_expression"];
const FAILURES: [&str; 6] = ["null", "false", "False", "None", "nil", "NULL"];

/// The parameters (by index) `f` validates.
pub(super) fn validated<D: Doc>(
    f: &Node<D>,
    params: &[String],
    checks: &[Check],
) -> BTreeSet<usize> {
    let range = f.range();
    // No guard inside, nothing validated: most functions stop here.
    if !checks
        .iter()
        .any(|(r, ..)| range.start <= r.start && r.end <= range.end)
    {
        return BTreeSet::new();
    }
    let returns: Vec<Node<D>> = f
        .dfs()
        .filter(|n| n.is_named() && RETURNS.contains(&n.kind().as_ref()))
        .filter(|r| {
            r.ancestors()
                .find(|a| crate::rules::complexity::is_function(a))
                .is_some_and(|a| a.range() == range)
        })
        .collect();
    if returns.is_empty() {
        return BTreeSet::new();
    }
    let cleared: Vec<Guard> = f.dfs().flat_map(|n| guards::of(&n, checks)).collect();
    params
        .iter()
        .enumerate()
        .filter(|(_, p)| !p.is_empty() && validates(&returns, &cleared, p, checks))
        .map(|(i, _)| i)
        .collect()
}

/// Does every return fail, or return with `param` checked, and do both occur?
fn validates<D: Doc>(
    returns: &[Node<D>],
    cleared: &[Guard],
    param: &str,
    checks: &[Check],
) -> bool {
    let (mut failing, mut passing) = (false, false);
    for r in returns {
        let Some(value) = r.children().find(|c| c.is_named() && c.kind() != "comment") else {
            return false;
        };
        if FAILURES.contains(&value.text().as_ref()) {
            failing = true;
            continue;
        }
        if guards::safe(&value, checks).0.contains(param) {
            // `return !p.contains("..")`: false exactly when the check fails.
            failing = true;
            passing = true;
            continue;
        }
        let at = r.range().start;
        let clean = cleared.iter().any(|g| match g {
            Guard::After(from, names) => *from <= at && names.contains(param),
            Guard::Within(span, names) => span.contains(&at) && names.contains(param),
            Guard::Settle(..) => false,
        });
        if !clean {
            return false;
        }
        passing = true;
    }
    failing && passing
}

/// Guard matches for the calls of `index` to known validators.
pub(super) fn calls<D: Doc>(index: &FileIndex<D>, ctx: &Ctx) -> Vec<Check> {
    let validators: HashSet<&str> = ctx
        .summaries
        .iter()
        .filter(|(_, s)| !s.validates.is_empty())
        .map(|(name, _)| name.as_str())
        .collect();
    if validators.is_empty() {
        return Vec::new();
    }
    // As `Ctx::summary` finds them: by name, or `*.method` for `obj.method`.
    let validates = |callee: &str| {
        validators.contains(callee)
            || callee
                .rsplit_once('.')
                .is_some_and(|(_, m)| validators.contains(format!("*.{m}").as_str()))
    };
    index
        .callees()
        .filter(|(_, callee)| validates(callee))
        .map(|(c, _)| (c.range(), true, 0))
        .collect()
}
