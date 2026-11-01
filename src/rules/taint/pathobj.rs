//! Path objects used on the file system: `p.read_text()`, `p.exists()` where
//! `p` is provably a path object (rule's `path_objects`): built by a matching
//! constructor (`pathlib.Path(…)`), joined from one (`base / name`,
//! `base.joinpath(name)`), derived from one (`.resolve()`, `.parent`), or a
//! parameter annotated with the type. The receiver is the sink, so a check
//! made after the join (`p.resolve().is_relative_to(BASE)`) guards the use.
//! `exists()` on anything else (a Django queryset) is not one.

use super::kotlin::Part;
use super::scan::FileIndex;
use super::summary::callee;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use regex::Regex;

pub(crate) struct PathObjects {
    /// Regex over a constructor's callee: `^(pathlib\.)?Path$`.
    pub types: Regex,
    /// Regex over the method names that touch the file system.
    pub uses: Regex,
}

/// Methods and attributes of a path that give a path.
const DERIVED: [&str; 10] = [
    "resolve",
    "absolute",
    "expanduser",
    "joinpath",
    "with_name",
    "with_suffix",
    "with_stem",
    "relative_to",
    "parent",
    "readlink",
];
const DEPTH: usize = 6;

impl PathObjects {
    /// (call start, receiver) for each use of a path object.
    pub(super) fn sinks<'a, D: Doc>(&self, index: &FileIndex<'a, D>) -> Vec<(usize, Node<'a, D>)> {
        let mut out = Vec::new();
        for call in index.calls() {
            let Some(f) = call.part("function").filter(|f| f.kind() == "attribute") else {
                continue;
            };
            let (Some(object), Some(name)) = (f.part("object"), f.part("attribute")) else {
                continue;
            };
            if self.uses.is_match(&name.text()) && self.is_path(&object, call.range().start, 0) {
                out.push((call.range().start, object));
            }
        }
        out
    }

    fn is_path<D: Doc>(&self, n: &Node<D>, before: usize, depth: usize) -> bool {
        if depth > DEPTH {
            return false;
        }
        let next = |m: &Node<D>| self.is_path(m, before, depth + 1);
        match n.kind().as_ref() {
            "parenthesized_expression" => n
                .children()
                .find(|c| c.is_named())
                .is_some_and(|c| next(&c)),
            "binary_operator" => {
                n.part("operator").is_some_and(|o| o.text() == "/")
                    && n.part("left").is_some_and(|l| next(&l))
            }
            "attribute" => {
                n.part("attribute")
                    .is_some_and(|a| DERIVED.contains(&a.text().as_ref()))
                    && n.part("object").is_some_and(|o| next(&o))
            }
            "call" => {
                if callee(n).is_some_and(|c| self.types.is_match(&c)) {
                    return true;
                }
                n.part("function")
                    .is_some_and(|f| f.kind() == "attribute" && next(&f))
            }
            "identifier" => self.named_path(n, before, depth),
            _ => false,
        }
    }

    /// A name assigned a path in its function (or the module), or a
    /// parameter annotated with a path type.
    fn named_path<D: Doc>(&self, n: &Node<D>, before: usize, depth: usize) -> bool {
        let name = n.text();
        let scope = n.ancestors().find(|a| is_function(a));
        if let Some(f) = &scope
            && let Some(params) = f.part("parameters")
            && params.children().any(|p| {
                matches!(
                    p.kind().as_ref(),
                    "typed_parameter" | "typed_default_parameter"
                ) && p
                    .children()
                    .any(|c| c.kind() == "identifier" && c.text() == name)
                    && p.part("type")
                        .is_some_and(|t| self.types.is_match(t.text().trim()))
            })
        {
            return true;
        }
        let module = n.ancestors().last();
        let local = scope.iter().map(|s| (s.clone(), true));
        local.chain(module.map(|m| (m, false))).any(|(s, local)| {
            s.dfs().any(|a| {
                a.kind() == "assignment"
                    && a.range().start < before
                    // In the module: its own assignments, not its functions'.
                    && (local || !a.ancestors().any(|x| is_function(&x)))
                    && a.part("left").is_some_and(|l| l.text() == name)
                    && (a.part("type").is_some_and(|t| self.types.is_match(t.text().trim()))
                        || a.part("right").is_some_and(|r| self.is_path(&r, before, depth + 1)))
            })
        })
    }
}
