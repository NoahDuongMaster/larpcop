//! Static fields of another class read by a callee: `String data =
//! Case68a.data;` in `Case68b.badSink()` is an input of that method, like a
//! parameter. Its summary records the sinks such a field reaches; a caller
//! holding the field tainted at the call (`data = request.getParameter(…)` in
//! `Case68a`, or `Case68a.data = …` anywhere) reaches them there. A caller
//! that set it to a constant first (`data = "foo"`) does not. C globals
//! (`static char *badData;`, `extern char *badData;` at file scope) are read
//! the same way: `char *data = badData;` in the callee.

use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// `Cls[field]` for every `Cls.field` that `f` reads: a class (capitalized)
/// and a field that is not a constant (`HttpStatus.OK`, `MAX_SIZE`).
pub(super) fn read<D: Doc>(f: &Node<D>) -> Vec<String> {
    let mut out: Vec<String> = f
        .dfs()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "field_access" | "member_access_expression"
            )
        })
        .filter(|n| {
            // A write is not a read.
            !n.parent().is_some_and(|p| {
                super::flow::assignment(&p).is_some_and(|(l, _)| l.range() == n.range())
            })
        })
        .filter_map(|n| super::entries::entry(&n))
        .filter(|key| {
            let (class, field) = key.split_once('[').unwrap_or_default();
            class.chars().next().is_some_and(char::is_uppercase)
                && field.chars().next().is_some_and(char::is_lowercase)
        })
        .collect();
    out.extend(globals_read(f));
    out.sort();
    out.dedup();
    out
}

/// The C file-scope variables `f` reads and does not declare itself.
fn globals_read<D: Doc>(f: &Node<D>) -> Vec<String> {
    if f.kind() != "function_definition" {
        return Vec::new();
    }
    let Some(unit) = f.ancestors().find(|a| a.kind() == "translation_unit") else {
        return Vec::new();
    };
    let globals = file_scope(&unit);
    if globals.is_empty() {
        return Vec::new();
    }
    let own: HashSet<String> = f
        .dfs()
        .filter(|n| matches!(n.kind().as_ref(), "declaration" | "parameter_declaration"))
        .flat_map(|d| declared(&d))
        .collect();
    f.dfs()
        .filter(|n| n.kind() == "identifier")
        .map(|n| n.text().to_string())
        .filter(|n| globals.contains(n) && !own.contains(n))
        .collect()
}

/// Variables declared at file scope, through preprocessor blocks.
fn file_scope<D: Doc>(unit: &Node<D>) -> HashSet<String> {
    let mut out = HashSet::new();
    let mut stack: Vec<Node<D>> = unit.children().collect();
    while let Some(n) = stack.pop() {
        match n.kind().as_ref() {
            "declaration" => out.extend(declared(&n)),
            k if k.starts_with("preproc_if") || k == "preproc_else" || k == "preproc_elif" => {
                stack.extend(n.children())
            }
            _ => {}
        }
    }
    out
}

/// The variables a declaration declares: not the functions it prototypes.
fn declared<D: Doc>(d: &Node<D>) -> Vec<String> {
    d.field_children("declarator")
        .filter_map(|mut n| {
            loop {
                match n.kind().as_ref() {
                    "identifier" => return Some(n.text().to_string()),
                    "init_declarator"
                    | "pointer_declarator"
                    | "array_declarator"
                    | "parenthesized_declarator" => {
                        n = n.field("declarator").or_else(|| n.child(1))?
                    }
                    _ => return None,
                }
            }
        })
        .collect()
}

/// Does the caller hold `key` (`Cls[field]`) tainted at `call`: the entry
/// itself, or its own bare field when it is `Cls`?
pub(super) fn held<D: Doc>(call: &Node<D>, key: &str, names: &HashSet<String>) -> bool {
    if names.contains(key) {
        return true;
    }
    let Some((class, field)) = split(key) else {
        return false;
    };
    names.contains(field) && within(call, class)
}

/// `Cls[field]` as (`Cls`, `field`).
pub(super) fn split(key: &str) -> Option<(&str, &str)> {
    key.strip_suffix(']').and_then(|k| k.split_once('['))
}

/// Is `call` in a method of class `class`?
pub(super) fn within<D: Doc>(call: &Node<D>, class: &str) -> bool {
    call.ancestors()
        .find(|a| crate::rules::complexity::is_function(a))
        .and_then(|f| super::defs::class_of(&f))
        .is_some_and(|c| c == class)
}
