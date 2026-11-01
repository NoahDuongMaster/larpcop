//! Lists filled and read by position in straight-line code:
//! `l.add("safe"); l.add(param); l.remove(0); bar = l.get(1)` reads `"safe"`'s
//! neighbour, not `param`. A list used any other way (passed on, iterated,
//! changed in a branch or loop) stays one tainted whole.

use super::paths::CONDITIONAL;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use std::collections::HashMap;

type Key = (usize, usize);

fn key<D: Doc>(n: &Node<D>) -> Key {
    let r = n.range();
    (r.start, r.end)
}

/// Reads of known lists → the value at that position (`None`: past the end).
pub(super) struct Lists<'a, D: Doc> {
    reads: HashMap<Key, Option<Node<'a, D>>>,
}

enum Op<'a, D: Doc> {
    Push(Node<'a, D>),
    Insert(usize, Node<'a, D>),
    Remove(Option<i64>),
    Shift,
    Read(Key, i64),
}

impl<'a, D: Doc> Lists<'a, D> {
    pub fn of(scope: &Node<'a, D>) -> Self {
        let mut reads = HashMap::new();
        let mut nodes = Vec::new();
        collect(scope, &mut nodes);
        for (name, init) in created(&nodes) {
            let Some(ops) = ops(&nodes, &name, &init, scope) else {
                continue;
            };
            let mut items: Vec<Node<D>> = init.children().filter(|c| c.is_named()).collect();
            if init.kind() != "list" && init.kind() != "array" {
                items.clear();
            }
            for op in ops {
                match op {
                    Op::Push(v) => items.push(v),
                    Op::Insert(i, v) if i <= items.len() => items.insert(i, v),
                    Op::Remove(Some(i)) => {
                        let Some(i) = index(i, items.len()) else {
                            break;
                        };
                        items.remove(i);
                    }
                    Op::Remove(None) => {
                        items.pop();
                    }
                    Op::Shift if !items.is_empty() => {
                        items.remove(0);
                    }
                    Op::Read(at, i) => {
                        reads.insert(at, index(i, items.len()).map(|i| items[i].clone()));
                    }
                    _ => break,
                }
            }
        }
        Lists { reads }
    }

    /// The value a read of a known list gets, or the read itself.
    pub fn resolve(&self, n: Node<'a, D>) -> Node<'a, D> {
        match self.reads.get(&key(&n)) {
            Some(Some(v)) => v.clone(),
            _ => n,
        }
    }
}

fn index(i: i64, len: usize) -> Option<usize> {
    let i = if i < 0 { len as i64 + i } else { i };
    usize::try_from(i).ok().filter(|i| *i < len)
}

fn collect<'a, D: Doc>(n: &Node<'a, D>, out: &mut Vec<Node<'a, D>>) {
    for c in n.children() {
        if !is_function(&c) {
            out.push(c.clone());
            collect(&c, out);
        }
    }
}

/// `l = []`, `List<String> l = new ArrayList<>()`, `const l = []`.
fn created<'a, D: Doc>(nodes: &[Node<'a, D>]) -> Vec<(String, Node<'a, D>)> {
    nodes
        .iter()
        .filter_map(|n| {
            let (name, value) = match n.kind().as_ref() {
                "assignment" => (n.field("left")?, n.field("right")?),
                "variable_declarator" => (n.field("name")?, n.field("value")?),
                _ => return None,
            };
            let new_list = matches!(value.kind().as_ref(), "list" | "array")
                || (value.kind() == "object_creation_expression"
                    && value.field("type").is_some_and(|t| {
                        let t = t.text();
                        t.contains("ArrayList") || t.contains("LinkedList")
                    })
                    && value.field("arguments").is_some_and(|a| a.text() == "()"));
            (name.kind() == "identifier" && new_list).then(|| (name.text().to_string(), value))
        })
        .collect()
}

/// Every use of the list `name` after its creation, in order; `None` when
/// one is not understood or may not run.
fn ops<'a, D: Doc>(
    nodes: &[Node<'a, D>],
    name: &str,
    init: &Node<'a, D>,
    scope: &Node<'a, D>,
) -> Option<Vec<Op<'a, D>>> {
    let mut out = Vec::new();
    let uses = nodes
        .iter()
        .filter(|n| n.kind() == "identifier" && n.text() == name);
    for u in uses {
        // The creation itself.
        if u.parent().is_some_and(|p| {
            p.field("value")
                .or_else(|| p.field("right"))
                .is_some_and(|v| v.range() == init.range())
        }) {
            if u.range().start > init.range().start {
                return None;
            }
            continue;
        }
        if u.range().end < init.range().start {
            return None;
        }
        // In the creation's own branch: no branch or loop of its own.
        if branches(u, scope) != branches(init, scope) {
            return None;
        }
        out.push(op(u)?);
    }
    Some(out)
}

/// The branches and loops `n` is in, up to `scope`.
fn branches<D: Doc>(n: &Node<D>, scope: &Node<D>) -> Vec<Key> {
    n.ancestors()
        .take_while(|a| a.range() != scope.range())
        .filter(|a| CONDITIONAL.contains(&a.kind().as_ref()))
        .map(|a| key(&a))
        .collect()
}

fn op<'a, D: Doc>(u: &Node<'a, D>) -> Option<Op<'a, D>> {
    let parent = u.parent()?;
    let int = |n: &Node<D>| -> Option<i64> {
        let t = n.text();
        let t = t.trim();
        t.parse().ok()
    };
    // `l[1]`
    if parent.kind() == "subscript" || parent.kind() == "subscript_expression" {
        let index = parent.children().filter(|c| c.is_named()).nth(1)?;
        return Some(Op::Read(key(&parent), int(&index)?));
    }
    // `l.add(x)` (Java: the call holds the name), `l.append(x)` (Python/JS: through an attribute).
    let call = if parent.kind() == "method_invocation" {
        parent.clone()
    } else if matches!(parent.kind().as_ref(), "attribute" | "member_expression") {
        parent
            .parent()
            .filter(|c| c.kind() == "call" || c.kind() == "call_expression")?
    } else {
        return None;
    };
    let method = call
        .field("name")
        .or_else(|| parent.field("attribute"))
        .or_else(|| parent.field("property"))?;
    let args: Vec<Node<D>> = call
        .field("arguments")?
        .children()
        .filter(|c| c.is_named())
        .collect();
    // The call's own value must not be used (`x = l.pop(0)` reads too).
    let statement = call
        .parent()
        .is_some_and(|p| p.kind() == "expression_statement");
    Some(match (method.text().as_ref(), args.as_slice()) {
        ("add" | "append" | "push", [v]) if statement => Op::Push(v.clone()),
        ("add" | "insert", [i, v]) if statement => {
            Op::Insert(usize::try_from(int(i)?).ok()?, v.clone())
        }
        ("remove" | "pop", [i]) if statement => Op::Remove(Some(int(i)?)),
        ("pop", []) if statement => Op::Remove(None),
        ("shift", []) if statement => Op::Shift,
        ("get", [i]) => Op::Read(key(&call), int(i)?),
        _ => return None,
    })
}
