//! Containers hold what was put in: `list.push(x)`, `map.set(k, x)`,
//! `Object.assign(o, x)` make the container carry `x`. Streams too:
//! `out.writeObject(x)`, C# `formatter.Serialize(stream, x)`; and a stream
//! built around another (`new ObjectOutputStream(bytes)`) writes into it, so
//! `bytes.toByteArray()` carries what was serialized.

use super::kotlin::Part;
use super::summary::{args, callee};
use ast_grep_core::{Doc, Node};

/// Methods that store their arguments in the object they are called on,
/// lowercased: C#'s `Add`/`AddLast`/`Enqueue`, Java's `put`/`offer` too.
const FILLS: [&str; 22] = [
    "addlast",
    "addfirst",
    "addall",
    "addrange",
    "put",
    "putall",
    "putifabsent",
    "offer",
    "enqueue",
    "tryadd",
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

/// Stream writes, on a stream named in the scope (not `response.getWriter()`).
const WRITES: [&str; 5] = [
    "write",
    "writeobject",
    "writeutf",
    "writebytes",
    "writechars",
];

/// The variable a call stores its arguments in: the receiver of a filling
/// method, or the first argument of `Object.assign` and of a `Serialize`.
pub(super) fn filled<D: Doc>(call: &Node<D>) -> Option<String> {
    let Some(name) = callee(call) else {
        return chained(call);
    };
    let first_arg = || first_name(call);
    if name == "Object.assign" {
        return first_arg();
    }
    let (receiver, method) = name.rsplit_once('.')?;
    let lower = method.to_lowercase();
    if lower == "serialize" {
        return first_arg();
    }
    if WRITES.contains(&lower.as_str()) {
        let plain = receiver.chars().all(|c| c.is_alphanumeric() || c == '_');
        return plain.then(|| receiver.to_string());
    }
    let root = receiver.split(['.', '[']).next()?;
    (FILLS.contains(&method.to_lowercase().as_str())
        && !root.is_empty()
        && root
            .chars()
            .all(|c| c.is_alphanumeric() || c == '_' || c == '$'))
    .then(|| root.to_string())
}

/// `order.setNote(x)` on an object the scope built: the object holds `x`.
pub(super) fn set_on<D: Doc>(
    call: &Node<D>,
    built: &std::collections::HashSet<String>,
) -> Option<String> {
    if built.is_empty() {
        return None;
    }
    setter_object(call).filter(|o| built.contains(o))
}

/// The object a one-argument setter is called on (`order.setNote(x)`).
pub(super) fn setter_object<D: Doc>(call: &Node<D>) -> Option<String> {
    let object = call.part("object")?;
    let method = call.part("name")?;
    let method = method.text();
    let setter = method.len() > 3
        && method.starts_with("set")
        && method[3..].starts_with(char::is_uppercase);
    (setter && args(call).len() == 1 && object.kind() == "identifier")
        .then(|| object.text().to_string())
}

/// `headers.get("Location").add(x)`: the variable at the root of the
/// receiver chain holds what the call stores.
fn chained<D: Doc>(call: &Node<D>) -> Option<String> {
    let member = call.part("function");
    let member = member.as_ref().unwrap_or(call);
    let method = member.part("name").or_else(|| member.part("property"))?;
    if !FILLS.contains(&method.text().to_lowercase().as_str()) {
        return None;
    }
    let mut object = member.part("object")?;
    loop {
        let inner = object
            .part("function")
            .and_then(|f| f.part("object"))
            .or_else(|| object.part("object"));
        match inner {
            Some(i) => object = i,
            None => break,
        }
    }
    (object.kind() == "identifier").then(|| object.text().to_string())
}

/// Is `call` a stream write or a serialization (`out.writeObject(x)`,
/// `formatter.Serialize(ms, x)`)?
pub(super) fn writes<D: Doc>(call: &Node<D>) -> bool {
    callee(call)
        .and_then(|c| c.rsplit('.').next().map(str::to_lowercase))
        .is_some_and(|m| m == "serialize" || WRITES.contains(&m.as_str()))
}

/// The streams `name` was built around in the function of `at`, innermost
/// last: `out = new ObjectOutputStream(bytes)` gives `bytes`. Only stream
/// and writer types count.
pub(super) fn wrapped<D: Doc>(at: &Node<D>, name: &str) -> Vec<String> {
    let Some(f) = at
        .ancestors()
        .find(|a| crate::rules::complexity::is_function(a))
    else {
        return Vec::new();
    };
    let mut out: Vec<String> = Vec::new();
    let mut current = name.to_string();
    for _ in 0..4 {
        let inner = f.dfs().find_map(|n| {
            let (left, right) = super::flow::assignment(&n)?;
            if left.text() != current
                || !matches!(
                    right.kind().as_ref(),
                    "object_creation_expression" | "new_expression"
                )
            {
                return None;
            }
            // Only streams and writers pass writes on (`new Cookie(name, v)`
            // does not write into `name`).
            let ty = right
                .part("type")
                .or_else(|| right.part("constructor"))?
                .text()
                .to_lowercase();
            let ty = ty.split('<').next().unwrap_or_default();
            if !(ty.ends_with("stream") || ty.ends_with("writer")) {
                return None;
            }
            first_name(&right)
        });
        match inner {
            Some(i) if !out.contains(&i) && i != name => {
                out.push(i.clone());
                current = i;
            }
            _ => break,
        }
    }
    out
}

/// The first argument of a call when it is a plain name (C# wraps each
/// argument in an `argument` node).
fn first_name<D: Doc>(call: &Node<D>) -> Option<String> {
    let first = args(call).into_iter().next()?;
    let inner = (first.kind() == "argument")
        .then(|| first.children().find(|c| c.is_named()))
        .flatten();
    let target = inner.unwrap_or(first);
    (target.kind() == "identifier").then(|| target.text().to_string())
}
