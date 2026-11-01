//! Containers hold what was put in: `list.push(x)`, `map.set(k, x)`,
//! `Object.assign(o, x)` make the container carry `x`.

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

/// The variable a call stores its arguments in: the receiver of a filling
/// method, or the first argument of `Object.assign`.
pub(super) fn filled<D: Doc>(call: &Node<D>) -> Option<String> {
    let Some(name) = callee(call) else {
        return chained(call);
    };
    if name == "Object.assign" {
        let target = args(call).into_iter().next()?;
        return (target.kind() == "identifier").then(|| target.text().to_string());
    }
    let (receiver, method) = name.rsplit_once('.')?;
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
    let object = call.part("object")?;
    let method = call.part("name")?;
    let method = method.text();
    let setter = method.len() > 3
        && method.starts_with("set")
        && method[3..].starts_with(char::is_uppercase);
    (setter && args(call).len() == 1 && built.contains(object.text().as_ref()))
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
