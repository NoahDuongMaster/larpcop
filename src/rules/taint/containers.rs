//! Containers hold what was put in: `list.push(x)`, `map.set(k, x)`,
//! `Object.assign(o, x)` make the container carry `x`.

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
    let name = callee(call)?;
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
