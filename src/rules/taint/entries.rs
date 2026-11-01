//! Entries of a map under a literal key: `m['b'] = x` taints `m['b']`, not
//! `m['a']`; `m.put("b", x)` then `m.get("a")` is clean. Reading the whole
//! map (`m`, `str(m)`) still sees every tainted entry.

use super::summary::args;
use ast_grep_core::{Doc, Node};

const SUBSCRIPTS: [&str; 6] = [
    "subscript",
    "subscript_expression",
    "element_reference",
    "element_access_expression",
    "index_expression",
    "array_access",
];
/// Calls that read or write one entry, by name; the key is the first argument.
const READS: [&str; 4] = ["get", "getOrDefault", "getProperty", "get_item"];
const WRITES: [&str; 6] = ["put", "set", "putIfAbsent", "setdefault", "Add", "TryAdd"];

/// `m[k]` for a subscript or a get/put-like call on a plain name with a
/// literal key; `None` for anything else.
pub(super) fn entry<D: Doc>(n: &Node<D>) -> Option<String> {
    let kind = n.kind();
    let (base, key) = if SUBSCRIPTS.contains(&kind.as_ref()) {
        let named: Vec<Node<D>> = n.children().filter(|c| c.is_named()).collect();
        (named.first()?.clone(), named.get(1)?.clone())
    } else if super::flow::CALLS.contains(&kind.as_ref()) {
        let text = n.text();
        if !READS.iter().chain(WRITES.iter()).any(|w| text.contains(w)) {
            return None;
        }
        let member = n.field("function");
        let member = member.as_ref().unwrap_or(n);
        let method = member.field("property").or_else(|| member.field("name"))?;
        let method = method.text();
        // `m.get(k)` reads, `m.put(k, v)` writes; `Paths.get("/srv", x)` is
        // neither (a class, and more arguments).
        let arity = if READS.contains(&method.as_ref()) {
            1
        } else if WRITES.contains(&method.as_ref()) {
            2
        } else {
            return None;
        };
        let object = member.field("object")?;
        let all = args(n);
        if all.len() != arity || object.text().starts_with(char::is_uppercase) {
            return None;
        }
        (object, all.into_iter().next()?)
    } else {
        return None;
    };
    let key = literal(&key)?;
    (base.kind() == "identifier" || base.kind() == "variable_name")
        .then(|| format!("{}[{key}]", base.text()))
}

/// The value a write-like call stores (`m.put("k", v)`: `v`).
pub(super) fn stored<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    let text = call.text();
    if !WRITES.iter().any(|w| text.contains(w)) {
        return None;
    }
    let member = call.field("function");
    let member = member.as_ref().unwrap_or(call);
    let method = member.field("property").or_else(|| member.field("name"))?;
    if !WRITES.contains(&method.text().as_ref()) {
        return None;
    }
    args(call).into_iter().nth(1)
}

/// Does `name` (a whole map) hold a tainted entry?
pub(super) fn holds_tainted(name: &str, names: &std::collections::HashSet<String>) -> bool {
    let prefix = format!("{name}[");
    names.iter().any(|n| n.starts_with(&prefix))
}

/// The text of a string literal without its quotes; numbers as written.
fn literal<D: Doc>(n: &Node<D>) -> Option<String> {
    let inner = if n.kind() == "argument" {
        n.children().find(|c| c.is_named())?
    } else {
        n.clone()
    };
    let text = inner.text();
    let kind = inner.kind();
    let quoted = kind.contains("string") && !text.contains(['{', '$', '#']);
    let number = matches!(
        kind.as_ref(),
        "integer" | "decimal_integer_literal" | "number"
    );
    (quoted || number).then(|| text.trim_matches(['"', '\'', '`']).to_string())
}
