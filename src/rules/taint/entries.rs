//! Entries of a map under a literal key: `m['b'] = x` taints `m['b']`, not
//! `m['a']`; `m.put("b", x)` then `m.get("a")` is clean. Two literal keys
//! address one entry too: Python's `conf.set('s', 'b', x)` /
//! `conf.get('s', 'a')`. Reading the whole map (`m`, `str(m)`) still sees
//! every tainted entry.

use super::kotlin::Part;
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
        let member = n.part("function");
        let member = member.as_ref().unwrap_or(n);
        let method = member
            .part("property")
            .or_else(|| member.part("name"))
            .or_else(|| member.part("attribute"))?;
        let method = method.text();
        // `m.get(k)` reads, `m.put(k, v)` writes; `Paths.get("/srv", x)` is
        // neither (a class, and more arguments).
        let keys = if READS.contains(&method.as_ref()) {
            1
        } else if WRITES.contains(&method.as_ref()) {
            0
        } else {
            return None;
        };
        let object = member.part("object")?;
        let all = args(n);
        if object.text().starts_with(char::is_uppercase) {
            return None;
        }
        // Reads: one key, or two literals (`conf.get('s', 'k')`); writes: the
        // keys before the value (`m.put(k, v)`, `conf.set('s', 'k', v)`).
        let keyed: Vec<Node<D>> = match (keys, all.len()) {
            (1, 1) => all,
            (1, 2) if all.iter().all(|a| literal(a).is_some()) => all,
            (0, 2 | 3) => all[..all.len() - 1].to_vec(),
            _ => return None,
        };
        let key = keyed
            .iter()
            .map(|k| literal(k))
            .collect::<Option<Vec<String>>>()?
            .join(SEPARATOR);
        return (object.kind() == "identifier" || object.kind() == "variable_name")
            .then(|| format!("{}[{key}]", object.text()));
    } else {
        return None;
    };
    let key = literal(&key)?;
    (base.kind() == "identifier" || base.kind() == "variable_name")
        .then(|| format!("{}[{key}]", base.text()))
}

/// Between the keys of an entry addressed by two (`conf[s␁k]`).
const SEPARATOR: &str = "\u{1}";

/// The entries a read may get: `d.get('k', 'default')` is `d[k]` for a dict,
/// `d[k␁default]` for a config parser.
pub(super) fn read_as(entry: &str) -> Vec<String> {
    let mut out = vec![entry.to_string()];
    if let Some((first, _)) = entry.split_once(SEPARATOR) {
        out.push(format!("{first}]"));
    }
    out
}

/// The value a write-like call stores (`m.put("k", v)`: `v`).
pub(super) fn stored<'a, D: Doc>(call: &Node<'a, D>) -> Option<Node<'a, D>> {
    let text = call.text();
    if !WRITES.iter().any(|w| text.contains(w)) {
        return None;
    }
    let member = call.part("function");
    let member = member.as_ref().unwrap_or(call);
    let method = member
        .part("property")
        .or_else(|| member.part("name"))
        .or_else(|| member.part("attribute"))?;
    if !WRITES.contains(&method.text().as_ref()) {
        return None;
    }
    let all = args(call);
    (2..=3)
        .contains(&all.len())
        .then(|| all.into_iter().last())
        .flatten()
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
