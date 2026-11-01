//! `safe_prefix:` a sink argument built as `"<literal>" + x` or `` `<literal>${x}` ``
//! whose fixed start matches the regex is safe: `res.redirect("/products/" + id)`
//! cannot leave the site, `fetch("https://api.example.com/" + id)` cannot pick the host.

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::collections::HashSet;

/// String literal kinds: JS/TS/Python, Go, Rust, PHP `"…"`.
const STRINGS: [&str; 6] = [
    "string",
    "template_string",
    "interpreted_string_literal",
    "raw_string_literal",
    "string_literal",
    "encapsed_string",
];

/// Text kinds inside a string literal; any other named child but an escape
/// is an interpolation (`${x}`, `#{x}`, `$x` in Kotlin and PHP), where the
/// fixed text ends.
const CONTENT: [&str; 5] = [
    "string_fragment",
    "string_content",
    "string_literal_content",
    "interpreted_string_literal_content",
    "escape_sequence",
];

/// Delimiters some grammars name (Python).
const DELIMITERS: [&str; 2] = ["string_start", "string_end"];

/// The fixed text an argument starts with, if it starts with a literal.
pub(super) fn leading<D: Doc>(node: &Node<D>) -> Option<String> {
    match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => leading(&node.part("left")?),
        "parenthesized_expression" => leading(&node.child(1)?),
        // C# and PHP wrap each call argument.
        "argument" => leading(&node.children().filter(|c| c.is_named()).last()?),
        "raw_string_literal" => Some(node.text().trim_matches('`').to_string()),
        k if STRINGS.contains(&k) => Some(literal(node).0),
        _ => None,
    }
}

/// A literal's text up to its first interpolation, and whether it has one.
fn literal<D: Doc>(node: &Node<D>) -> (String, bool) {
    let mut fixed = String::new();
    for c in node.children().filter(|c| c.is_named()) {
        match c.kind().as_ref() {
            k if CONTENT.contains(&k) => fixed.push_str(&c.text()),
            k if DELIMITERS.contains(&k) => {}
            _ => return (fixed, true),
        }
    }
    (fixed, false)
}

/// Does a URL built from `node` start safely: its fixed start (literals and
/// constants joined, up to the first other part) matches `safe`, or has a
/// `?` or `#`, after which the rest only picks the query or the fragment?
pub(super) fn safe_start<D: Doc>(safe: &regex::Regex, node: &Node<D>) -> bool {
    let mut text = String::new();
    fixed(node, &mut text);
    let known = text.split(CONSTANT).next().unwrap_or_default();
    (!known.is_empty() && safe.is_match(known)) || text.contains(['?', '#'])
}

/// Stands for a constant's unknown text in a fixed start.
const CONSTANT: char = '\u{1}';

/// Appends the fixed start of `node`; false once a part is not fixed.
fn fixed<D: Doc>(node: &Node<D>, text: &mut String) -> bool {
    let kind = node.kind();
    match kind.as_ref() {
        "binary_expression" | "binary_operator"
            if node
                .field("operator")
                .is_some_and(|o| matches!(o.text().as_ref(), "+" | "."))
                || node
                    .children()
                    .any(|c| !c.is_named() && matches!(c.text().as_ref(), "+" | ".")) =>
        {
            node.part("left").is_some_and(|l| fixed(&l, text))
                && node.part("right").is_some_and(|r| fixed(&r, text))
        }
        "parenthesized_expression" => node.child(1).is_some_and(|c| fixed(&c, text)),
        "argument" => node
            .children()
            .filter(|c| c.is_named())
            .last()
            .is_some_and(|c| fixed(&c, text)),
        "raw_string_literal" => {
            text.push_str(node.text().trim_matches('`'));
            true
        }
        k if STRINGS.contains(&k) => {
            let (part, interpolated) = literal(node);
            text.push_str(&part);
            !interpolated
        }
        // `Pictures::$VIEW_PIC_URL`, `self::BASE`, `BASE_URL`: set by the code.
        "class_constant_access_expression" | "scoped_property_access_expression" => {
            text.push(CONSTANT);
            true
        }
        _ if is_constant_name(&node.text()) => {
            text.push(CONSTANT);
            true
        }
        _ => false,
    }
}

/// `BASE_URL`, `Config.BASE_URL`, `Routes::HOME`.
fn is_constant_name(text: &str) -> bool {
    let last = text.rsplit(['.', ':']).next().unwrap_or_default();
    last.len() > 1
        && last.starts_with(|c: char| c.is_ascii_uppercase())
        && last
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':'))
}

/// The first operand of a built value: `reverse(…)` in `reverse(…) + "?q=" + q`.
pub(super) fn leftmost<'a, D: Doc>(node: &Node<'a, D>) -> Node<'a, D> {
    let inner = match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => node.part("left"),
        "parenthesized_expression" => node.child(1),
        "argument" => node.children().filter(|c| c.is_named()).last(),
        _ => None,
    };
    inner.map_or_else(|| node.clone(), |n| leftmost(&n))
}

/// A guard `x.startsWith("<literal>")` only proves anything when the literal
/// is (the beginning of) a safe start: `startsWith("/")` keeps a redirect on
/// the site, `startsWith("http")` does not. Other guards are kept as they are.
pub(super) fn guard_holds<D: Doc>(guard: &Node<D>, safe: Option<&regex::Regex>) -> bool {
    if !super::flow::CALLS.contains(&guard.kind().as_ref()) {
        return true;
    }
    let Some(name) = super::summary::callee(guard).or_else(|| {
        // `file.getCanonicalPath().startsWith(base)`: a chain has no plain callee.
        let method = super::summary::called_name(guard)?;
        Some(format!("x.{method}"))
    }) else {
        return true;
    };
    // Go's strings.HasPrefix(s, prefix) takes the prefix second.
    let at = match name.as_str() {
        n if n.ends_with(".startsWith")
            || n.ends_with(".startswith")
            || n.ends_with(".starts_with")
            || n.ends_with(".StartsWith")
            || n.ends_with(".start_with?") =>
        {
            0
        }
        "strings.HasPrefix" | "bytes.HasPrefix" => 1,
        _ => return true,
    };
    let literal = super::summary::args(guard).into_iter().nth(at);
    let Some(lit) = literal.filter(|a| STRINGS.contains(&a.kind().as_ref())) else {
        return true;
    };
    match safe {
        // The checked start may end where the safe part begins (`"/"` + a path).
        Some(safe) => leading(&lit)
            .is_some_and(|start| safe.is_match(&start) || safe.is_match(&(start + "a"))),
        // A fixed directory proves a path stays in it only once `..` is
        // resolved: `canonical.startsWith("/srv/")`, not `name.startsWith("id=")`.
        None => checked(guard, at).is_some_and(|c| normalized(&c)),
    }
}

/// The value a prefix check looks at: the receiver, or Go's first argument.
fn checked<'a, D: Doc>(guard: &Node<'a, D>, literal_at: usize) -> Option<Node<'a, D>> {
    if literal_at == 1 {
        return super::summary::args(guard).into_iter().next();
    }
    guard
        .part("object")
        .or_else(|| guard.part("function").and_then(|f| f.part("object")))
}

const NORMALIZING: &str = r"(?i)(normalize|canonical|realpath|abspath|normpath|toRealPath|resolve|getFullPath|expand_path|cleanpath|filepath\.(Clean|Abs)|\.Clean\()";

static RE: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(NORMALIZING).expect("regex"));

/// Is `value` a normalized path, or a name assigned one in its function?
fn normalized<D: Doc>(value: &Node<D>) -> bool {
    RE.is_match(&value.text()) || !normalizing(value).is_empty()
}

/// The normalized paths a name is assigned in its function
/// (`Path p = Paths.get(BASE + f).normalize()`).
fn normalizing<'a, D: Doc>(value: &Node<'a, D>) -> Vec<Node<'a, D>> {
    if !matches!(value.kind().as_ref(), "identifier" | "simple_identifier") {
        return Vec::new();
    }
    let name = value.text();
    let Some(f) = value
        .ancestors()
        .find(|a| crate::rules::complexity::is_function(a))
    else {
        return Vec::new();
    };
    f.dfs()
        .filter_map(|n| super::flow::assignment(&n))
        .filter(|(l, r)| l.text() == name && RE.is_match(&r.text()))
        .map(|(_, r)| r)
        .collect()
}

/// A prefix check on a normalized path proves what the path was built from:
/// `normalizedTarget.startsWith(base)` with `normalizedTarget =
/// Paths.get(BASE + fileName).normalize()` keeps `fileName` inside `BASE`.
pub(super) fn derived<D: Doc>(guard: &Node<D>) -> HashSet<String> {
    let prefix_check = super::summary::called_name(guard).is_some_and(|m| {
        matches!(
            m.as_str(),
            "startsWith"
                | "startswith"
                | "starts_with"
                | "StartsWith"
                | "start_with?"
                | "HasPrefix"
        )
    });
    if !prefix_check {
        return HashSet::new();
    }
    let at = usize::from(super::summary::called_name(guard).as_deref() == Some("HasPrefix"));
    checked(guard, at)
        .map(|c| normalizing(&c))
        .unwrap_or_default()
        .iter()
        .flat_map(|r| super::guards::names(r))
        .collect()
}
