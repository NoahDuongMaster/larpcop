//! `safe_prefix:` a sink argument built as `"<literal>" + x` or `` `<literal>${x}` ``
//! whose fixed start matches the regex is safe: `res.redirect("/products/" + id)`
//! cannot leave the site, `fetch("https://api.example.com/" + id)` cannot pick the host.

use ast_grep_core::{Doc, Node};

/// String literal kinds: JS/TS/Python, Go, Rust.
const STRINGS: [&str; 5] = [
    "string",
    "template_string",
    "interpreted_string_literal",
    "raw_string_literal",
    "string_literal",
];

/// The fixed text an argument starts with, if it starts with a literal.
pub(super) fn leading<D: Doc>(node: &Node<D>) -> Option<String> {
    match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => leading(&node.field("left")?),
        "parenthesized_expression" => leading(&node.child(1)?),
        // C# and PHP wrap each call argument.
        "argument" => leading(&node.children().filter(|c| c.is_named()).last()?),
        "raw_string_literal" => Some(node.text().trim_matches('`').to_string()),
        k if STRINGS.contains(&k) => {
            let mut fixed = String::new();
            for c in node.children() {
                match c.kind().as_ref() {
                    "string_fragment"
                    | "string_content"
                    | "string_literal_content"
                    | "interpreted_string_literal_content" => fixed.push_str(&c.text()),
                    "template_substitution" | "interpolation" => break,
                    _ => {}
                }
            }
            Some(fixed)
        }
        _ => None,
    }
}

/// The first operand of a built value: `reverse(…)` in `reverse(…) + "?q=" + q`.
pub(super) fn leftmost<'a, D: Doc>(node: &Node<'a, D>) -> Node<'a, D> {
    let inner = match node.kind().as_ref() {
        "binary_expression" | "binary_operator" => node.field("left"),
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
        .field("object")
        .or_else(|| guard.field("function").and_then(|f| f.field("object")))
}

const NORMALIZING: &str = r"(?i)(normalize|canonical|realpath|abspath|normpath|toRealPath|resolve|getFullPath|expand_path|cleanpath|filepath\.(Clean|Abs)|\.Clean\()";

/// Is `value` a normalized path, or a name assigned one in its function?
fn normalized<D: Doc>(value: &Node<D>) -> bool {
    static RE: std::sync::LazyLock<regex::Regex> =
        std::sync::LazyLock::new(|| regex::Regex::new(NORMALIZING).expect("regex"));
    if RE.is_match(&value.text()) {
        return true;
    }
    if value.kind() != "identifier" {
        return false;
    }
    let name = value.text();
    let Some(f) = value
        .ancestors()
        .find(|a| crate::rules::complexity::is_function(a))
    else {
        return false;
    };
    f.dfs().any(|n| {
        let (left, right) = match n.kind().as_ref() {
            "variable_declarator" => (n.field("name"), n.field("value")),
            "assignment" | "assignment_expression" | "short_var_declaration" => {
                (n.field("left"), n.field("right"))
            }
            _ => return false,
        };
        left.is_some_and(|l| l.text() == name) && right.is_some_and(|r| RE.is_match(&r.text()))
    })
}
