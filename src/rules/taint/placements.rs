//! Where an escaped value ends up decides whether the escaping protects it.
//! An HTML escaper does not in a script, a style, an unquoted attribute or
//! a URL (contexts.rs); a quote escaper (a rule's `quote_escapers`, a regex
//! over the call: `mysqli_real_escape_string(`, `addslashes(`) only inside a
//! quoted string:
//! `"… WHERE id=" . esc($id)` needs no quote to inject. The text before the
//! value is read where the call is used, or, when its result is assigned to
//! a local (`$t = esc($x);`), where that local is read before it is written
//! again. A place that cannot be read does not count.

use super::NAMES;
use super::constant::Env;
use super::contexts::{html_escaper, prefix, unsafe_context};
use super::flow::assignment;
use crate::rules::complexity::is_function;
use ast_grep_core::{Doc, Node};
use regex::Regex;

/// Is sanitizer match `n` used where its escaping does not protect?
pub(super) fn misplaced<D: Doc>(n: &Node<D>, html: bool, quotes: Option<&(Regex, String)>) -> bool {
    let html = html && html_escaper(n);
    let quote = quotes.filter(|(re, _)| re.is_match(&n.text()));
    if !html && quote.is_none() {
        return false;
    }
    let before = placements(n);
    (html && before.iter().any(|p| unsafe_context(&p.to_lowercase())))
        || quote.is_some_and(|(_, chars)| before.iter().any(|p| !inside_quotes(p, chars)))
}

/// The text before each place the value of `n` is put in.
fn placements<D: Doc>(n: &Node<D>) -> Vec<String> {
    let scope = n
        .ancestors()
        .find(|a| is_function(a))
        .or_else(|| n.ancestors().last())
        .unwrap_or_else(|| n.clone());
    let env = Env::new(&scope);
    let mut out = Vec::new();
    place(n, &scope, &env, 0, &mut out);
    out
}

/// Where the value of `n` is put: the text before it, or, when it is
/// assigned to a local (`$s = esc($x);`, and copied on: `$t = $s;`), the
/// places that local is read before it is written again.
fn place<'a, D: Doc>(
    n: &Node<'a, D>,
    scope: &Node<'a, D>,
    env: &Env<'a, D>,
    depth: usize,
    out: &mut Vec<String>,
) {
    if let Some(p) = prefix(n, env) {
        out.push(p);
        return;
    }
    let Some((left, right)) = n.parent().and_then(|p| assignment(&p)) else {
        return;
    };
    if depth > 3 || right.range() != n.range() || !NAMES.contains(&left.kind().as_ref()) {
        return;
    }
    let name = left.text();
    let after = n.parent().map_or(n.range().end, |p| p.range().end);
    let writes = |d: &Node<D>| assignment(d).is_some_and(|(l, _)| l.text() == name);
    let next = scope
        .dfs()
        .filter(|d| d.range().start >= after && writes(d))
        .map(|d| d.range().start)
        .min()
        .unwrap_or(usize::MAX);
    let reads = scope.dfs().filter(|d| {
        NAMES.contains(&d.kind().as_ref())
            && d.text() == name
            && (after..next).contains(&d.range().start)
    });
    for read in reads {
        place(&read, scope, env, depth + 1, out);
    }
}

/// Does text `before` end inside a string quoted with one of `chars`?
fn inside_quotes(before: &str, chars: &str) -> bool {
    let (mut quote, mut escaped) = (None, false);
    for c in before.chars() {
        match (c, quote) {
            _ if escaped => escaped = false,
            ('\\', Some(_)) => escaped = true,
            ('\'' | '"' | '`', None) => quote = Some(c),
            (c, Some(q)) if c == q => quote = None,
            _ => {}
        }
    }
    quote.is_some_and(|q| chars.contains(q))
}

#[cfg(test)]
mod tests {
    use super::inside_quotes;

    #[test]
    fn quotes_left_open() {
        let all = "'\"`";
        assert!(inside_quotes("SELECT * FROM t WHERE name='", all));
        assert!(!inside_quotes("SELECT * FROM t WHERE id=", all));
        assert!(!inside_quotes("WHERE a='x' AND id=", all));
        assert!(inside_quotes("WHERE a=\"it's ", all));
        assert!(inside_quotes("WHERE a='\\' ", all));
        assert!(!inside_quotes("$a = \"", "'"));
    }
}
