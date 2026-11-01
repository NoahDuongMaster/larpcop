//! HTML escaping protects element text and quoted attribute values only.
//! An escaped value placed in an unquoted attribute (`<img src=%s>`: a space
//! starts a new attribute, `onerror=…`), an event handler (`onclick="…"`), a
//! `<script>`/`<style>` block, or at the start of a URL attribute (`href="…"`:
//! `javascript:` needs no escaped character) is not made safe by it. The
//! text before the value is read from the concatenation, format string
//! (through local constants: `fmt = "<img src=%s>"; format(fmt, esc(x))`)
//! or template it is part of.

use super::constant::{Env, Value, eval};
use super::kotlin::Part;
use ast_grep_core::{Doc, Node};
use std::sync::LazyLock;

static PLACEHOLDER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"%%|%(\d+\$)?[-#+ 0]*\d*(\.\d+)?[a-zA-Z]|\{(\d*)[^{}]*\}").expect("regex")
});
static HANDLER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\son[a-z]+\s*=\s*("[^"]*|'[^']*|[^\s"'>]*)$"#).expect("regex")
});
static URL_START: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r#"\s(href|action|formaction|xlink:href)\s*=\s*["']?$"#).expect("regex")
});

const CONCATS: [&str; 3] = [
    "binary_expression",
    "binary_operator",
    "additive_expression",
];
const TEMPLATES: [&str; 5] = [
    "template_string",
    "string",
    "string_literal",
    "interpolated_string_expression",
    "encapsed_string",
];
const FORMATS: [&str; 7] = [
    "format",
    "formatted",
    "Sprintf",
    "sprintf",
    "Fprintf",
    "printf",
    "Format",
];

static HTML_ESCAPER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)html|^escape$|^h$|^e$|^esc$|escape_?html").expect("regex")
});
static OTHER_ESCAPER: LazyLock<regex::Regex> = LazyLock::new(|| {
    regex::Regex::new(r"(?i)attr|javascript|^js|url|uri|css|json|xml").expect("regex")
});

/// Is `call` an HTML (element text) escaper: `escapeHtml4`, `htmlEscape`,
/// `encodeForHTML`, `html.escape`, not `encodeForHTMLAttribute`?
pub(super) fn html_escaper<D: Doc>(call: &Node<D>) -> bool {
    super::summary::called_name(call)
        .is_some_and(|n| HTML_ESCAPER.is_match(&n) && !OTHER_ESCAPER.is_match(&n))
}

/// Is `escaped` (an HTML-escaping call) placed where HTML escaping does not
/// protect?
pub(super) fn misplaced<'a, D: Doc>(escaped: &Node<'a, D>, env: &Env<'a, D>) -> bool {
    prefix(escaped, env).is_some_and(|p| unsafe_context(&p.to_lowercase()))
}

/// The text before the value in the string it is put in, as far as known.
fn prefix<'a, D: Doc>(value: &Node<'a, D>, env: &Env<'a, D>) -> Option<String> {
    let mut cur = value.clone();
    for _ in 0..8 {
        let parent = cur.parent()?;
        let kind = parent.kind();
        match kind.as_ref() {
            "parenthesized_expression" | "argument" | "value_argument" => {}
            k if CONCATS.contains(&k) => {
                let (left, right) = (parent.part("left")?, parent.part("right")?);
                let op = operator(&parent, &left, &right);
                if op == "%" && left.range() != cur.range() {
                    // Python `"<img src=%s>" % esc(x)` or `% (a, esc(x))`.
                    return before_placeholder(&text(&left, env)?, index_in(&right, &cur));
                }
                if right.range() == cur.range() && matches!(op.as_str(), "+" | ".") {
                    return Some(pieces(&left, env));
                }
            }
            "argument_list" | "arguments" | "value_arguments" => {
                let call = parent.parent()?;
                return formatted(&call, &cur, env);
            }
            k if TEMPLATES.contains(&k) => {
                let start = parent.range().start;
                return Some(parent.text()[..cur.range().start.checked_sub(start)?].to_string());
            }
            _ if kind.contains("interpolation") || kind.contains("substitution") => {}
            _ => return None,
        }
        cur = parent;
    }
    None
}

/// `String.format(fmt, a, esc(x))`, `fmt.Sprintf(…)`, `"…".format(…)`: the
/// format string up to the placeholder `arg` fills.
fn formatted<'a, D: Doc>(
    call: &Node<'a, D>,
    arg: &Node<'a, D>,
    env: &Env<'a, D>,
) -> Option<String> {
    let name = super::summary::called_name(call)?;
    if !FORMATS.contains(&name.as_str()) {
        return None;
    }
    let args = super::summary::args(call);
    let at = args.iter().position(|a| a.range() == arg.range())?;
    let receiver = call.part("function").and_then(|f| f.part("object"));
    // `"…".format(x)` formats its receiver; `format(fmt, x)` its first argument.
    if let Some(r) = receiver.as_ref().and_then(|r| text(r, env)) {
        return before_placeholder(&r, at);
    }
    let fmt = args
        .iter()
        .position(|a| text(a, env).is_some_and(|t| PLACEHOLDER.is_match(&t)))?;
    let fmt_text = text(&args[fmt], env)?;
    before_placeholder(&fmt_text, at.checked_sub(fmt + 1)?)
}

/// The format up to placeholder `k` (`{k}` if numbered).
fn before_placeholder(fmt: &str, k: usize) -> Option<String> {
    let mut seen = 0;
    for m in PLACEHOLDER.captures_iter(fmt) {
        let whole = m.get(0)?;
        if whole.as_str() == "%%" {
            continue;
        }
        let numbered = m.get(3).filter(|n| !n.as_str().is_empty());
        let index = numbered
            .and_then(|n| n.as_str().parse().ok())
            .unwrap_or(seen);
        if index == k {
            return Some(fmt[..whole.start()].to_string());
        }
        seen += 1;
    }
    None
}

/// Where `cur` sits among the values a `%` formats: `(a, esc(x))` → 1.
fn index_in<D: Doc>(values: &Node<D>, cur: &Node<D>) -> usize {
    values
        .children()
        .filter(|c| c.is_named())
        .position(|c| c.range() == cur.range())
        .unwrap_or(0)
}

/// The known text of a concatenation's left side; unknown parts count as
/// empty, which keeps the tag structure the literals give.
fn pieces<'a, D: Doc>(n: &Node<'a, D>, env: &Env<'a, D>) -> String {
    if CONCATS.contains(&n.kind().as_ref())
        && let (Some(l), Some(r)) = (n.part("left"), n.part("right"))
    {
        return pieces(&l, env) + &pieces(&r, env);
    }
    text(n, env).unwrap_or_default()
}

fn text<'a, D: Doc>(n: &Node<'a, D>, env: &Env<'a, D>) -> Option<String> {
    match eval(n, env, 0)? {
        Value::Str(s) => Some(s),
        _ => None,
    }
}

fn operator<D: Doc>(n: &Node<D>, l: &Node<D>, r: &Node<D>) -> String {
    let start = n.range().start;
    n.text()
        .get(l.range().end - start..r.range().start - start)
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Does lowercased HTML `before` end where escaping does not protect?
fn unsafe_context(before: &str) -> bool {
    let open = |tag: &str| {
        before
            .rfind(&format!("<{tag}"))
            .is_some_and(|o| before.rfind(&format!("</{tag}")).is_none_or(|c| c < o))
    };
    if open("script") || open("style") {
        return true;
    }
    let (Some(lt), gt) = (before.rfind('<'), before.rfind('>')) else {
        return false;
    };
    if gt.is_some_and(|g| g > lt) {
        return false;
    }
    let tag = &before[lt..];
    tag.trim_end().ends_with('=') || HANDLER.is_match(tag) || URL_START.is_match(tag)
}

#[cfg(test)]
mod tests {
    use super::unsafe_context;

    #[test]
    fn contexts() {
        assert!(unsafe_context("<img src="));
        assert!(unsafe_context("<img src=x onerror=\""));
        assert!(unsafe_context("<a href=\""));
        assert!(unsafe_context("<script>var a = '"));
        assert!(unsafe_context("<div onclick=\"go('"));
        assert!(!unsafe_context("<p>hello "));
        assert!(!unsafe_context("<img alt=\""));
        assert!(!unsafe_context("<script>x</script><p>"));
    }
}
