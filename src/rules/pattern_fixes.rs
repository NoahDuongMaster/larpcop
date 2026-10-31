//! Two ast-grep pattern pitfalls, fixed before rules are compiled:
//! - Go allows no bare expression at the top of a file, so `db.Query($X)`
//!   written alone parses as a type conversion and never matches a call. Such
//!   patterns get a function body as context, with the expression selected
//!   (what `context`/`selector` does when written by hand).
//! - `f($A, $$$REST)` does not match `f(x)`: the comma wants a second
//!   argument. Both shapes are matched.

use ast_grep_core::Language;
use ast_grep_language::{LanguageExt, SupportLang};
use regex::Regex;
use serde_json::{Value, json};
use std::sync::LazyLock;

/// `p`, plus `p` without the `, $$$REST` / `$$$REST,` items that would need a
/// neighbour to match (`f(a, $$$R)`, `{ $$$A, where: $W }`).
pub fn variants(p: &str) -> Vec<String> {
    static TRAILING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r",\s*\$\$\$[A-Z0-9_]*(\s*[)}\]])").expect("static regex"));
    static LEADING: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"([({\[]\s*)\$\$\$[A-Z0-9_]*\s*,\s*").expect("static regex"));
    let mut out = vec![p.to_string()];
    for re in [&*TRAILING, &*LEADING] {
        for v in out.clone() {
            let w = re.replace_all(&v, "$1").into_owned();
            if !out.contains(&w) {
                out.push(w);
            }
        }
    }
    out
}

/// `(context, selector)` for a Go pattern that does not parse on its own.
pub fn context(p: &str) -> Option<(String, String)> {
    let lang = SupportLang::Go;
    let alone = lang.ast_grep(lang.pre_process_pattern(p).as_ref());
    if !alone.root().get_inner_node().has_error() {
        return None;
    }
    let context = format!("func _() {{\n{p}\n}}");
    let grep = lang.ast_grep(lang.pre_process_pattern(&context).as_ref());
    // The first statement of the body (newer grammars wrap them in `statement_list`).
    let statement = grep
        .root()
        .dfs()
        .find(|n| n.kind() == "block")?
        .dfs()
        .skip(1)
        .find(|c| c.is_named() && c.kind() != "statement_list")?;
    let kind = match statement.kind().as_ref() {
        "expression_statement" => statement.child(0)?.kind().to_string(),
        k => k.to_string(),
    };
    Some((context, kind))
}

/// Rule files with patterns to fix, rewritten; `None` if nothing changes.
pub fn rewrite_rule_file(text: &str) -> Option<String> {
    let mut docs: Vec<Value> = serde_saphyr::from_multiple(text).ok()?;
    let mut changed = false;
    for doc in &mut docs {
        let go = doc["language"]
            .as_str()
            .is_some_and(|l| l.eq_ignore_ascii_case("go") || l.eq_ignore_ascii_case("golang"));
        for key in ["rule", "constraints", "utils"] {
            if let Some(v) = doc.get_mut(key) {
                changed |= rewrite(v, go);
            }
        }
    }
    changed.then(|| {
        docs.iter()
            .map(Value::to_string)
            .collect::<Vec<_>>()
            .join("\n---\n")
    })
}

fn rewrite(v: &mut Value, go: bool) -> bool {
    let mut changed = false;
    match v {
        Value::Object(map) => {
            for (k, child) in map.iter_mut() {
                if k != "pattern" {
                    changed |= rewrite(child, go);
                }
            }
            let Some(Value::String(p)) = map.get("pattern").cloned() else {
                return changed;
            };
            let fixed: Vec<Value> = variants(&p)
                .iter()
                .map(|p| match go.then(|| context(p)).flatten() {
                    Some((context, selector)) => {
                        json!({ "context": context, "selector": selector })
                    }
                    None => json!(p),
                })
                .collect();
            if fixed.len() == 1 && fixed[0] == json!(p) {
                return changed;
            }
            map.remove("pattern");
            let any = Value::Array(fixed.into_iter().map(|f| json!({ "pattern": f })).collect());
            if map.contains_key("any") {
                let all = map.entry("all").or_insert_with(|| json!([]));
                if let Value::Array(list) = all {
                    list.push(json!({ "any": any }));
                }
            } else {
                map.insert("any".into(), any);
            }
            true
        }
        Value::Array(items) => {
            for child in items {
                changed |= rewrite(child, go);
            }
            changed
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn calls_get_a_function_body() {
        let (ctx, sel) = super::context("db.Query($X)").unwrap();
        assert!(ctx.contains("func _()"));
        assert_eq!(sel, "call_expression");
        assert!(super::context("func $F($$$P) { $$$B }").is_none());
        let yaml = "id: x\nlanguage: Go\nrule:\n  any:\n    - pattern: exec.Command($C)\n    - kind: call_expression\n";
        let out = super::rewrite_rule_file(yaml).unwrap();
        assert!(out.contains("\"selector\":\"call_expression\""), "{out}");
        assert!(
            super::rewrite_rule_file("id: y\nlanguage: TypeScript\nrule:\n  pattern: eval($X)\n")
                .is_none()
        );
        assert_eq!(
            super::variants("$M.eval($X, $$$R)"),
            ["$M.eval($X, $$$R)", "$M.eval($X)"]
        );
        assert_eq!(
            super::variants("$M.f({ $$$A, where: $W, $$$R })"),
            [
                "$M.f({ $$$A, where: $W, $$$R })",
                "$M.f({ $$$A, where: $W })",
                "$M.f({ where: $W, $$$R })",
                "$M.f({ where: $W })"
            ]
        );
        let js = "id: z\nlanguage: JavaScript\nrule:\n  pattern: f($A, $$$B)\n";
        let out = super::rewrite_rule_file(js).unwrap();
        assert!(out.contains("\"f($A)\""), "{out}");
    }
}
