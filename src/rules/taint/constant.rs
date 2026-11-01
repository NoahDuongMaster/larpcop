//! Values known before the program runs: literals, arithmetic and
//! comparisons on them, and local names whose last write before a point is
//! an unconditional assignment of such a value. Used to drop branches that
//! can never run (`if (7 * 42) - num > 200`, `match "ABC"[0]`).

use super::kotlin::Part;
use ast_grep_core::{Doc, Node};

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Value {
    Int(i64),
    Str(String),
    Bool(bool),
}

pub(crate) use super::env::Env;

/// The value of `n`, when it is known.
pub(crate) fn eval<D: Doc>(n: &Node<D>, env: &Env<D>, depth: usize) -> Option<Value> {
    if depth > 8 {
        return None;
    }
    let named = || n.children().filter(|c| c.is_named());
    let kind = n.kind();
    match kind.as_ref() {
        "parenthesized_expression" | "case_pattern" => eval(&named().next()?, env, depth),
        "integer" | "decimal_integer_literal" | "number" | "integer_literal" | "int_literal" => {
            let digits: String = n.text().chars().filter(|c| *c != '_').collect();
            digits
                .trim_end_matches(['L', 'l'])
                .parse()
                .ok()
                .map(Value::Int)
        }
        "true" => Some(Value::Bool(true)),
        "false" => Some(Value::Bool(false)),
        "string" | "string_literal" | "character_literal" | "interpreted_string_literal" => {
            string(n)
        }
        "identifier" => env.value(&n.text(), n.range().start, depth),
        "not_operator" => not(eval(&n.part("argument")?, env, depth)?),
        "unary_operator" | "unary_expression" | "prefix_unary_expression" => {
            let operand = n
                .part("argument")
                .or_else(|| n.part("operand"))
                .or_else(|| named().last())?;
            let v = eval(&operand, env, depth)?;
            match (n.text().trim_start().chars().next()?, v) {
                ('-', Value::Int(i)) => Some(Value::Int(i.checked_neg()?)),
                ('+', Value::Int(i)) => Some(Value::Int(i)),
                ('!', v) => not(v),
                _ => None,
            }
        }
        "binary_operator" | "binary_expression" | "boolean_operator" => {
            let (l, r) = (n.part("left")?, n.part("right")?);
            let op = n.text()[l.range().end - n.range().start..r.range().start - n.range().start]
                .trim()
                .to_string();
            binary(&op, &l, &r, env, depth)
        }
        "comparison_operator" => {
            let parts: Vec<Node<D>> = named().collect();
            let [l, r] = parts.as_slice() else {
                return None;
            };
            let op = n.text()[l.range().end - n.range().start..r.range().start - n.range().start]
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ");
            binary(&op, l, r, env, depth)
        }
        "subscript" => {
            let parts: Vec<Node<D>> = named().collect();
            let [base, index] = parts.as_slice() else {
                return None;
            };
            match (eval(base, env, depth)?, eval(index, env, depth)?) {
                (Value::Str(s), Value::Int(i)) => char_at(&s, i),
                _ => None,
            }
        }
        "method_invocation" => {
            let object = eval(&n.part("object")?, env, depth)?;
            let args: Vec<Node<D>> = n
                .part("arguments")?
                .children()
                .filter(|c| c.is_named())
                .collect();
            let arg = args.first().and_then(|a| eval(a, env, depth));
            match (n.part("name")?.text().as_ref(), object, arg) {
                ("charAt", Value::Str(s), Some(Value::Int(i))) => char_at(&s, i),
                ("equals", a, Some(b)) => Some(Value::Bool(a == b)),
                ("contains", Value::Str(s), Some(Value::Str(t))) => {
                    Some(Value::Bool(s.contains(&t)))
                }
                ("startsWith", Value::Str(s), Some(Value::Str(t))) => {
                    Some(Value::Bool(s.starts_with(&t)))
                }
                ("endsWith", Value::Str(s), Some(Value::Str(t))) => {
                    Some(Value::Bool(s.ends_with(&t)))
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn binary<D: Doc>(op: &str, l: &Node<D>, r: &Node<D>, env: &Env<D>, depth: usize) -> Option<Value> {
    let left = eval(l, env, depth);
    // `false && x`, `true || x`: decided by the left side alone.
    match (op, &left) {
        ("&&" | "and", Some(Value::Bool(false))) => return Some(Value::Bool(false)),
        ("||" | "or", Some(Value::Bool(true))) => return Some(Value::Bool(true)),
        _ => {}
    }
    let (a, b) = (left?, eval(r, env, depth)?);
    use Value::{Bool, Int, Str};
    Some(match (op, a, b) {
        ("+", Int(x), Int(y)) => Int(x.checked_add(y)?),
        ("-", Int(x), Int(y)) => Int(x.checked_sub(y)?),
        ("*", Int(x), Int(y)) => Int(x.checked_mul(y)?),
        ("+", Str(x), Str(y)) => Str(x + &y),
        ("<", Int(x), Int(y)) => Bool(x < y),
        (">", Int(x), Int(y)) => Bool(x > y),
        ("<=", Int(x), Int(y)) => Bool(x <= y),
        (">=", Int(x), Int(y)) => Bool(x >= y),
        ("==" | "===", x, y) => Bool(x == y),
        ("!=" | "!==", x, y) => Bool(x != y),
        ("in", Str(x), Str(y)) => Bool(y.contains(&x)),
        ("not in", Str(x), Str(y)) => Bool(!y.contains(&x)),
        ("&&" | "and", Bool(x), Bool(y)) => Bool(x && y),
        ("||" | "or", Bool(x), Bool(y)) => Bool(x || y),
        _ => return None,
    })
}

fn not(v: Value) -> Option<Value> {
    match v {
        Value::Bool(b) => Some(Value::Bool(!b)),
        _ => None,
    }
}

fn char_at(s: &str, i: i64) -> Option<Value> {
    let chars: Vec<char> = s.chars().collect();
    let i = if i < 0 { chars.len() as i64 + i } else { i };
    chars
        .get(usize::try_from(i).ok()?)
        .map(|c| Value::Str(c.to_string()))
}

/// A string or character literal without interpolation: its text.
fn string<D: Doc>(n: &Node<D>) -> Option<Value> {
    if n.dfs()
        .any(|c| c.kind() == "interpolation" || c.kind() == "template_substitution")
    {
        return None;
    }
    let text = n.text();
    let body = text.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    let quote = if body.starts_with("\"\"\"") || body.starts_with("'''") {
        3
    } else {
        1
    };
    if body.len() < 2 * quote {
        return None;
    }
    let inner = &body[quote..body.len() - quote];
    let mut out = String::new();
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next()? {
                c @ ('\'' | '"' | '\\') => out.push(c),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(Value::Str(out))
}
