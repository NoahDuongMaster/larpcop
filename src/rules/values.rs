//! What a metavariable holds when the program runs, for ast-grep rules that
//! judge a value rather than how it is spelled:
//!
//! ```yaml
//! rule: { pattern: MessageDigest.getInstance($ALG) }
//! metadata: { resolve: { ALG: "(?i)^(md5|sha-?1)$" } }
//! ```
//!
//! A match is kept when `$ALG` can hold a matching string: a literal, a local
//! assigned one, a constant of the file (`static final String ALG = "MD5"`,
//! module-level `ALG = "md5"`), `props.getProperty("hashAlg1", "SHA512")` or a
//! Spring `@Value("${crypto.alg:MD5}")` field, read from the project's
//! `.properties` and `application*.yml` (a key set differently in two files
//! can hold either). A value that cannot be known is not reported.

use super::complexity::is_function;
use super::taint::constant::{Env, Value, eval};
use super::taint::flow::assignment;
use anyhow::{Context, Result, anyhow};
use ast_grep_config::RuleConfig;
use ast_grep_core::{Doc, Node, NodeMatch};
use ast_grep_language::SupportLang;
use regex::Regex;

pub use super::settings::Settings;

/// A rule's `metadata.resolve`: metavariable → the regex its value matches.
pub struct Resolve(Vec<(String, Regex)>);

impl Resolve {
    pub fn of(rule: &RuleConfig<SupportLang>) -> Result<Option<Self>> {
        let meta = serde_json::to_value(&rule.metadata)?;
        let Some(map) = meta.get("resolve").and_then(|r| r.as_object()) else {
            return Ok(None);
        };
        let mut out = Vec::new();
        for (var, re) in map {
            let re = re.as_str().ok_or_else(|| {
                anyhow!("rule `{}`: metadata.resolve.{var} is not a regex", rule.id)
            })?;
            let re = Regex::new(re)
                .with_context(|| format!("rule `{}`: metadata.resolve.{var}", rule.id))?;
            out.push((var.clone(), re));
        }
        Ok(Some(Resolve(out)))
    }

    /// Can every resolved metavariable `m` binds hold a matching value? (One
    /// a branch of the rule does not bind does not count.)
    pub fn keeps<D: Doc>(&self, m: &NodeMatch<D>, settings: &Settings) -> bool {
        self.0.iter().all(|(var, re)| {
            m.get_env()
                .get_match(var)
                .is_none_or(|n| may_hold(n, re, settings))
        })
    }
}

/// Can `n` hold a string matching `re`?
pub fn may_hold<D: Doc>(n: &Node<D>, re: &Regex, settings: &Settings) -> bool {
    let scope = n
        .ancestors()
        .find(|a| is_function(a))
        .unwrap_or_else(|| top(n));
    let env = Env::new(&scope);
    values(n, &env, settings, 0).iter().any(|v| re.is_match(v))
}

fn values<'a, D: Doc>(
    n: &Node<'a, D>,
    env: &Env<'a, D>,
    s: &Settings,
    depth: usize,
) -> Vec<String> {
    if depth > 6 {
        return Vec::new();
    }
    // Kotlin `value_argument`, C# `argument`: the expression inside.
    if matches!(n.kind().as_ref(), "value_argument" | "argument")
        && let Some(inner) = n.children().find(|c| c.is_named())
    {
        return values(&inner, env, s, depth);
    }
    if let Some(Value::Str(v)) = eval(n, env, 0) {
        return vec![v];
    }
    match n.kind().as_ref() {
        "identifier" | "simple_identifier" => {
            let name = n.text();
            if env.writes(&name) {
                return env
                    .candidates(&name, n.range().start)
                    .iter()
                    .flat_map(|v| values(v, env, s, depth + 1))
                    .collect();
            }
            declared(n, &name, s, depth)
        }
        // `this.alg`, `Crypto.ALG`, `self.alg`
        "field_access" | "member_expression" | "attribute" | "member_access_expression" => {
            let field = n
                .field("field")
                .or_else(|| n.field("property"))
                .or_else(|| n.field("attribute"))
                .or_else(|| n.field("name"));
            field
                .map(|f| declared(n, &f.text(), s, depth))
                .unwrap_or_default()
        }
        "method_invocation" | "call_expression" | "call" | "invocation_expression" => {
            setting(n, env, s, depth)
        }
        _ => Vec::new(),
    }
}

/// `props.getProperty("k", "default")`, `env.getProperty("k")`,
/// `config.get("k")`: the key's values in the settings, else the default.
fn setting<'a, D: Doc>(
    call: &Node<'a, D>,
    env: &Env<'a, D>,
    s: &Settings,
    depth: usize,
) -> Vec<String> {
    let name = call.field("name").or_else(|| {
        call.field("function").and_then(|f| {
            f.field("property")
                .or_else(|| f.field("attribute"))
                .or_else(|| f.field("name"))
        })
    });
    if !name.is_some_and(|n| matches!(n.text().as_ref(), "getProperty" | "getString" | "getValue"))
    {
        return Vec::new();
    }
    let args: Vec<Node<D>> = call
        .field("arguments")
        .map(|a| a.children().filter(|c| c.is_named()).collect())
        .unwrap_or_default();
    let Some(Value::Str(key)) = args.first().and_then(|k| eval(k, env, 0)) else {
        return Vec::new();
    };
    let found = s.get(&key);
    if !found.is_empty() {
        return found.to_vec();
    }
    args.get(1)
        .map(|d| values(d, env, s, depth + 1))
        .unwrap_or_default()
}

/// A constant of the file named `name` (declared once, outside functions,
/// with a value), or a Spring `@Value("${key:default}")` field.
fn declared<D: Doc>(n: &Node<D>, name: &str, s: &Settings, depth: usize) -> Vec<String> {
    let root = top(n);
    let decls: Vec<Node<D>> = root
        .dfs()
        .filter(|d| {
            matches!(
                d.kind().as_ref(),
                "variable_declarator" | "assignment" | "property_declaration"
            ) && assignment(d)
                .map(|(l, _)| l)
                .or_else(|| d.field("name"))
                .is_some_and(|l| l.text() == name)
                && !d.ancestors().any(|a| is_function(&a))
        })
        .collect();
    let [decl] = decls.as_slice() else {
        return Vec::new();
    };
    if let Some(key) = spring_value(decl) {
        let (key, default) = key
            .split_once(':')
            .map_or((key.as_str(), None), |(k, d)| (k, Some(d)));
        let found = s.get(key);
        return match (found.is_empty(), default) {
            (false, _) => found.to_vec(),
            (true, Some(d)) => vec![d.to_string()],
            (true, None) => Vec::new(),
        };
    }
    let Some((_, value)) = assignment(decl) else {
        return Vec::new();
    };
    values(&value, &Env::new(&root), s, depth + 1)
}

/// The file's root node.
fn top<'a, D: Doc>(n: &Node<'a, D>) -> Node<'a, D> {
    n.ancestors().last().unwrap_or_else(|| n.clone())
}

/// `@Value("${crypto.alg:MD5}")` on the field `decl` declares: `crypto.alg:MD5`.
fn spring_value<D: Doc>(decl: &Node<D>) -> Option<String> {
    let field = decl.parent()?;
    let modifiers = field.children().find(|c| c.kind() == "modifiers")?;
    let text = modifiers.text();
    let start = text.find("@Value(\"${")? + "@Value(\"${".len();
    let end = start + text[start..].find("}\"")?;
    Some(text[start..end].to_string())
}
