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
use anyhow::{Context, Result, anyhow};
use ast_grep_config::RuleConfig;
use ast_grep_core::{Doc, Node, NodeMatch};
use ast_grep_language::SupportLang;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

/// Settings files' keys → the values they are given, read on first use.
#[derive(Default)]
pub struct Settings {
    root: Option<std::path::PathBuf>,
    map: std::sync::OnceLock<HashMap<String, Vec<String>>>,
}

#[derive(Default)]
struct Map(HashMap<String, Vec<String>>);

/// Directories whose settings are not the program's.
const SKIPPED: [&str; 6] = ["test", "tests", "node_modules", "target", "build", "dist"];

impl Settings {
    pub fn new(root: &Path) -> Self {
        Settings {
            root: Some(root.to_path_buf()),
            map: std::sync::OnceLock::new(),
        }
    }

    fn get(&self, key: &str) -> &[String] {
        let map = self
            .map
            .get_or_init(|| self.root.as_deref().map(Map::load).unwrap_or_default().0);
        map.get(key).map(Vec::as_slice).unwrap_or_default()
    }
}

impl Map {
    fn load(root: &Path) -> Self {
        let mut out = Map::default();
        // The repo's files, tracked ones included even when git-ignored.
        let rels = crate::files::list(root, &crate::files::Scope::All).unwrap_or_default();
        for rel in rels {
            if rel.split('/').any(|part| SKIPPED.contains(&part)) {
                continue;
            }
            let name = rel.rsplit('/').next().unwrap_or(&rel);
            let yaml = (name.starts_with("application") || name.starts_with("bootstrap"))
                && (name.ends_with(".yml") || name.ends_with(".yaml"));
            if !(name.ends_with(".properties") || yaml) {
                continue;
            }
            let Ok(text) = std::fs::read_to_string(root.join(&rel)) else {
                continue;
            };
            if yaml {
                out.yaml(&text);
            } else {
                out.properties(&text);
            }
        }
        out
    }

    fn add(&mut self, key: &str, value: &str) {
        let values = self.0.entry(key.to_string()).or_default();
        if !values.iter().any(|v| v == value) {
            values.push(value.to_string());
        }
    }

    fn properties(&mut self, text: &str) {
        for line in text.lines().map(str::trim_start) {
            if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
                continue;
            }
            if let Some(i) = line
                .find(['=', ':'])
                .or_else(|| line.find(char::is_whitespace))
            {
                self.add(line[..i].trim(), line[i + 1..].trim());
            }
        }
    }

    fn yaml(&mut self, text: &str) {
        let docs: Vec<serde_json::Value> = serde_saphyr::from_multiple(text).unwrap_or_default();
        for doc in &docs {
            self.flatten("", doc);
        }
    }

    fn flatten(&mut self, prefix: &str, v: &serde_json::Value) {
        match v {
            serde_json::Value::Object(map) => {
                for (k, v) in map {
                    let key = if prefix.is_empty() {
                        k.clone()
                    } else {
                        format!("{prefix}.{k}")
                    };
                    self.flatten(&key, v);
                }
            }
            serde_json::Value::String(s) => self.add(prefix, s),
            serde_json::Value::Number(n) => self.add(prefix, &n.to_string()),
            serde_json::Value::Bool(b) => self.add(prefix, &b.to_string()),
            _ => {}
        }
    }
}

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
            matches!(d.kind().as_ref(), "variable_declarator" | "assignment")
                && d.field("name")
                    .or_else(|| d.field("left"))
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
    let Some(value) = decl.field("value").or_else(|| decl.field("right")) else {
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
