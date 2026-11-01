//! Schema of a `taint:` rule.

use crate::rules::Level;
use serde::Deserialize;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaintConfig {
    pub id: String,
    /// ast-grep language names, e.g. [TypeScript, Tsx, JavaScript].
    pub languages: Vec<String>,
    pub severity: Option<Level>,
    pub message: String,
    pub note: Option<String>,
    /// ast-grep patterns of untrusted data, e.g. `req.query`.
    #[serde(default)]
    pub sources: Vec<String>,
    /// Names that are untrusted wherever they are read, matched as written:
    /// PHP's `$_GET` cannot be an ast-grep pattern (`$_…` is a metavariable).
    #[serde(default)]
    pub source_names: Vec<String>,
    /// ast-grep patterns of dangerous calls, e.g. `$DB.query($SQL, $$$REST)`.
    pub sinks: Vec<String>,
    /// Metavariable of the sink argument that must stay clean (default: the whole call).
    pub sink_arg: Option<String>,
    /// Regex over the literal start of a built sink argument (`"/p/" + id`)
    /// that makes it safe, e.g. `^/[^/\\]` for redirects.
    pub safe_prefix: Option<String>,
    /// Regex on the called name: a matching call's result is clean (Rails
    /// route helpers `^\w+_(path|url)$` build URLs of the app itself).
    #[serde(default)]
    pub sanitizer_names: Option<String>,
    /// ast-grep patterns that make data safe, e.g. `Number($X)`.
    #[serde(default)]
    pub sanitizers: Vec<String>,
    /// Regexes on the text of the function around a sink: a match means the
    /// function made the sink safe whatever reaches it
    /// (`new Yaml(new SafeConstructor())`, `SimpleEvaluationContext`).
    #[serde(default)]
    pub unless: Vec<String>,
    /// ast-grep patterns of checks in `if` conditions, e.g. `$X.startsWith($P)`:
    /// a checked name is clean after a branch that returns or throws, and
    /// inside a branch taken when the check passes.
    #[serde(default)]
    pub guards: Vec<String>,
    /// Patterns true when the value is unsafe: `$P.includes("$S")`. After
    /// `if ($P.includes("..")) return;` the name is clean; inside the `if`
    /// it is not.
    #[serde(default)]
    pub rejects: Vec<String>,
    /// Destructured parameters by type: with `Request: req`, the parameter
    /// `{ query }: Request` reads `req.query`.
    #[serde(default)]
    pub param_types: std::collections::BTreeMap<String, String>,
    /// Parameter decorators whose parameter is request data (`Body`, `Query`).
    #[serde(default)]
    pub param_decorators: Vec<String>,
    /// Regex over a function's decorators (without `@`) that makes it a route
    /// handler: all its parameters are request data (`app\.get\(`).
    pub handler_decorators: Option<String>,
    /// GraphQL resolvers' arguments are request data: `(parent, args)` in
    /// JS/TS, the parameters after `(root, info)` in Python.
    #[serde(default)]
    pub resolver_args: bool,
    /// Sink metavariable → regex over its type as the project's language server
    /// shows it (`DB: "Pool|PoolClient"`). Without a server the sink counts.
    #[serde(default)]
    pub sink_types: std::collections::BTreeMap<String, String>,
    /// Functions whose return value is the response body: a tainted value
    /// they return reaches the sink (Spring `@ResponseBody`, Flask views).
    pub response_returns: Option<ResponseReturns>,
    /// Globs of files the rule does not report in (tests, fixtures). Their
    /// functions still count when other files call them.
    #[serde(default)]
    pub exclude: Vec<String>,
}

/// Which functions write what they return to the response. Regexes are
/// matched against the function's header: its decorators or annotations and
/// signature, then the header of its class.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResponseReturns {
    /// Every regex must match the headers (`@GetMapping`, `@ResponseBody`).
    pub headers: Vec<String>,
    /// No match of this one (`produces = "application/json"`).
    pub not: Option<String>,
    /// Regex over the declared return type, where there is one (`^String$`).
    pub types: Option<String>,
    /// Regex over the returned node's kind (`^(string|binary_operator)$`).
    pub values: Option<String>,
}
