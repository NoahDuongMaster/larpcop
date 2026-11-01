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
    /// Regex over a class header (`class A extends B`, up to its body): the
    /// parameters of its methods are request data (gRPC `ImplBase`,
    /// `Servicer`). A method taking a `StreamObserver`/`ServerCallContext` is
    /// one without it.
    #[serde(default)]
    pub handler_classes: Option<String>,
    /// Regex over a parameter's declared type that makes it request data
    /// (Go gRPC `*pb.HelloRequest`).
    #[serde(default)]
    pub input_types: Option<String>,
    /// XSS: an HTML escaper does not clean a value placed in an unquoted
    /// attribute, an event handler, a script or a URL attribute.
    #[serde(default)]
    pub escape_contexts: bool,
    /// Regex over the text of sanitizer calls that escape quotes only
    /// (`mysqli_real_escape_string(`): they clean a value placed inside a
    /// quoted string, not one placed outside (see placements.rs).
    #[serde(default)]
    pub quote_escapers: Option<String>,
    /// The quotes `quote_escapers` protect inside (default `'"` and
    /// backquote): `'` alone for PHP code, where `"…"` interpolates `{$…}`.
    #[serde(default)]
    pub quote_chars: Option<String>,
    /// Deserialization: bytes the program serialized itself
    /// (`out.writeObject(x)`) hold `x`'s content, not a structure the
    /// sender chose, so a stream write does not carry taint for this rule.
    #[serde(default)]
    pub own_serialization_safe: bool,
    /// Argument vectors that run a command string through a shell (see
    /// argv.rs): `calls` (regex over the callee), `shells`, `flags`.
    #[serde(default)]
    pub shell_argv: Option<ShellArgvConfig>,
    /// Sources that are the route itself in a handler whose routes have no
    /// variables (`request.path` under `@app.route('/a/b')`; see routes.rs).
    #[serde(default)]
    pub fixed_route_sources: Vec<String>,
    /// Path objects used on the file system (see pathobj.rs): `types`
    /// (regex over the constructor), `uses` (regex over the methods).
    #[serde(default)]
    pub path_objects: Option<PathObjectsConfig>,
    /// Values placed into HTML markup that is assigned to a variable are
    /// sinks (PHP pages printed by a shared template; see fragments.rs).
    #[serde(default)]
    pub html_fragments: bool,
    /// Calls that write outside data into an argument, `name:index` or
    /// `name:index..` (`fgets:0`, `recv:1`, `scanf:1..`; see outputs.rs).
    #[serde(default)]
    pub source_writes: Vec<String>,
    /// Calls that copy what they are given into an argument (`strcpy:0`).
    #[serde(default)]
    pub copies: Vec<String>,
    /// Sink metavariable → regex over its type as the project's language server
    /// shows it (`DB: "Pool|PoolClient"`). Without a server the sink counts.
    #[serde(default)]
    pub sink_types: std::collections::BTreeMap<String, String>,
    /// Like `sink_types`, but the sink counts only when the type is known
    /// (declared, or `new T(…)` at the sink).
    #[serde(default)]
    pub strict_sink_types: std::collections::BTreeMap<String, String>,
    /// Sink metavariable → regex over a type that is not the sink's: the sink
    /// is dropped when the declared type matches (`DB: '^DOMXPath$'`).
    #[serde(default)]
    pub excluded_sink_types: std::collections::BTreeMap<String, String>,
    /// Guard or sanitizer metavariable → regex every value it can hold must
    /// match (see valued.rs): `ALLOW: '^/\^\[a-z]*\$/$'`.
    #[serde(default)]
    pub values: std::collections::BTreeMap<String, String>,
    /// Sink metavariable → regex over how the object it names is set up in
    /// the file (see configured.rs).
    #[serde(default)]
    pub sink_configured: std::collections::BTreeMap<String, String>,
    /// Sink metavariable → regex over its text: a sink for a cookie named
    /// `session` only (`N: "^[\"']?(session|sid)"`).
    #[serde(default)]
    pub sink_texts: std::collections::BTreeMap<String, String>,
    /// Source metavariable → regex over the type its name is declared with in
    /// the file; an undeclared name does not count (see srctypes.rs).
    #[serde(default)]
    pub source_types: std::collections::BTreeMap<String, String>,
    /// Source metavariable → regex over its text (`M: "^find"`).
    #[serde(default)]
    pub source_text: std::collections::BTreeMap<String, String>,
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

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShellArgvConfig {
    /// Regex over the callee (`subprocess.run`, `ProcessBuilder`, `exec`).
    pub calls: String,
    /// Regex over the first element: a shell (`sh`, `/bin/bash`, `cmd.exe`).
    pub shells: String,
    /// Regex over the second element: the flag that runs a string (`-c`).
    pub flags: String,
    /// Where a call takes its vector: `execv:1` (an array), `execl:1..` (the
    /// arguments from there on). The first argument otherwise.
    #[serde(default)]
    pub vectors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathObjectsConfig {
    /// Regex over a constructor's callee or an annotation: `^(pathlib\.)?Path$`.
    pub types: String,
    /// Regex over the method names that touch the file system.
    pub uses: String,
}
