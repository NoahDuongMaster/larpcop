//! Building taint rules and running them on files, for the tests.

use super::*;
use crate::config::TaintConfig;
use std::path::Path;

pub(super) fn rule(
    lang: &str,
    root: &Path,
    sources: &[&str],
    sinks: &[&str],
    sanitizers: &[&str],
) -> TaintRule {
    guarded(lang, root, sources, sinks, sanitizers, &[])
}

pub(super) fn guarded(
    lang: &str,
    root: &Path,
    sources: &[&str],
    sinks: &[&str],
    sanitizers: &[&str],
    guards: &[&str],
) -> TaintRule {
    let cfg = guarded_config(lang, sources, sinks, sanitizers, guards);
    TaintRule::new(&cfg, typed::Typed::default(), root.to_path_buf()).unwrap()
}

/// A redirect-like rule: a value starting with `prefix` is safe.
pub(super) fn with_safe_prefix(cfg: TaintConfig, prefix: &str, root: &Path) -> TaintRule {
    let cfg = TaintConfig {
        safe_prefix: Some(prefix.into()),
        ..cfg
    };
    TaintRule::new(&cfg, typed::Typed::default(), root.to_path_buf()).unwrap()
}

pub(super) fn guarded_config(
    lang: &str,
    sources: &[&str],
    sinks: &[&str],
    sanitizers: &[&str],
    guards: &[&str],
) -> TaintConfig {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
    TaintConfig {
        id: "taint".into(),
        languages: vec![lang.into()],
        severity: None,
        message: "request data reaches a sink".into(),
        note: None,
        sources: s(sources),
        sinks: s(sinks),
        sink_arg: Some("X".into()),
        sanitizers: s(sanitizers),
        safe_prefix: None,
        sanitizer_names: None,
        unless: Vec::new(),
        guards: s(guards),
        param_types: Default::default(),
        source_names: Vec::new(),
        rejects: Vec::new(),
        param_decorators: Vec::new(),
        handler_decorators: None,
        resolver_args: false,
        exclude: Default::default(),
        sink_types: Default::default(),
        values: Default::default(),
        sink_configured: Default::default(),
        strict_sink_types: Default::default(),
        excluded_sink_types: Default::default(),
        sink_texts: Default::default(),
        source_types: Default::default(),
        source_text: Default::default(),
        response_returns: None,
        handler_classes: None,
        input_types: None,
        escape_contexts: false,
        quote_escapers: None,
        quote_chars: None,
        own_serialization_safe: false,
        shell_argv: None,
        fixed_route_sources: Vec::new(),
        path_objects: None,
        html_fragments: false,
        source_writes: Vec::new(),
        copies: Vec::new(),
    }
}

/// A violation as the tests compare them: (rule, line, column, note).
type Key = (String, usize, usize, Option<String>);

fn keys(vs: &[Violation]) -> Vec<Key> {
    let mut keys: Vec<Key> = vs
        .iter()
        .map(|v| (v.rule.clone(), v.line, v.column, v.note.clone()))
        .collect();
    keys.sort();
    keys
}

/// Checks `file` with every rule of `rules` through the multi-rule path (one
/// batch), the way `larpcop check` does.
pub(super) fn multi(rules: &[TaintRule], file: &SourceFile) -> Vec<Violation> {
    let Some(lang) = SupportLang::from_path(&file.rel) else {
        return Vec::new();
    };
    let grep = lang.ast_grep(crate::rules::macros::expand(lang, &file.content));
    check_indexed_multi(rules, file, lang, &FileIndex::new(grep.root()))
}

/// The violations of the single-rule path, after asserting that the
/// multi-rule path finds exactly the same ones for this rule alone: every
/// taint test is thus also a test of the code `larpcop check` runs.
pub(super) fn check_parity(r: &TaintRule, file: &SourceFile) -> Vec<Violation> {
    let single = r.check(file);
    let both = multi(std::slice::from_ref(r), file);
    assert_eq!(
        keys(&single),
        keys(&both),
        "single-rule path (left) and multi-rule path (right) disagree on {}",
        file.rel
    );
    single
}

pub(super) fn found(r: &TaintRule, root: &Path, rel: &str) -> Vec<(usize, String)> {
    let content = std::fs::read_to_string(root.join(rel)).unwrap();
    let file = SourceFile {
        rel: rel.into(),
        content,
    };
    check_parity(r, &file)
        .into_iter()
        .map(|v| (v.line, v.note.unwrap_or_default()))
        .collect()
}
