use super::*;
use crate::rules::taint::routes::FixedRoutes;
use crate::rules::taint::scan::Indexed;
use crate::rules::taint::TaintRule;
use ast_grep_core::AstGrep;
use ast_grep_language::{LanguageExt, SupportLang};
use regex::Regex;

fn dummy_rule(id: &str, sink_pat: &str, san_pat: Option<&str>) -> TaintRule {
    let lang = SupportLang::JavaScript;
    let grep = lang.ast_grep(sink_pat);
    let sink_matcher = grep.root();
    let sanitizer_names = san_pat.map(|p| Regex::new(p).unwrap());
    let indexed: Indexed = Indexed {
        sources: Vec::new(),
        sinks: vec![(sink_matcher.clone(), None)],
        sanitizers: Vec::new(),
        guards: Vec::new(),
        rules: Vec::new(),
    };
    TaintRule {
        id: id.to_string(),
        message: "test".to_string(),
        severity: crate::rules::Severity::Error,
        languages: vec!["javascript".to_string()],
        fixed_routes: FixedRoutes {
            sources: Vec::new(),
            sinks: Vec::new(),
        },
        sanitizer_names,
        langs: vec![(lang, indexed)],
    }
}

#[test]
fn test_multi_hits_aggregates_multiple_rules() {
    let r0 = dummy_rule("r0", "sink($$$)", None);
    let r1 = dummy_rule("r1", "sink($$$)", Some("safe"));
    let grep = SupportLang::JavaScript.ast_grep("function test() { sink(x); }");
    let root = grep.root();
    let node = root
        .dfs()
        .find(|n| n.kind() == "call_expression")
        .unwrap();
    let h0 = Hits::new(
        vec![(node.range().start, node.clone(), Vec::new())],
        &root,
        Default::default(),
    );
    let h1 = Hits::new(
        vec![(node.range().start, node.clone(), Vec::new())],
        &root,
        Default::default(),
    );
    let file_hits = vec![h0, h1];
    let mh = MultiHits::from_prepared(&[&r0, &r1], &[], &file_hits);
    assert_eq!(mh.list.len(), 1);
    assert_eq!(mh.list[0].sink_mask, 0b11);
    assert_eq!(mh.sink_mask_at(&node.range()), 0b11);
}

#[test]
fn test_multi_hits_sources_and_sanitizers_spans() {
    let r0 = dummy_rule("r0", "sink($$$)", None);
    let grep = SupportLang::JavaScript.ast_grep("function test() { let x = 1; }");
    let root = grep.root();
    let h0 = Hits::new(Vec::new(), &root, Default::default());
    let mut ctx0 = Ctx::default();
    ctx0.sources.insert(10..20);
    ctx0.sanitizers.insert(30..40);
    let mut ctx1 = Ctx::default();
    ctx1.sources.insert(10..20);
    let contexts = vec![&ctx0, &ctx1];
    let mh = MultiHits::from_prepared(&[&r0, &r0], &contexts, &[h0.clone(), h0]);
    assert_eq!(mh.source_mask_at(&(10..20)), 0b11);
    assert_eq!(mh.sanitizer_mask_at(&(30..40)), 0b01);
    assert_eq!(mh.source_mask_at(&(0..5)), 0);
}

#[test]
fn test_multi_hits_enforces_128_rule_cap() {
    let rules: Vec<TaintRule> = (0..130)
        .map(|i| dummy_rule(&format!("r{i}"), "sink($$$)", None))
        .collect();
    let rule_refs: Vec<&TaintRule> = rules.iter().collect();
    let grep = SupportLang::JavaScript.ast_grep("sink(x);");
    let root = grep.root();
    let node = root
        .dfs()
        .find(|n| n.kind() == "call_expression")
        .unwrap();
    let file_hits: Vec<Hits<ast_grep_language::SupportLangDoc>> = (0..130)
        .map(|_| {
            Hits::new(
                vec![(node.range().start, node.clone(), Vec::new())],
                &root,
                Default::default(),
            )
        })
        .collect();
    let mh = MultiHits::from_prepared(&rule_refs, &[], &file_hits);
    assert_eq!(mh.list[0].sink_mask, !0u128);
}

#[test]
fn test_multi_hits_by_scope_nested_functions() {
    let r0 = dummy_rule("r0", "sink($$$)", None);
    let code = "function outer() { sink(1); function inner() { sink(2); } }";
    let grep = SupportLang::JavaScript.ast_grep(code);
    let root = grep.root();
    let calls: Vec<_> = root
        .dfs()
        .filter(|n| n.kind() == "call_expression")
        .collect();
    assert_eq!(calls.len(), 2);
    let h0 = Hits::new(
        vec![
            (calls[0].range().start, calls[0].clone(), Vec::new()),
            (calls[1].range().start, calls[1].clone(), Vec::new()),
        ],
        &root,
        Default::default(),
    );
    let mh = MultiHits::from_prepared(&[&r0], &[], &[h0]);
    assert_eq!(mh.list.len(), 2);
    assert_eq!(mh.by_scope.len(), 2);
}

#[test]
fn test_multi_hits_empty_hits() {
    let r0 = dummy_rule("r0", "sink($$$)", None);
    let grep = SupportLang::JavaScript.ast_grep("let x = 1;");
    let root = grep.root();
    let h0 = Hits::new(Vec::new(), &root, Default::default());
    let mh = MultiHits::from_prepared(&[&r0], &[], &[h0]);
    assert!(mh.list.is_empty());
    assert!(mh.by_scope.is_empty());
    assert_eq!(mh.sink_mask_at(&(0..10)), 0);
}
