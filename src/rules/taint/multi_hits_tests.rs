use super::*;
use ast_grep_language::{LanguageExt, SupportLang};

#[test]
fn test_multi_hits_empty() {
    let grep = SupportLang::JavaScript.ast_grep("function foo() {}");
    let root = grep.root();
    let hits0 = Hits::new(vec![], &root, Default::default());
    let empty = MultiHits::from_rules(&[], &[hits0]);
    assert!(empty.is_empty());
    assert_eq!(empty.len(), 0);
    assert_eq!(empty.sink_mask_at(&(0..10)), 0);
}

#[test]
fn test_multi_hits_from_rules_aggregates_masks() {
    let grep = SupportLang::JavaScript.ast_grep("function foo() { sink1(a); sink2(b); }");
    let root = grep.root();
    let calls: Vec<_> = root
        .dfs()
        .filter(|n| n.kind() == "call_expression")
        .collect();
    assert_eq!(calls.len(), 2);
    let (na, nb) = (calls[0].clone(), calls[1].clone());
    let hits0 = Hits::new(
        vec![(na.range().start, na.clone(), Vec::new())],
        &root,
        Default::default(),
    );
    let hits1 = Hits::new(
        vec![
            (na.range().start, na.clone(), Vec::new()),
            (nb.range().start, nb.clone(), Vec::new()),
        ],
        &root,
        Default::default(),
    );
    let multi = MultiHits::from_rules(&[], &[hits0, hits1]);
    assert_eq!(multi.len(), 2);
    assert_eq!(multi.hits()[0].sink_mask, 0b11);
    assert_eq!(multi.hits()[1].sink_mask, 0b10);
    assert_eq!(multi.sink_mask_at(&na.range()), 0b11);
    assert_eq!(multi.sink_mask_at(&nb.range()), 0b10);
}

#[test]
fn test_multi_hits_spans_and_guards() {
    let grep = SupportLang::JavaScript.ast_grep("function foo() {}");
    let root = grep.root();
    let hits0 = Hits::new(vec![], &root, Default::default());
    let mut multi = MultiHits::from_rules(&[], &[hits0]);
    multi.add_source_span(10..20, 0b01);
    multi.add_sanitizer_span(15..25, 0b10);
    multi.add_sink_span(20..30, 0b11);
    multi.add_guard_check(0b01, (12..18, true, 1));

    assert_eq!(multi.source_mask_at(&(10..20)), 0b01);
    assert_eq!(multi.sanitizer_mask_at(&(15..25)), 0b10);
    assert_eq!(multi.sink_mask_at(&(20..30)), 0b11);

    let guards = multi.guards_for(&(10..30));
    assert_eq!(guards.len(), 1);
    assert_eq!(guards[0].0, 0b01);
    assert_eq!(guards[0].1.0, 12..18);
}
