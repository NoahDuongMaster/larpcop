use super::*;
use crate::files::SourceFile;
use crate::rules::taint::scan::FileIndex;
use crate::rules::taint::tests_support::{guarded, rule};
use crate::rules::taint::{TaintRule, flow::Ctx};
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::{LanguageExt, SupportLang};

const SRC: &str =
    "function foo(req) { if (ok(req.query)) { sink1(req.query); } sink2(esc(req.query)); }";

/// The rules' hits aggregated, the rule `k` being `rules[k]`.
fn aggregated(rules: &[TaintRule], then: impl FnOnce(&MultiHits<'_, StrDoc<SupportLang>>)) {
    let file = SourceFile {
        rel: "a.js".into(),
        content: SRC.into(),
    };
    let grep = SupportLang::JavaScript.ast_grep(SRC);
    let index = FileIndex::new(grep.root());
    let (ctxs, hits): (Vec<Ctx>, Vec<_>) = rules
        .iter()
        .map(|r| {
            r.prepare(SupportLang::JavaScript, &index, &file, 0)
                .unwrap()
        })
        .unzip();
    let refs: Vec<&Ctx> = ctxs.iter().collect();
    let multi = MultiHits::from_prepared(&refs, &hits, &index.root, index.skeletons.clone());
    then(&multi);
}

fn two_rules(dir: &std::path::Path) -> Vec<TaintRule> {
    vec![
        rule("JavaScript", dir, &["req.query"], &["sink1($X)"], &[]),
        rule(
            "JavaScript",
            dir,
            &["req.query"],
            &["sink1($X)", "sink2($X)"],
            &["esc($X)"],
        ),
    ]
}

#[test]
fn sinks_are_aggregated_over_rules_by_position() {
    let dir = tempfile::tempdir().unwrap();
    aggregated(&two_rules(dir.path()), |multi| {
        assert_eq!(multi.active, 0b11);
        let sinks: Vec<_> = multi
            .sinks
            .iter()
            .map(|s| (s.node.text().to_string(), s.rules))
            .collect();
        assert_eq!(
            sinks,
            [("req.query".into(), 0b11), ("esc(req.query)".into(), 0b10)]
        );
        assert!(multi.sinks[0].at < multi.sinks[1].at);
        assert!(multi.sinks.iter().all(|s| s.typed.is_empty()));
    });
}

#[test]
fn sources_and_sanitizers_answer_per_rule() {
    let dir = tempfile::tempdir().unwrap();
    aggregated(&two_rules(dir.path()), |multi| {
        let at = |text: &str| SRC.find(text).map(|s| s..s + text.len()).unwrap();
        assert_eq!(multi.sources.covers(&at("req.query"), !0), 0b11);
        assert_eq!(multi.sources.covers(&at("sink1"), !0), 0);
        assert_eq!(multi.sanitizers.covers(&at("esc(req.query)"), !0), 0b10);
        let inner = SRC.rfind("req.query").unwrap();
        assert_eq!(multi.sanitizers.covers(&(inner..inner + 9), 0b10), 0b10);
        assert_eq!(multi.sanitizers.covers(&(inner..inner + 9), 0b01), 0);
        assert_eq!(multi.sanitizers.covers(&at("sink1"), !0), 0);
    });
}

#[test]
fn rules_with_the_same_guards_share_a_group() {
    let dir = tempfile::tempdir().unwrap();
    let with = |guards: &[&str]| {
        guarded(
            "JavaScript",
            dir.path(),
            &["req.query"],
            &["sink1($X)"],
            &[],
            guards,
        )
    };
    let rules = [with(&["ok($X)"]), with(&[]), with(&["ok($X)"])];
    aggregated(&rules, |multi| {
        assert_eq!(multi.active, 0b111);
        let masks: Vec<_> = multi.guard_groups.iter().map(|(m, _)| *m).collect();
        assert_eq!(masks, [0b101, 0b010]);
    });
}
