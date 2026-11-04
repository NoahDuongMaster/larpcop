//! Rules checked together in one batch find what each finds alone, and the
//! multi-rule path gives the single-rule path's findings on the cases its
//! walk could drop or add to (every other taint test asserts that too).

use super::tests_support::{check_parity, guarded_config, multi};
use super::*;
use crate::config::TaintConfig;

fn rule_of(cfg: &TaintConfig) -> TaintRule {
    TaintRule::new(cfg, typed::Typed::default(), std::env::temp_dir()).unwrap()
}

fn file(rel: &str, src: &str) -> SourceFile {
    SourceFile {
        rel: rel.into(),
        content: src.into(),
    }
}

/// The lines `cfg`'s rule reports, the paths having agreed.
fn lines(cfg: &TaintConfig, rel: &str, src: &str) -> Vec<usize> {
    let violations = check_parity(&rule_of(cfg), &file(rel, src));
    violations.iter().map(|v| v.line).collect()
}

fn js(id: &str, sources: &[&str], sinks: &[&str], sanitizers: &[&str]) -> TaintConfig {
    TaintConfig {
        id: id.into(),
        ..guarded_config("JavaScript", sources, sinks, sanitizers, &[])
    }
}

#[test]
fn a_summary_that_drops_its_argument_flows_nothing() {
    let src = "\
function zero(s) { return 1; }
function pass(s) { return s; }
function h(req) {
  const n = zero(req.query.id);
  db.query(n);
  const m = pass(zero(zero(req.query.id)));
  db.query(m);
  const k = pass(pass(req.query.id));
  db.query(k);
}
";
    let cfg = js("t", &["req.query.id"], &["$D.query($X)"], &[]);
    assert_eq!(lines(&cfg, "a.js", src), [9]);
}

#[test]
fn a_nested_function_does_not_see_names_its_parameters_shadow() {
    let src = "\
function h(req) {
  const id = req.query.id;
  [1].forEach(function (id) { db.query(id); });
  [2].forEach(function (x) { db.query(id); });
}
";
    let cfg = js("t", &["req.query.id"], &["$D.query($X)"], &[]);
    assert_eq!(lines(&cfg, "a.js", src), [4]);
}

#[test]
fn two_guards_of_one_rule_combine_in_an_or() {
    let src = "\
function h(req) {
  const x = req.query.x;
  if (isA(x) || isB(x)) { db.query(x); }
  if (isA(x) && isB(x)) { db.query(x); }
  if (isA(x)) { db.query(x); }
  if (!isB(x)) { return; }
  db.query(x);
}
function g(req) {
  const y = req.query.y;
  if (isA(y) || other(y)) { db.query(y); }
}
";
    let cfg = TaintConfig {
        guards: vec!["isA($X)".into(), "isB($X)".into()],
        ..js("t", &["req.query.x", "req.query.y"], &["$D.query($X)"], &[])
    };
    assert_eq!(lines(&cfg, "a.js", src), [11]);
}

#[test]
fn switch_arms_narrow_for_rules_without_guards() {
    let src = "\
function h(req) {
  const x = req.query.x;
  switch (x) {
    case 'a': db.query(x); break;
    default: db.query(x);
  }
}
";
    let cfg = js("t", &["req.query.x"], &["$D.query($X)"], &[]);
    assert_eq!(lines(&cfg, "a.js", src), [5]);
}

#[test]
fn a_sanitizer_name_cleans_only_the_call_it_names() {
    let src = "\
function h(req) {
  db.query(esc(req.query.a));
  db.query(esc(req.query.a) + req.query.b);
  db.query(req.query.b + esc(req.query.a));
}
";
    let cfg = TaintConfig {
        sanitizer_names: Some("esc".into()),
        ..js("t", &["req.query.a", "req.query.b"], &["$D.query($X)"], &[])
    };
    assert_eq!(lines(&cfg, "a.js", src), [3, 4]);
}

#[test]
fn a_renaming_macro_is_followed_before_deciding_the_file_has_no_source() {
    let src = "\
#define READ fgets
void run(void) {
    char buf[10];
    READ(buf, 10, stdin);
    system(buf);
}
";
    let cfg = TaintConfig {
        source_writes: vec!["fgets:0".into()],
        ..guarded_config("C", &[], &["system($X)"], &[], &[])
    };
    assert_eq!(lines(&cfg, "a.c", src), [5]);
}

/// A file with something for every rule below to find or miss.
const BATCH_SRC: &str = "\
function a(req) {
  const q = req.query.q;
  const b = req.body.b;
  db.query(q);
  db.query(esc(q));
  exec(b);
  exec(q);
  if (isOk(q)) { db.query(q); }
  rows.forEach(function (r) { db.query(r + q); });
  db.query(req.params.p);
}
function pass(s) { return s; }
function b(req) {
  db.query(pass(req.query.q));
  exec(pass(req.body.b));
}
";

fn batch() -> Vec<TaintConfig> {
    vec![
        js("db", &["req.query.q"], &["$D.query($X)"], &[]),
        js("shell", &["req.body.b", "req.query.q"], &["exec($X)"], &[]),
        js("clean", &["req.query.q"], &["$D.query($X)"], &["esc($X)"]),
        TaintConfig {
            guards: vec!["isOk($X)".into()],
            ..js("guarded", &["req.query.q"], &["$D.query($X)"], &[])
        },
        js("params", &["req.params.p"], &["$D.query($X)"], &[]),
        js("none", &["req.nothing"], &["$D.query($X)"], &[]),
    ]
}

#[test]
fn rules_in_one_batch_do_not_see_each_others_taint() {
    let rules: Vec<TaintRule> = batch().iter().map(rule_of).collect();
    let f = file("a.js", BATCH_SRC);
    let together = multi(&rules, &f);
    for rule in &rules {
        let info = rule.info();
        let mine = |vs: &[Violation]| -> Vec<(usize, usize)> {
            let mut at: Vec<_> = vs
                .iter()
                .filter(|v| v.rule == info.id)
                .map(|v| (v.line, v.column))
                .collect();
            at.sort();
            at
        };
        let alone = rule.check(&f);
        assert_eq!(mine(&alone), mine(&together), "rule {}", info.id);
    }
    let by_rule = |id: &str| together.iter().filter(|v| v.rule == id).count();
    assert!(by_rule("db") > 0 && by_rule("shell") > 0 && by_rule("params") == 1);
    assert_eq!(by_rule("none"), 0);
}

#[test]
fn a_batch_of_more_than_128_rules_checks_them_all() {
    let rules: Vec<TaintRule> = (0..130)
        .map(|i| {
            rule_of(&js(
                &format!("r{i}"),
                &["req.query.q"],
                &["$D.query($X)"],
                &[],
            ))
        })
        .collect();
    let src = "function h(req) { db.query(req.query.q); }";
    let found = multi(&rules, &file("a.js", src));
    let ids: std::collections::BTreeSet<&str> = found.iter().map(|v| v.rule.as_str()).collect();
    assert_eq!(found.len(), 130);
    assert_eq!(ids.len(), 130);
    assert!(ids.contains("r129") && ids.contains("r128") && ids.contains("r127"));
}
