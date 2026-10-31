//! A branch that replaces an unsafe value, and appending to a value that
//! starts safely.

use super::TaintRule;
use super::tests_calls::found;
use crate::config::TaintConfig;

fn reported(lang: &str, rel: &str, src: &str, cfg: TaintConfig) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(rel), src).unwrap();
    let rule = TaintRule::new(
        &TaintConfig {
            id: "taint".into(),
            languages: vec![lang.into()],
            message: "m".into(),
            sources: vec!["req.query".into()],
            sink_arg: Some("U".into()),
            ..cfg
        },
        super::typed::Typed::default(),
        dir.path().to_path_buf(),
    )
    .unwrap();
    found(&rule, dir.path(), rel)
        .iter()
        .map(|(l, _)| *l)
        .collect()
}

#[test]
fn check_then_replace_and_safe_append() {
    let src = "\
function a(req, res) {
  let next = req.query.next;
  if (!next || !next.startsWith('/')) { next = '/home'; }
  res.redirect(next);
}
function b(req, res) {
  let next = req.query.next;
  if (!next) { next = '/home'; }
  res.redirect(next);
}
function c(req, res) {
  let url = buildUrl('search');
  url += '?q=' + req.query.q;
  res.redirect(url);
}
function d(req, res) {
  let url = '';
  url += req.query.to;
  res.redirect(url);
}
function e(req, res) {
  res.redirect(buildUrl('search') + '?q=' + req.query.q);
}
";
    let cfg = TaintConfig {
        sinks: vec!["res.redirect($U)".into()],
        guards: vec!["$U.startsWith($P)".into()],
        safe_prefix: Some("^/[^/\\\\]".into()),
        sanitizer_names: Some("^buildUrl$".into()),
        ..Default::default()
    };
    // b: no check, the replacement only covers a missing value; d: starts empty.
    assert_eq!(reported("JavaScript", "r.js", src, cfg), [9, 19]);
}

#[test]
fn java_validator_replaced_in_branch() {
    let src = "\
class R {
  void a(HttpServletRequest req, HttpServletResponse res) throws Exception {
    String to = req.query(\"to\");
    if (!to.startsWith(\"/\")) {
      to = \"/home\";
    }
    res.sendRedirect(to);
  }
}
";
    let cfg = TaintConfig {
        sinks: vec!["$R.sendRedirect($U)".into()],
        guards: vec!["$U.startsWith($P)".into()],
        safe_prefix: Some("^/[^/\\\\]".into()),
        ..Default::default()
    };
    assert!(reported("Java", "R.java", src, cfg).is_empty());
}
