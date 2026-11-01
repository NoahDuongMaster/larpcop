//! A branch that replaces an unsafe value, and appending to a value that
//! starts safely, and arms of a `switch` on fixed values.

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

/// A ternary is one of its sides: the condition is not its value, and a
/// guard in it cleans the side it protects.
#[test]
fn ternary_sides() {
    let js = "\
function a(req, res) {
  const u = req.query.next;
  res.redirect(isLocal(u) ? u : '/');
  res.redirect(u.startsWith('/') ? '/home' : '/login');
  res.redirect(isLocal(u) ? '/' : u);
  res.redirect(u ? u : '/');
}
";
    let cfg = TaintConfig {
        sinks: vec!["res.redirect($U)".into()],
        guards: vec!["isLocal($U)".into()],
        ..Default::default()
    };
    assert_eq!(reported("JavaScript", "a.js", js, cfg), [5, 6]);
}

/// A fixed-prefix check is a path guard only on a resolved path.
#[test]
fn prefix_checks_need_a_resolved_path() {
    let js = "\
function f(req) {
  const raw = req.query.f;
  if (raw.startsWith('/srv/')) {
    sink(raw);
  }
  const resolved = path.resolve(raw);
  if (resolved.startsWith('/srv/')) {
    sink(resolved);
  }
}
";
    let cfg = TaintConfig {
        sinks: vec!["sink($U)".into()],
        guards: vec!["$P.startsWith($B)".into()],
        ..Default::default()
    };
    assert_eq!(reported("JavaScript", "a.js", js, cfg), [4]);
}

/// In an arm of a `switch`/`when`/`match` on fixed values the subject is one
/// of them; a default arm, a variable label, or falling through from one is not.
#[test]
fn switch_arms_on_fixed_values() {
    let cfg = || TaintConfig {
        sinks: vec!["q($U)".into()],
        ..Default::default()
    };
    let js = "\
function f(req) {
  const s = req.query;
  switch (s) {
    case 'a':
    case 'b':
      q(s);
      break;
    case other:
    case 'c':
      q(s);
      break;
    default:
      q(s);
  }
}
";
    assert_eq!(reported("JavaScript", "a.js", js, cfg()), [10, 13]);
    let java = "\
class A {
  void f(Req req) {
    String s = req.getParameter(\"s\");
    switch (s) {
      case \"a\": q(s); break;
      case Mode.FAST: q(s); break;
      default: q(s);
    }
    String r = switch (s) { case \"x\" -> q(s); default -> q(s); };
  }
}
";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A.java"), java).unwrap();
    let rule = super::tests_calls::rule(
        "Java",
        dir.path(),
        &["$R.getParameter($K)"],
        &["q($X)"],
        &[],
    );
    let lines: Vec<usize> = found(&rule, dir.path(), "A.java")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [7, 9]);
    let kt = "\
fun f(req: Req) {
    val s = req.query
    when (s) {
        \"a\", \"b\" -> q(s)
        in ALLOWED -> q(s)
        other -> q(s)
        else -> q(s)
    }
}
";
    assert_eq!(reported("Kotlin", "A.kt", kt, cfg()), [6, 7]);
    let go = "\
package m

func f(req *Req) {
\ts := req.query
\tswitch s {
\tcase \"a\", \"b\":
\t\tq(s)
\tdefault:
\t\tq(s)
\t}
}
";
    assert_eq!(reported("Go", "a.go", go, cfg()), [9]);
    let py = "\
def f(req):
    s = req.query
    match s:
        case 'a' | 'b':
            q(s)
        case x:
            q(s)
";
    assert_eq!(reported("Python", "a.py", py, cfg()), [7]);
    let cs = "\
class A {
  void F(Req req) {
    var s = req.query;
    switch (s) {
      case \"a\": q(s); break;
      default: q(s); break;
    }
  }
}
";
    assert_eq!(reported("CSharp", "A.cs", cs, cfg()), [6]);
}
