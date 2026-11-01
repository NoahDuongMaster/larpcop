//! Validators of the project's own guard the argument where they are called.

use super::TaintRule;
use super::tests_calls::found;
use crate::config::TaintConfig;

fn reported(lang: &str, rel: &str, src: &str, rejects: &[&str], sink: &str) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(rel), src).unwrap();
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
    let rule = TaintRule::new(
        &TaintConfig {
            id: "taint".into(),
            languages: vec![lang.into()],
            message: "m".into(),
            sources: s(&["req.query"]),
            sinks: s(&[sink]),
            sink_arg: Some("X".into()),
            rejects: s(rejects),
            ..Default::default()
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

const JS: &str = "\
function pathFilter(p) {
  if (p.includes('..') || p.startsWith('/')) { return null; }
  return p;
}
function isSafe(p) { return !p.includes('..'); }
function notChecked(p) {
  if (p.length === 0) { return null; }
  return p;
}
function a(req) {
  const f = req.query.f;
  if (pathFilter(f) === null) { return; }
  fs.readFileSync(f);
}
function b(req) {
  const f = req.query.f;
  if (!isSafe(f)) { throw new Error('bad'); }
  fs.readFileSync(f);
}
function c(req) {
  const f = req.query.f;
  if (notChecked(f) === null) { return; }
  fs.readFileSync(f);
}
function d(req) {
  const f = req.query.f;
  if (isSafe(f)) { fs.readFileSync(f); }
  fs.readFileSync(f);
}
";

#[test]
fn null_or_false_unless_checked() {
    let sink = "fs.readFileSync($X)";
    // Nothing known to validate: every read is reported.
    assert_eq!(
        reported("JavaScript", "a.js", JS, &[], sink),
        [13, 18, 23, 27, 28]
    );
    // c: `notChecked` fails on an unrelated condition; d: safe only inside the `if`.
    let rejects = ["$P.includes('$S')"];
    assert_eq!(reported("JavaScript", "a.js", JS, &rejects, sink), [23, 28]);
}

#[test]
fn python_bool_validator() {
    let src = "\
def is_safe(name):
    if '..' in name:
        return False
    return True

def view(req):
    name = req.query['n']
    if not is_safe(name):
        abort(400)
    open(name)
";
    let got = reported("Python", "v.py", src, &["'$S' in $P"], "open($X)");
    assert!(got.is_empty(), "{got:?}");
}

/// A check passed as a lambda to a helper that runs the sink only when the
/// check holds: judged with the rule's guards at the call.
#[test]
fn lambda_checks() {
    let java = "\
class A {
  private void readFile(Supplier<Boolean> condition, String name) {
    if (condition.get()) {
      sink(name);
    }
  }
  void a(Req req) {
    String f = req.getParameter(\"f\");
    this.readFile(() -> f != null && ALLOWED.contains(f), f);
    this.readFile(() -> f != null, f);
  }
}
";
    let js = "\
function readFile(cond, name) {
  if (cond()) {
    sink(name);
  }
}
function a(req) {
  const f = req.query.f;
  readFile(() => allowed.includes(f), f);
  readFile(() => true, f);
}
";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A.java"), java).unwrap();
    std::fs::write(dir.path().join("a.js"), js).unwrap();
    let lines = |lang: &str, rel: &str, source: &str, guard: &str| -> Vec<usize> {
        let r =
            super::tests_calls::guarded(lang, dir.path(), &[source], &["sink($X)"], &[], &[guard]);
        super::tests_calls::found(&r, dir.path(), rel)
            .iter()
            .map(|(l, _)| *l)
            .collect()
    };
    assert_eq!(
        lines("Java", "A.java", "req.getParameter($K)", "$L.contains($X)"),
        [10]
    );
    assert_eq!(
        lines("JavaScript", "a.js", "req.query", "$L.includes($X)"),
        [9]
    );
}

/// A method reference applied to the sink's argument, a boolean parameter
/// computed by a lambda kept in a variable.
#[test]
fn method_references_and_boolean_checks() {
    let java = "\
class A {
  private void go(String url, Function<String, Boolean> validator) {
    if (validator.apply(url)) {
      sink(url);
    }
  }
  private void ping(String ip, boolean isValid) {
    if (isValid) {
      sink(ip);
    }
  }
  void a(Req req) {
    String u = req.getParameter(\"u\");
    this.go(u, ALLOWED::contains);
    this.go(u, Objects::nonNull);
    Supplier<Boolean> validator = () -> u != null && ALLOWED.contains(u);
    this.ping(u, validator.get());
    this.ping(u, u != null);
  }
}
";
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("A.java"), java).unwrap();
    let r = super::tests_calls::guarded(
        "Java",
        dir.path(),
        &["req.getParameter($K)"],
        &["sink($X)"],
        &[],
        &["$L.contains($X)"],
    );
    let lines: Vec<usize> = super::tests_calls::found(&r, dir.path(), "A.java")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [15, 18]);
}

/// A loop runs until its condition fails: after `while (p has "..")` with no
/// `break`, `p` has none; inside the loop the condition holds.
#[test]
fn loop_conditions() {
    let js = "\
function a(req) {
  let p = req.query.p;
  while (p.includes('..')) {
    p = p.replace('..', '');
  }
  fs.readFile(p);
}
function b(req) {
  let p = req.query.p;
  while (p.includes('..')) {
    if (p.length > 9) break;
    p = p.replace('..', '');
  }
  fs.readFile(p);
}
function c(req) {
  let p = req.query.p;
  do { p = p.replace('..', ''); } while (p.includes('..'));
  fs.readFile(p);
}
";
    let rejects = ["$P.includes('$S')"];
    assert_eq!(
        reported("JavaScript", "a.js", js, &rejects, "fs.readFile($X)"),
        [14]
    );
    let py = "\
def a(req):
    p = req.query
    while '..' in p:
        p = p.replace('..', '')
    open(p)
";
    assert_eq!(
        reported("Python", "a.py", py, &["'$S' in $P"], "open($X)"),
        Vec::<usize>::new()
    );
    let rb = "\
def a(req)
  p = req.query
  p = p.sub('..', '') while p.include?('..')
  File.read(p)
end
";
    assert_eq!(
        reported("Ruby", "a.rb", rb, &["$P.include?('$S')"], "File.read($X)"),
        Vec::<usize>::new()
    );
}
