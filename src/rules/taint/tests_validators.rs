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
