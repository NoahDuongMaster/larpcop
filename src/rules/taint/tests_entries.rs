//! Map entries under literal keys are tainted one by one.

use super::tests_calls::{found, rule};

fn lines(lang: &str, rel: &str, src: &str, sources: &[&str]) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(rel), src).unwrap();
    let r = rule(lang, dir.path(), sources, &["sink($X)"], &[]);
    found(&r, dir.path(), rel).iter().map(|(l, _)| *l).collect()
}

#[test]
fn python_and_js_subscripts() {
    let py = "\
def a(req):
    m = {}
    m['a'] = 'fixed'
    m['b'] = req.query
    sink(m['a'])
    sink(m['b'])
    sink(str(m))
    m['b'] = 'clean now'
    sink(m['b'])
";
    assert_eq!(lines("Python", "a.py", py, &["req.query"]), [6, 7]);
    let js = "\
function a(req) {
  const m = {};
  m['a'] = 'fixed';
  m['b'] = req.query.q;
  sink(m['a']);
  sink(m['b']);
}
";
    assert_eq!(lines("JavaScript", "a.js", js, &["req.query"]), [6]);
}

#[test]
fn java_put_and_get() {
    let java = "\
class A {
  void f(Req req) {
    java.util.Map<String, Object> map = new java.util.HashMap<>();
    map.put(\"keyA\", \"a\");
    map.put(\"keyB\", req.getParameter(\"p\"));
    sink((String) map.get(\"keyA\"));
    sink((String) map.get(\"keyB\"));
  }
}
";
    assert_eq!(
        lines("Java", "A.java", java, &["req.getParameter($K)"]),
        [7]
    );
}

#[test]
fn guessed_method_keeps_receiver_taint() {
    // The class's own `get` is the only `get` the project defines; the
    // request's `.get` is not it.
    let py = "\
class Search(View):
    def get(self, req):
        q = req.query.get('q')
        sink(q)
";
    assert_eq!(lines("Python", "v.py", py, &["req.query"]), [4]);
}
