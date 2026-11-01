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

/// Lists by position in straight-line code; a list changed in a branch or
/// passed on stays one whole.
#[test]
fn lists_by_position() {
    let py = r#"def a(req):
    param = req.GET.get('q')
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[1]
    sink(bar)

def b(req):
    param = req.GET.get('q')
    lst = []
    lst.append('safe')
    lst.append(param)
    lst.append('moresafe')
    lst.pop(0)
    bar = lst[0]
    sink(bar)

def c(req):
    param = req.GET.get('q')
    lst = []
    lst.append('safe')
    if param:
        lst.append(param)
    bar = lst[0]
    sink(bar)

def d(req):
    param = req.GET.get('q')
    lst = ['safe', param]
    helper(lst)
    bar = lst[0]
    sink(bar)
"#;
    assert_eq!(lines("Python", "l.py", py, &["req.GET"]), [19, 28, 35]);
    let java = r#"class L {
  void a(Req req) {
    String param = req.getParameter("p");
    java.util.List<String> valuesList = new java.util.ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0);
    String bar = valuesList.get(1);
    sink(bar);
  }
  void b(Req req) {
    String param = req.getParameter("p");
    java.util.List<String> valuesList = new java.util.ArrayList<String>();
    valuesList.add("safe");
    valuesList.add(param);
    valuesList.add("moresafe");
    valuesList.remove(0);
    String bar = valuesList.get(0);
    sink(bar);
  }
}
"#;
    assert_eq!(
        lines("Java", "L.java", java, &["req.getParameter($K)"]),
        [20]
    );
}

/// A bean the scope builds holds what its setters are given; a parameter
/// (`resp`) does not become tainted through its setters.
#[test]
fn setters_of_built_objects() {
    let java = "\
class A {
  void a(Req req, Resp resp) {
    PayRequest p = new PayRequest();
    p.setNote(req.getParameter(\"n\"));
    sink(client.execute(p));
    resp.setContentType(req.getParameter(\"t\"));
    sink(resp.getLocale());
  }
}
";
    assert_eq!(
        lines("Java", "A.java", java, &["req.getParameter($K)"]),
        [5]
    );
}

/// Two literal keys address one entry (`configparser`); a dict's
/// `get(k, default)` still reads `d[k]`.
#[test]
fn entries_under_two_keys() {
    let py = "\
def f(req):
    conf = configparser.ConfigParser()
    conf.add_section('s')
    conf.set('s', 'keyA', 'a-Value')
    conf.set('s', 'keyB', req.query)
    sink(conf.get('s', 'keyA'))
    sink(conf.get('s', 'keyB'))
    d = {}
    d['k'] = req.query
    sink(d.get('k', 'none'))
    sink(d.get('j', 'none'))
";
    assert_eq!(lines("Python", "a.py", py, &["req.query"]), [7, 10]);
}

/// An object with a field set from request data carries it when passed on
/// whole; its other fields stay clean.
#[test]
fn objects_with_tainted_fields() {
    let js = "\
function save(u) { sink(u.name); }
function a(req) {
  const o = {};
  o.name = req.query.n;
  o.kind = 'user';
  save(o);
  sink(o.kind);
  sink(o.name);
}
";
    assert_eq!(lines("JavaScript", "a.js", js, &["req.query"]), [6, 8]);
}
