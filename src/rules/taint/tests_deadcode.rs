//! Branches decided by known values: the dead side does not count.

use super::tests_calls::{found, rule};

fn lines(lang: &str, rel: &str, src: &str, source: &str) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(rel), src).unwrap();
    let r = rule(lang, dir.path(), &[source], &["sink($X)"], &[]);
    found(&r, dir.path(), rel).iter().map(|(l, _)| *l).collect()
}

/// `if`, `x if c else y`, `in` on a known string, `match` on `"ABC"[1]`; the
/// last function's condition is a parameter and decides nothing.
#[test]
fn python() {
    let py = r#"def a(req):
    param = req.GET.get('q')
    num = 86
    if 7 * 42 - num > 200:
        bar = 'This_should_always_happen'
    else:
        bar = param
    sink(bar)

def b(req):
    param = req.GET.get('q')
    bar = "This should never happen"
    if 'should' in bar:
        bar = param
    sink(bar)

def c(req):
    param = req.GET.get('q')
    num = 106
    bar = "This_should_always_happen" if 7 * 18 + num > 200 else param
    sink(bar)

def d(req):
    param = req.GET.get('q')
    possible = "ABC"
    guess = possible[1]
    match guess:
        case 'A':
            bar = param
        case 'B':
            bar = 'bob'
        case _:
            bar = param
    sink(bar)

def e(req):
    param = req.GET.get('q')
    TestParam = "This should never happen"
    if 'should' not in TestParam:
        bar = "Ifnot case passed"
    else:
        bar = param
    sink(bar)

def f(req, n):
    param = req.GET.get('q')
    if n > 200:
        bar = 'x'
    else:
        bar = param
    sink(bar)
"#;
    assert_eq!(lines("Python", "a.py", py, "req.GET"), [15, 43, 51]);
}

/// Ternary, `if`/`else`, `switch` on `charAt` with fall-through.
#[test]
fn java() {
    let java = r#"class A {
  void a(Req req) {
    String param = req.getParameter("p");
    int num = 106;
    String bar = (7 * 18) + num > 200 ? "This_should_always_happen" : param;
    sink(bar);
  }
  void b(Req req) {
    String param = req.getParameter("p");
    String bar;
    int num = 86;
    if ((7 * 42) - num > 200) bar = "This_should_always_happen";
    else bar = param;
    sink(bar);
  }
  void c(Req req) {
    String param = req.getParameter("p");
    String bar;
    String guess = "ABC";
    char switchTarget = guess.charAt(1);
    switch (switchTarget) {
      case 'A': bar = param; break;
      case 'B': bar = "bob"; break;
      case 'C':
      case 'D': bar = param; break;
      default: bar = "bob's your uncle"; break;
    }
    sink(bar);
  }
  void d(Req req) {
    String param = req.getParameter("p");
    String bar;
    String guess = "ABC";
    char switchTarget = guess.charAt(2);
    switch (switchTarget) {
      case 'A': bar = param; break;
      case 'B': bar = "bob"; break;
      case 'C':
      case 'D': bar = param; break;
      default: bar = "bob's your uncle"; break;
    }
    sink(bar);
  }
}
"#;
    assert_eq!(lines("Java", "A.java", java, "req.getParameter($K)"), [42]);
}
