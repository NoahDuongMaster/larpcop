//! Data written into a stream, serialized, and read back elsewhere.

use super::tests_calls::found;
use super::tests_support::guarded_config;

fn lines(
    lang: &str,
    files: &[(&str, &str)],
    checked: &str,
    source: &str,
    sink: &str,
) -> Vec<usize> {
    let dir = tempfile::tempdir().unwrap();
    for (rel, src) in files {
        std::fs::write(dir.path().join(rel), src).unwrap();
    }
    let cfg = guarded_config(lang, &[source], &[sink], &[], &[]);
    let rule = super::TaintRule::new(
        &cfg,
        super::typed::Typed::default(),
        dir.path().to_path_buf(),
    )
    .unwrap();
    found(&rule, dir.path(), checked)
        .iter()
        .map(|(l, _)| *l)
        .collect()
}

#[test]
fn serialized_data_carries_its_taint() {
    let a = "\
class A {
  void bad(HttpServletRequest request) throws Exception {
    String data = request.getParameter(\"name\");
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutput out = new ObjectOutputStream(bytes);
    out.writeObject(data);
    byte[] serialized = bytes.toByteArray();
    (new B()).sink(serialized);
  }
  void good() throws Exception {
    ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    ObjectOutput out = new ObjectOutputStream(bytes);
    out.writeObject(\"foo\");
    (new B()).sink(bytes.toByteArray());
  }
}
";
    let b = "\
class B {
  void sink(byte[] serialized) throws Exception {
    ObjectInput in = new ObjectInputStream(new ByteArrayInputStream(serialized));
    String data = (String) in.readObject();
    db.query(data);
  }
}
";
    let java = lines(
        "Java",
        &[("A.java", a), ("B.java", b)],
        "A.java",
        "$R.getParameter($K)",
        "db.query($X)",
    );
    assert_eq!(java, [8]);
    let cs = "\
class A {
  void Bad(HttpRequest req) {
    string data = req.Query[\"q\"];
    BinaryFormatter formatter = new BinaryFormatter();
    MemoryStream stream = new MemoryStream();
    formatter.Serialize(stream, data);
    byte[] serialized = stream.ToArray();
    string back = (string) formatter.Deserialize(new MemoryStream(serialized));
    db.query(back);
  }
}
";
    assert_eq!(
        lines(
            "CSharp",
            &[("A.cs", cs)],
            "A.cs",
            "$R.Query[$K]",
            "db.query($X)"
        ),
        [9]
    );
}

/// Only streams and writers pass writes on to what they were built around:
/// a cookie filled by a setter does not taint its name.
#[test]
fn only_streams_wrap() {
    let a = "\
class A {
  void f(HttpServletRequest request) {
    String name = \"rememberMe\";
    Cookie c = new Cookie(name, \"v\");
    c.setPath(request.getRequestURI());
    db.query(name);
  }
}
";
    assert!(
        lines(
            "Java",
            &[("A.java", a)],
            "A.java",
            "$R.getRequestURI()",
            "db.query($X)"
        )
        .is_empty()
    );
}

/// A static field of another class read by the callee: reported where the
/// caller set it from request data and calls, not where it set a constant.
#[test]
fn static_fields_read_by_callees() {
    let a = "\
public class CaseA {
  public static String data;
  public void bad(HttpServletRequest request) {
    data = request.getParameter(\"name\");
    (new CaseB()).badSink();
  }
  public void good(HttpServletRequest request) {
    data = \"foo\";
    (new CaseB()).badSink();
  }
  public void other(HttpServletRequest request) {
    CaseA.data = request.getParameter(\"name\");
    (new CaseB()).goodSink();
  }
}
";
    let b = "\
public class CaseB {
  public void badSink() {
    String data = CaseA.data;
    db.query(\"SELECT \" + data);
  }
  public void goodSink() {
    String data = CaseA.data;
    db.query(\"SELECT 1\");
  }
}
";
    let java = lines(
        "Java",
        &[("CaseA.java", a), ("CaseB.java", b)],
        "CaseA.java",
        "$R.getParameter($K)",
        "db.query($X)",
    );
    assert_eq!(java, [5]);
}
