//! Taint in C#/Java shapes: classes of the same directory, `new X().M()`,
//! `+=`, bare class fields, `List.Add`, chains of classes past two imports.

use super::tests_calls::{found, rule};

#[test]
fn csharp_classes_of_the_same_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("Sink.cs"),
        "\
public class Sink
{
    public static void Run(string data) { Db.Exec(data); }
    public void Write(string data) { Db.Exec(data); }
}
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("Page.cs"),
        "\
public class Page
{
    private string saved;
    public void A(HttpRequest req) { Sink.Run(req.QueryString[\"id\"]); }
    public void B(HttpRequest req) { (new Sink()).Write(req.QueryString[\"id\"]); }
    public void C(HttpRequest req)
    {
        var cmd = \"\";
        cmd += req.QueryString[\"id\"];
        cmd += \" and 1=1\";
        Db.Exec(cmd);
    }
    public void D(HttpRequest req) { saved = req.QueryString[\"id\"]; }
    public void E() { Db.Exec(saved); }
    public void F(HttpRequest req)
    {
        var list = new List<string>();
        list.Add(req.QueryString[\"id\"]);
        Db.Exec(list[0]);
    }
    public void G(string saved) { Db.Exec(saved); }
}
",
    )
    .unwrap();
    let r = rule(
        "CSharp",
        dir.path(),
        &["req.QueryString"],
        &["Db.Exec($X)"],
        &[],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "Page.cs")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    // A, B through Sink.cs; C after `+=` of a constant; E reads the field D
    // stored; F through the list. G's `saved` is its own parameter.
    assert_eq!(lines, [4, 5, 11, 14, 19]);
}

/// Past two imports, only files leading to a sink are followed: a chain of
/// four classes still reaches it, and a chain that cleans the value on the way
/// stays clean.
#[test]
fn chains_past_two_imports() {
    let dir = tempfile::tempdir().unwrap();
    let class = |name: &str, body: &str| {
        let src = format!(
            "public class {name} {{\n    public static void Run(string d) {{ {body} }}\n}}\n"
        );
        std::fs::write(dir.path().join(format!("{name}.cs")), src).unwrap();
    };
    class("A", "B.Run(d);");
    class("B", "C.Run(d);");
    class("C", "D.Run(d);");
    class("D", "Db.Exec(d);");
    class("E", "F.Run(int.Parse(d).ToString());");
    class("F", "G.Run(d);");
    class("G", "Db.Exec(d);");
    std::fs::write(
        dir.path().join("Page.cs"),
        "public class Page\n{\n    public void P(HttpRequest req) { A.Run(req.QueryString[\"id\"]); }\n    public void Q(HttpRequest req) { E.Run(req.QueryString[\"id\"]); }\n}\n",
    )
    .unwrap();
    let r = rule(
        "CSharp",
        dir.path(),
        &["req.QueryString"],
        &["Db.Exec($X)"],
        &["int.Parse($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "Page.cs")
        .iter()
        .map(|(l, _)| *l)
        .collect();
    assert_eq!(lines, [3]);
}
