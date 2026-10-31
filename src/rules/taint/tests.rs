use super::*;

fn rule(
    langs: &[&str],
    sources: &[&str],
    sinks: &[&str],
    arg: Option<&str>,
    sanitizers: &[&str],
) -> TaintRule {
    let s = |v: &[&str]| v.iter().map(|x| x.to_string()).collect();
    TaintRule::new(
        &TaintConfig {
            id: "sql-taint".into(),
            languages: s(langs),
            severity: None,
            message: "request data reaches SQL".into(),
            note: None,
            sources: s(sources),
            sinks: s(sinks),
            sink_arg: arg.map(String::from),
            sanitizers: s(sanitizers),
            safe_prefix: None,
            guards: Vec::new(),
            param_types: [("Request".to_string(), "req".to_string())].into(),
            param_decorators: Vec::new(),
            handler_decorators: None,
            resolver_args: false,
            sink_types: Default::default(),
        },
        typed::Typed::default(),
        std::env::temp_dir(),
    )
    .unwrap()
}

fn lines(r: &TaintRule, rel: &str, src: &str) -> Vec<usize> {
    let file = SourceFile {
        rel: rel.into(),
        content: src.into(),
    };
    r.check(&file).iter().map(|v| v.line).collect()
}

#[test]
fn follows_assignments_within_a_function() {
    let r = rule(
        &["TypeScript"],
        &["req.query"],
        &["$DB.query($SQL)"],
        Some("SQL"),
        &["Number($X)"],
    );
    let src = "\
function a(req) {
  const id = req.query.id;
  const sql = `select * from u where id = ${id}`;
  return db.query(sql);
}
function b(req) {
  const id = Number(req.query.id);
  return db.query(`select ${id}`);
}
function c(req) {
  let id = req.query.id;
  id = Number(id);
  return db.query(`select ${id}`);
}
function d(req) {
  const { id } = req.query;
  return db.query('select ' + id);
}
function e(id) {
  return db.query(`select ${id}`);
}
";
    // a: through two variables; b: sanitized; c: re-assigned clean; d: destructuring;
    // e: a parameter is not a source (no interprocedural tracking).
    assert_eq!(lines(&r, "x.ts", src), [4, 17]);
}

#[test]
fn python_flask_to_cursor() {
    let r = rule(
        &["Python"],
        &["request.args", "request.form"],
        &["$C.execute($SQL)", "$C.execute($SQL, $P)"],
        Some("SQL"),
        &["int($X)"],
    );
    let src = "\
def view():
    name = request.args.get('name')
    q = \"select * from u where name = '%s'\" % name
    cur.execute(q)
    uid = int(request.args['id'])
    cur.execute(f\"select * from u where id = {uid}\")
    cur.execute(\"select * from u where name = %s\", (name,))
";
    assert_eq!(lines(&r, "app.py", src), [4]);
}

#[test]
fn destructured_variables_and_typed_parameters() {
    let r = rule(
        &["TypeScript"],
        &["req.query"],
        &["$RES.redirect($URL)"],
        Some("URL"),
        &[],
    );
    let src = "\
function a(req, res) {
  const { query } = req;
  res.redirect(query.to);
}
const b = ({ query }: Request, res: Response) => {
  const toUrl = query.to as string;
  res.redirect(toUrl);
};
function c(req, res) {
  const { params } = req;
  res.redirect(params.to);
}
const d = ({ query }: Other, res) => res.redirect(query.to);
function e(req, res) {
  const { query: q } = req;
  res.redirect(q.to);
}
";
    // c: `req.params` is not a source here; d: not a Request.
    assert_eq!(lines(&r, "x.ts", src), [3, 7, 16]);
}
