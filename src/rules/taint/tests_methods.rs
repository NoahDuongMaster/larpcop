//! Methods: known to callers as `Class.method`, also across imports, with
//! Python's `self` / `cls` not counted among the arguments.

use super::tests_calls::{found, rule};

#[test]
fn methods_of_imported_classes() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(dir.path().join("app/dao")).unwrap();
    std::fs::write(
        dir.path().join("app/dao/student.py"),
        "\
class Student:
    @staticmethod
    async def create(conn, name):
        q = \"INSERT INTO students (name) VALUES ('\" + name + \"')\"
        await conn.execute(q)

    def rename(self, conn, name):
        conn.execute(\"UPDATE students SET name = '\" + name + \"'\")
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("app/views.py"),
        "\
from app.dao.student import Student

async def add(request):
    data = await request.post()
    await Student.create(conn, data['name'])
    await Student.create(data['name'], 'fixed')

def rename(request, student):
    student.rename(conn, request.args['name'])
",
    )
    .unwrap();
    let r = rule(
        "Python",
        dir.path(),
        &["await request.post()", "request.args"],
        &["$C.execute($X)"],
        &[],
    );
    let hits = found(&r, dir.path(), "app/views.py");
    // The second call passes request data as `conn`, which never reaches SQL.
    assert_eq!(
        hits.iter().map(|(l, _)| *l).collect::<Vec<_>>(),
        [5, 9],
        "{hits:?}"
    );
    assert!(hits[0].1.contains("`Student.create`"), "{hits:?}");
}
