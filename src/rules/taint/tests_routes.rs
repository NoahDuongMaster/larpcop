//! `request.path` in handlers of routes without variables (routes.rs).

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;

fn path_rule(root: &std::path::Path) -> TaintRule {
    let cfg = TaintConfig {
        handler_decorators: Some(r"^\w+\.(get|post|put|patch|delete|route)\(".into()),
        fixed_route_sources: vec!["request.path".into()],
        ..guarded_config(
            "Python",
            &["request.path", "request.args"],
            &["os.system($X)"],
            &[],
            &[],
        )
    };
    TaintRule::new(&cfg, typed::Typed::default(), root.to_path_buf()).unwrap()
}

const VIEWS: &str = "\
@app.route('/benchmark/a', methods=['POST'])
def a():
    parts = request.path.split('/')
    os.system('echo ' + parts[1])

@app.route('/files/<path:name>')
def b(name):
    os.system('cat ' + request.path)

@app.route('/x')
@app.route('/y/<int:id>')
def c(id=0):
    os.system(request.path)

def d():
    os.system(request.path)

@app.route('/z')
def e():
    os.system(request.args['q'])
";

#[test]
fn the_path_of_a_route_without_variables_is_a_constant() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("views.py"), VIEWS).unwrap();
    let lines = |r: &TaintRule| -> Vec<usize> {
        found(r, dir.path(), "views.py")
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    };
    assert_eq!(lines(&path_rule(dir.path())), [8, 13, 16, 20]);

    // A blueprint mounted under a prefix with variables, in another file.
    std::fs::write(
        dir.path().join("app.py"),
        "app.register_blueprint(bp, url_prefix='/<lang>')\n",
    )
    .unwrap();
    assert_eq!(lines(&path_rule(dir.path())), [4, 8, 13, 16, 20]);
}
