//! Argument vectors run through a shell (argv.rs): literal lists, lists built
//! by appends in `if`/`else` branches, Java's `ProcessBuilder` lists.

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::{ShellArgvConfig, TaintConfig};

fn shell_rule(lang: &str, root: &std::path::Path, sources: &[&str], sinks: &[&str]) -> TaintRule {
    let cfg = TaintConfig {
        shell_argv: Some(ShellArgvConfig {
            calls: "^(subprocess\\.(run|call|Popen|check_output)|ProcessBuilder|(.*\\.)?exec)$"
                .into(),
            shells: "(?i)(^|/)(sh|bash|zsh|cmd(\\.exe)?|powershell)$".into(),
            flags: "^(-c|/c|-Command)$".into(),
            vectors: Vec::new(),
        }),
        ..guarded_config(lang, sources, sinks, &[], &[])
    };
    TaintRule::new(&cfg, typed::Typed::default(), root.to_path_buf()).unwrap()
}

#[test]
fn argument_vectors_through_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.py"),
        "\
def a():
    q = request.args.get('q')
    subprocess.run(['sh', '-c', 'echo ' + q])
    subprocess.run(['ls', '-c', q])
    subprocess.run(['sh', '-c', 'echo hi', q])
    subprocess.run(['cmd.exe', '/c', 'echo', q])
    args = []
    if 'Windows' in os.name:
        args.append('cmd.exe')
        args.append('/c')
    else:
        args.append('sh')
        args.append('-c')
    args.append(f'echo {q}')
    subprocess.run(args, capture_output=True)
    plain = []
    plain.append('ls')
    plain.append(q)
    subprocess.run(plain)
    looped = ['sh', '-c']
    for x in q:
        looped.append(x)
    subprocess.run(looped)
",
    )
    .unwrap();
    let r = shell_rule(
        "Python",
        dir.path(),
        &["request.args.get($$$A)"],
        &["os.system($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "a.py")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // `sh -c 'echo hi' q` runs a constant (`q` is its `$0`); cmd.exe joins
    // the words after `/c`. A built list is reported where the command is added.
    assert_eq!(lines, [3, 6, 14]);

    std::fs::write(
        dir.path().join("A.java"),
        "\
class A {
    void a(HttpServletRequest request) throws Exception {
        String q = request.getParameter(\"q\");
        java.util.List<String> argList = new java.util.ArrayList<>();
        argList.add(\"sh\");
        argList.add(\"-c\");
        argList.add(\"echo \" + q);
        new ProcessBuilder(argList).start();
        Runtime.getRuntime().exec(new String[] {\"bash\", \"-c\", q});
        Runtime.getRuntime().exec(new String[] {\"echo\", q});
    }
}
",
    )
    .unwrap();
    let r = shell_rule(
        "Java",
        dir.path(),
        &["$R.getParameter($$$A)"],
        &["noSink($X)"],
    );
    let lines: Vec<usize> = found(&r, dir.path(), "A.java")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(lines, [7, 9]);
}
