//! C: data read into a buffer (`fgets`), copied (`strncat`), run through a
//! macro alias (`#define SYSTEM system`).

use super::tests_calls::found;
use super::tests_support::guarded_config;
use super::*;
use crate::config::TaintConfig;

const SRC: &str = "\
#ifdef _WIN32
#define SYSTEM _wsystem
#else
#define SYSTEM system
#endif
void run(void) {
    char buf[100] = \"ls \";
    char line[50];
    if (fgets(line, 50, stdin) != NULL) {
        strncat(buf, line, 50);
    }
    SYSTEM(buf);
}
void fixed(void) {
    char buf[100] = \"ls \";
    char line[50] = \"-l\";
    strncat(buf, line, 50);
    SYSTEM(buf);
}
void env(void) {
    char *home = getenv(\"HOME\");
    char cmd[200];
    sprintf(cmd, \"ls %s\", home);
    system(cmd);
}
";

#[test]
fn c_buffers_written_by_calls() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.c"), SRC).unwrap();
    let cfg = TaintConfig {
        source_writes: vec!["fgets:0".into(), "recv:1".into(), "scanf:1..".into()],
        copies: vec!["strncat:0".into(), "strcpy:0".into(), "sprintf:0".into()],
        ..guarded_config("C", &["getenv($$$A)"], &["system($X)"], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "a.c")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(lines, [12, 24]);
}

#[test]
fn c_functions_of_other_files_in_the_directory() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.c"),
        "\
void run_it(char *cmd);
void quiet(char *cmd);
void bad(void) {
    char *cmd = getenv(\"CMD\");
    run_it(cmd);
    quiet(cmd);
}
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.c"),
        "\
void run_it(char *cmd)
{
    system(cmd);
}

void quiet(char *cmd) {
    printf(\"%s\", cmd);
}
",
    )
    .unwrap();
    let r = super::tests_calls::rule("C", dir.path(), &["getenv($$$A)"], &["system($X)"], &[]);
    let lines: Vec<usize> = found(&r, dir.path(), "a.c")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    assert_eq!(lines, [5]);
}

#[test]
fn c_exec_vectors_through_a_shell() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.c"),
        "\
#define SHELL \"/bin/sh\"
#define ARG \"-c\"
void bad(void) {
    char *cmd = getenv(\"CMD\");
    execl(SHELL, SHELL, ARG, cmd, NULL);
    execl(\"/bin/ls\", \"ls\", cmd, NULL);
    char *args[] = {SHELL, ARG, cmd, NULL};
    execv(SHELL, args);
    _spawnl(0, \"cmd.exe\", \"cmd.exe\", \"/c\", \"dir\", cmd, NULL);
}
",
    )
    .unwrap();
    let cfg = TaintConfig {
        shell_argv: Some(crate::config::ShellArgvConfig {
            calls: "^(execl|execv|_spawnl)$".into(),
            shells: "(?i)(^|[/\\\\])(sh|cmd(\\.exe)?)$".into(),
            flags: "^(-c|/[cC])$".into(),
            vectors: vec!["execl:1..".into(), "execv:1".into(), "_spawnl:2..".into()],
        }),
        ..guarded_config("C", &["getenv($$$A)"], &["system($X)"], &[], &[])
    };
    let r = TaintRule::new(&cfg, typed::Typed::default(), dir.path().to_path_buf()).unwrap();
    let lines: Vec<usize> = found(&r, dir.path(), "a.c")
        .into_iter()
        .map(|(l, _)| l)
        .collect();
    // `ls cmd` runs no shell; `cmd.exe /c dir cmd` joins `cmd` into the command.
    assert_eq!(lines, [5, 7, 9]);
}

#[test]
fn c_pointers_function_pointers_and_globals() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("a.c"),
        "\
static char *saved;
static char *quiet;
static void show(char *s) { printf(s); }
static void show_saved(void) { char *s = saved; printf(s); }
static void show_quiet(void) { printf(quiet); }
void through_pointer(void) {
    char *data = \"\";
    char **in = &data;
    char **out = &data;
    {
        char *data = getenv(\"X\");
        *in = data;
    }
    {
        char *data = *out;
        printf(data);
    }
}
void through_function_pointer(void) {
    void (*fp)(char *) = show;
    fp(getenv(\"X\"));
}
void through_global(void) {
    saved = getenv(\"X\");
    quiet = \"fixed\";
    show_saved();
    show_quiet();
}
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("b.c"),
        "\
extern char *shared;
void show_shared(void) { printf(shared); }
void print_it(char *s) { printf(s); }
",
    )
    .unwrap();
    std::fs::write(
        dir.path().join("c.c"),
        "\
char *shared;
void show_shared(void);
void print_it(char *s);
void across_files(void) {
    void (*fp)(char *) = print_it;
    shared = getenv(\"X\");
    show_shared();
    fp(getenv(\"Y\"));
}
",
    )
    .unwrap();
    let r = super::tests_calls::rule(
        "C",
        dir.path(),
        &["getenv($$$A)"],
        &["printf($F, $$$A)", "printf($F)"],
        &[],
    );
    let lines = |f: &str| -> Vec<usize> {
        found(&r, dir.path(), f)
            .into_iter()
            .map(|(l, _)| l)
            .collect()
    };
    assert_eq!(lines("a.c"), [16, 21, 26]);
    assert_eq!(lines("c.c"), [7, 8]);
}
