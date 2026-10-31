mod common;

use common::{BAD_TS, GOOD_TS, Repo, STANDARDS, copy_dir, extends_yaml, file_url};
use std::path::Path;

#[test]
fn reports_violations_across_languages() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    repo.write("job.py", "try:\n    run()\nexcept:\n    pass\n");
    repo.write(
        "main.go",
        "package main\n\nfunc main() {\n\tpanic(\"boom\")\n}\n",
    );
    let big: String = (0..301).map(|i| format!("x{i} = {i}\n")).collect();
    repo.write("big.py", &big);

    let run = repo.run(&["check"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    for id in [
        "no-explicit-any",
        "no-console",
        "py-no-bare-except",
        "go-no-panic",
        "max-lines",
    ] {
        assert!(out.contains(id), "missing {id} in:\n{out}");
    }
    assert!(out.contains("src/a.ts"), "{out}");
}

#[test]
fn clean_code_passes() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", GOOD_TS);
    let run = repo.run(&["check"]);
    assert_eq!(run.code(), 0, "{}", run.stdout());
    assert!(run.stdout().contains("no violations"));
}

#[test]
fn locked_rule_cannot_be_disabled() {
    let repo = Repo::new();
    repo.write(
        ".agentkit.yaml",
        &format!("{}disable: [no-explicit-any]\n", extends_yaml(STANDARDS)),
    );
    let run = repo.run(&["check"]);
    assert_eq!(run.code(), 3);
    assert!(
        run.stderr()
            .contains("cannot disable rule `no-explicit-any`"),
        "{}",
        run.stderr()
    );
}

#[test]
fn unlocked_rule_can_be_disabled() {
    let repo = Repo::new();
    repo.write(
        ".agentkit.yaml",
        &format!("{}disable: [no-console]\n", extends_yaml(STANDARDS)),
    );
    repo.write("a.ts", "console.log(1);\n");
    assert_eq!(repo.run(&["check"]).code(), 0);
}

#[test]
fn forced_standards_apply_without_repo_config() {
    let repo = Repo::new();
    repo.write("a.ts", BAD_TS);
    assert!(
        repo.run(&["check"])
            .stdout()
            .contains("no rules configured")
    );
    let run = repo.run(&["check", "--extends", STANDARDS]);
    assert_eq!(run.code(), 1);
    assert!(run.stdout().contains("no-explicit-any"));
}

#[test]
fn standards_from_git_at_a_pinned_tag() {
    let standards = Repo::new();
    copy_dir(Path::new(STANDARDS), &standards.path());
    standards.commit_all("v1");
    standards.git(&["tag", "v1.0.0"]);

    let repo = Repo::new();
    let url = format!("{}#v1.0.0", file_url(&standards.path()));
    repo.write(".agentkit.yaml", &extends_yaml(&url));
    repo.write("a.ts", BAD_TS);
    let run = repo.run(&["check"]);
    assert_eq!(run.code(), 1, "{}{}", run.stdout(), run.stderr());
    assert!(run.stdout().contains("no-explicit-any"));
    assert!(repo.run(&["rules"]).stdout().contains("#v1.0.0"));
}

#[test]
fn recommended_standards_from_a_git_subdirectory() {
    let upstream = Repo::new();
    let recommended = concat!(env!("CARGO_MANIFEST_DIR"), "/standards/recommended");
    copy_dir(
        Path::new(recommended),
        &upstream.path().join("standards/recommended"),
    );
    upstream.commit_all("recommended");
    upstream.git(&["tag", "v2.0.0"]);

    let repo = Repo::new();
    let url = format!(
        "{}#v2.0.0//standards/recommended",
        file_url(&upstream.path())
    );
    repo.write(".agentkit.yaml", &extends_yaml(&url));
    repo.write(
        "db.ts",
        "export const q = (id: string) => db.query(`select * from u where id = ${id}`);\n",
    );
    repo.write("ok.py", "import yaml\ndata = yaml.load(open('a.yml'))\n");
    let run = repo.run(&["check"]);
    assert_eq!(run.code(), 1, "{}{}", run.stdout(), run.stderr());
    let out = run.stdout();
    assert!(
        out.contains("no-sql-interpolation") && out.contains("py-yaml-safe-load"),
        "{out}"
    );
    assert_eq!(repo.run(&["fix", "ok.py"]).code(), 0);
    assert!(repo.read("ok.py").contains("yaml.safe_load(open('a.yml'))"));
}

#[test]
fn staged_mode_checks_what_will_be_committed() {
    let repo = Repo::with_standards();
    repo.write("a.ts", BAD_TS);
    repo.git(&["add", "a.ts"]);
    repo.write("a.ts", GOOD_TS); // fixed on disk, but not staged
    assert_eq!(repo.run(&["check", "--staged"]).code(), 1);
    repo.git(&["add", "a.ts"]);
    assert_eq!(repo.run(&["check", "--staged"]).code(), 0);
}

#[test]
fn changed_and_since_only_cover_modified_files() {
    let repo = Repo::with_standards();
    repo.write("legacy.ts", BAD_TS);
    repo.commit_all("legacy");
    repo.write("new.ts", GOOD_TS);
    assert_eq!(
        repo.run(&["check", "--changed"]).code(),
        0,
        "legacy file must not be checked"
    );
    repo.commit_all("new");
    assert_eq!(repo.run(&["check", "--since", "HEAD~1"]).code(), 0);
    repo.write("new.ts", BAD_TS);
    repo.commit_all("bad");
    assert_eq!(repo.run(&["check", "--since", "HEAD~2"]).code(), 1);
}

#[test]
fn delegated_linter_failure_is_a_violation() {
    let repo = Repo::new();
    let cfg = "linters:\n  - id: no-todo\n    run: \"! grep -n TODO {files}\"\n    include: ['**/*.ts']\n";
    repo.write(".agentkit.yaml", cfg);
    repo.write("a.ts", "// TODO: later\n");
    let run = repo.run(&["check"]);
    assert_eq!(run.code(), 1);
    assert!(
        run.stdout().contains("no-todo") && run.stdout().contains("TODO: later"),
        "{}",
        run.stdout()
    );
}

#[test]
fn github_format_emits_annotations() {
    let repo = Repo::with_standards();
    repo.write("a.ts", BAD_TS);
    let out = repo.run(&["check", "--format", "github"]).stdout();
    assert!(
        out.contains("::error title=no-explicit-any,file=a.ts,line=1,col="),
        "{out}"
    );
}

/// Regression: a live Codex run dodged a `console.$METHOD(...)` pattern with
/// computed access. Every spelling must be caught, unrelated names must not.
#[test]
fn no_console_cannot_be_dodged() {
    let repo = Repo::with_standards();
    let dodges = [
        "console.log(x);",
        "globalThis[\"console\"][\"log\"](x);",
        "window.console.error(x);",
        "const c = console;",
        "globalThis['console'].warn(x);",
    ];
    for (i, code) in dodges.iter().enumerate() {
        repo.write(&format!("d{i}.ts"), &format!("{code}\n"));
    }
    repo.write(
        "fine.ts",
        "const consoleMode = 1;\nlogger.info(\"console\", consoleMode);\n",
    );
    let out = repo.run(&["check"]).stdout();
    for (i, dodge) in dodges.iter().enumerate() {
        assert!(
            out.contains(&format!("d{i}.ts")),
            "dodge {dodge} not caught:\n{out}"
        );
    }
    assert!(!out.contains("fine.ts"), "false positive:\n{out}");
}
