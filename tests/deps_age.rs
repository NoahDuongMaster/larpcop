mod common;

use common::deps::{AGE, fake_deps_dev, npm_lock, repo};
use serde_json::json;

#[test]
fn versions_younger_than_the_minimum_age_are_rejected() {
    let repo = repo(AGE);
    repo.write(".npmrc", "min-release-age=14\n");
    repo.write("package-lock.json", &npm_lock(&[("lodash", "4.17.21")]));
    repo.commit_all("base");

    repo.seed_published("npm", "left-pad", "1.3.0", 2000);
    repo.seed_published("npm", "evil-pkg", "1.0.0", 2);
    let lock = npm_lock(&[
        ("lodash", "4.17.21"),
        ("left-pad", "1.3.0"),
        ("evil-pkg", "1.0.0"),
        ("ghost", "0.0.1"),
    ]);
    repo.write("package-lock.json", &lock);
    let run = repo.run(&["check", "--changed"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    assert!(
        out.contains("`evil-pkg@1.0.0` (npm) was published 2 days ago"),
        "{out}"
    );
    assert!(out.contains("Use a release published before"), "{out}");
    // Unknown dates fail closed (here: the lookup cannot reach deps.dev).
    assert!(
        out.contains("`ghost@0.0.1` (npm): could not look up"),
        "{out}"
    );
    assert!(
        !out.contains("left-pad") && !out.contains("lodash"),
        "{out}"
    );

    repo.write(".larpcop.yaml", &format!("{AGE}  exempt: ['npm:ghost']\n"));
    let run = repo.run(&["check", "--changed"]);
    assert!(!run.stdout().contains("ghost"), "{}", run.stdout());
    assert!(run.stdout().contains("evil-pkg"));

    // Once committed, an unchanged lockfile is not looked up again.
    repo.commit_all("deps");
    assert_eq!(repo.run(&["check"]).code(), 0);
}

#[test]
fn pull_requests_are_measured_against_the_merge_base() {
    let repo = repo(AGE);
    repo.write(".npmrc", "min-release-age=14\n");
    repo.write("package-lock.json", &npm_lock(&[("lodash", "4.17.21")]));
    repo.commit_all("base");
    repo.git(&["checkout", "-q", "-b", "feature"]);
    repo.seed_published("npm", "fresh", "2.0.0", 1);
    repo.write(
        "package-lock.json",
        &npm_lock(&[("lodash", "4.17.21"), ("fresh", "2.0.0")]),
    );
    repo.commit_all("add fresh");
    let run = repo.run(&["check", "--since", "main", "--format", "github"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    assert!(
        out.contains("::error title=dependency-release-age,file=package-lock.json,line="),
        "{out}"
    );
    assert!(
        out.contains("`fresh@2.0.0` (npm) was published 24 hour(s) ago"),
        "{out}"
    );
}

#[test]
fn security_fixes_may_be_younger_than_the_minimum_age() {
    let at = |days: i64| {
        (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(days * 24)).to_string()
    };
    let version = |days: i64, advisories: &[&str]| {
        let keys: Vec<_> = advisories.iter().map(|id| json!({"id": id})).collect();
        json!({"publishedAt": at(days), "advisoryKeys": keys}).to_string()
    };
    let package = |versions: &[(&str, i64)]| {
        let list: Vec<_> = versions
            .iter()
            .map(|(v, d)| json!({"versionKey": {"version": v}, "publishedAt": at(*d)}))
            .collect();
        json!({"versions": list}).to_string()
    };
    let crate_path = |rest: &str| format!("/v3/systems/cargo/packages/{rest}");
    let api = fake_deps_dev(vec![
        (crate_path("ureq/versions/3.5.0"), version(9, &[])),
        (crate_path("ureq/versions/3.4.2"), version(48, &[])),
        (crate_path("ureq"), package(&[("3.4.2", 48), ("3.5.0", 9)])),
        (crate_path("webpki-roots/versions/1.0.11"), version(8, &[])),
        (
            crate_path("webpki-roots/versions/1.0.9"),
            version(100, &["RUSTSEC-2026-0381"]),
        ),
        (
            crate_path("webpki-roots"),
            package(&[("1.0.9", 100), ("1.0.11", 8)]),
        ),
    ]);
    let registry = "source = \"registry+https://github.com/rust-lang/crates.io-index\"";
    let repo = repo(AGE);
    repo.write(
        "Cargo.lock",
        &format!(
            "version = 4\n\n[[package]]\nname = \"ureq\"\nversion = \"3.5.0\"\n{registry}\n\n\
             [[package]]\nname = \"webpki-roots\"\nversion = \"1.0.11\"\n{registry}\n"
        ),
    );
    let run = repo.run_env(&["check", "--changed"], &[("LARPCOP_DEPS_API", &api)]);
    let out = run.stdout();
    assert_eq!(run.code(), 1, "{out}");
    assert!(out.contains("1 error(s), 1 warning(s)"), "{out}");
    assert!(
        out.contains("`ureq@3.5.0` (cargo) was published 9 days ago"),
        "{out}"
    );
    assert!(out.contains("Use ureq@3.4.2 (published "), "{out}");
    assert!(
        out.contains(
            "`webpki-roots@1.0.11` (cargo) is only 8 days old, but allowed as a security fix: \
             `webpki-roots@1.0.9`, the newest release at least 14 days old, has known advisories \
             (RUSTSEC-2026-0381)."
        ),
        "{out}"
    );
}

#[test]
fn package_manager_age_gate_must_be_on() {
    let repo = repo(AGE);
    repo.write("web/pnpm-lock.yaml", "lockfileVersion: '9.0'\n");
    let run = repo.run(&["check", "--changed"]);
    let out = run.stdout();
    assert_eq!(run.code(), 1);
    assert!(
        out.contains("pnpm can still install versions younger than 14 days"),
        "{out}"
    );
    assert!(out.contains("minimumReleaseAge: 20160` in web/pnpm-workspace.yaml"));

    repo.write("web/pnpm-workspace.yaml", "minimumReleaseAge: 1440\n");
    let run = repo.run(&["check", "--changed"]);
    assert!(
        run.stdout().contains("is only 1.0 day(s)"),
        "{}",
        run.stdout()
    );

    repo.write("web/pnpm-workspace.yaml", "minimumReleaseAge: 20160\n");
    assert_eq!(repo.run(&["check", "--changed"]).code(), 0);
}
