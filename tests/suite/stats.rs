//! `stats` (which rules fire, which caught nothing) and `rules --for` (only
//! the rules that apply to one file).

use crate::common::{BAD_TS, GOOD_TS, Repo};

#[test]
fn stats_says_which_rules_fire_and_which_stay_silent() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    repo.write("src/b.ts", GOOD_TS);
    let run = repo.run(&["stats"]);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let out = run.stdout();
    let (table, rest) = out.split_once("caught nothing").expect("a silent section");
    // The bad file's rules are in the table, with a count.
    assert!(table.contains("no-console"), "{out}");
    assert!(table.contains("no-explicit-any"), "{out}");
    // A rule of the standard that applies here and caught nothing is not.
    assert!(rest.contains("max-lines"), "{out}");
    assert!(!rest.contains("no-console"), "{out}");
    assert!(
        out.contains("2 finding(s)") || out.contains("3 finding(s)"),
        "{out}"
    );
}

#[test]
fn stats_json_carries_every_rule_it_looked_at() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", BAD_TS);
    let run = repo.run(&["stats", "--json"]);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let data: serde_json::Value = serde_json::from_str(&run.stdout()).expect("json");
    let fired = data["fired"].as_array().expect("fired");
    assert!(fired.iter().any(|r| r["id"] == "no-console"));
    assert!(
        data["silent"]
            .as_array()
            .is_some_and(|s| s.iter().all(|r| r["count"] == 0))
    );
}

#[test]
fn rules_for_keeps_only_what_applies_to_the_file() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", GOOD_TS);
    repo.write("job.py", "print(1)\n");
    let ts = repo.run(&["rules", "--for", "src/a.ts"]);
    assert_eq!(ts.code(), 0, "{}", ts.stderr());
    let out = ts.stdout();
    assert!(out.contains("no-console"), "{out}");
    // A rule targetting Python files is not listed for a TypeScript one.
    assert!(!out.contains("py-no-bare-except"), "{out}");
    let py = repo.run(&["rules", "--for", "job.py"]);
    assert!(py.stdout().contains("py-no-bare-except"), "{}", py.stdout());
    assert!(!py.stdout().contains("no-console"), "{}", py.stdout());
}

#[test]
fn rules_for_json_is_machine_readable() {
    let repo = Repo::with_standards();
    repo.write("src/a.ts", GOOD_TS);
    let run = repo.run(&["rules", "--for", "src/a.ts", "--json"]);
    assert_eq!(run.code(), 0, "{}", run.stderr());
    let data: serde_json::Value = serde_json::from_str(&run.stdout()).expect("json");
    let rows = data.as_array().expect("array");
    assert!(rows.iter().any(|r| r["id"] == "no-console"));
    assert!(rows.iter().all(|r| r["message"].is_string()));
}
