//! `larpcop dashboard`: per-rule counts, baseline debt trend, hotspots.

use crate::common::Repo;

#[test]
fn dashboard_shows_open_and_baselined_violations_and_the_debt_trend() {
    let repo = Repo::with_standards();
    repo.write(
        "src/a.ts",
        "console.log(1);\nconsole.log(2);\nconsole.log(3);\n",
    );
    repo.commit_all("legacy");
    assert_eq!(repo.run(&["baseline"]).code(), 0);
    repo.commit_all("baseline: 3");
    repo.write("src/a.ts", "console.log(1);\n");
    assert_eq!(repo.run(&["baseline", "--prune"]).code(), 0);
    repo.commit_all("baseline: 1");
    repo.write(
        "src/b.ts",
        "export function f(x: number) {\n  console.log(x);\n  return x;\n}\n",
    );

    let run = repo.run(&["dashboard", "--json"]);
    let d: serde_json::Value = serde_json::from_str(&run.stdout()).unwrap();
    let console = d["rules"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["id"] == "no-console")
        .unwrap();
    assert_eq!(
        (console["open"].as_u64(), console["baselined"].as_u64()),
        (Some(1), Some(1))
    );
    let trend: Vec<u64> = d["debt"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| p["entries"].as_u64().unwrap())
        .collect();
    assert_eq!(trend, [3, 1]);
    assert_eq!(d["metrics"]["most_complex"][0]["name"], "f");

    assert_eq!(repo.run(&["dashboard", "--out", "dash.html"]).code(), 0);
    let html = repo.read("dash.html");
    assert!(
        html.contains("<code>no-console</code>") && html.contains("<polyline"),
        "{html}"
    );
    assert!(
        !html.contains("<script"),
        "the page must work without scripts"
    );
}
