use super::*;
use crate::deps::ecosystem::Patterns;
use crate::deps::fake::{self, Request as Http, Server};
use serde_json::{Value, json};
use std::time::Duration;

fn deps() -> Deps {
    Deps {
        min_days: None,
        approval: false,
        vulns: Some(Severity::High),
        approved: Patterns::default(),
        exempt: Patterns::default(),
        exclude: globset::GlobSet::empty(),
    }
}

fn request(spec: &str) -> Request {
    Request {
        eco: Ecosystem::Npm,
        spec: spec.into(),
        name: Some(spec.split('@').next().unwrap().into()),
        version: None,
        via: "npm install",
    }
}

fn advisory(id: &str, severity: &str) -> Value {
    json!({ "id": id, "summary": format!("{id} summary"), "database_specific": { "severity": severity } })
}

fn is_detail(req: &Http) -> bool {
    req.path.starts_with("/vulns/")
}

/// OSV with `ids` for every package asked about, and these advisory records.
fn osv(ids: &[&str], records: Vec<Value>) -> Server {
    let ids: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
    fake::serve(move |req| {
        if let Some(id) = req.path.strip_prefix("/vulns/") {
            return match records.iter().find(|r| r["id"] == id) {
                Some(r) => fake::json(r),
                None => fake::reply(404, ""),
            };
        }
        let n = req.json()["queries"].as_array().unwrap().len();
        fake::json(&json!({ "results": vec![json!({ "vulns": ids }); n] }))
    })
}

fn gate(server: &Server, spec: &str) -> Option<String> {
    deps().gate_vulnerable(
        &Osv::at(&server.url, None),
        Severity::High,
        &[request(spec)],
    )
}

#[test]
fn an_unpinned_install_only_looks_at_malware() {
    let server = osv(
        &["GHSA-old-1", "GHSA-old-2", "MAL-2026-5"],
        vec![advisory("MAL-2026-5", "HIGH")],
    );
    let reason = gate(&server, "express").expect("blocked");
    assert!(
        reason.contains("`express` (npm): malicious advisory MAL-2026-5"),
        "{reason}"
    );
    let fetched: Vec<_> = server.requests().into_iter().filter(is_detail).collect();
    assert_eq!(fetched.len(), 1, "the old advisories are never fetched");

    let clean = osv(&["GHSA-old-1", "GHSA-old-2"], vec![]);
    assert!(gate(&clean, "express").is_none());
    assert!(clean.requests().iter().all(|r| !is_detail(r)));
}

#[test]
fn a_pinned_install_is_judged_by_severity() {
    let high = osv(&["GHSA-h"], vec![advisory("GHSA-h", "HIGH")]);
    let reason = gate(&high, "lodash@4.17.20").expect("blocked");
    assert!(reason.contains("High advisory GHSA-h"), "{reason}");
    let low = osv(&["GHSA-l"], vec![advisory("GHSA-l", "LOW")]);
    assert!(gate(&low, "lodash@4.17.20").is_none());
}

#[test]
fn an_install_that_cannot_be_vetted_does_not_run() {
    let down = fake::serve(|_| fake::reply(503, ""));
    let reason = gate(&down, "express").expect("blocked");
    assert!(reason.contains("could not check this install"), "{reason}");
    let short = fake::serve(|_| fake::json(&json!({ "results": [] })));
    let reason = gate(&short, "express").expect("blocked");
    assert!(reason.contains("0 result(s) for 1 queries"), "{reason}");
}

fn locked(rel: &str, pin: &Pinned, fresh: bool) -> Locked {
    Locked {
        rel: rel.into(),
        content: Arc::from(""),
        pin: pin.clone(),
        fresh,
    }
}

#[test]
fn a_pin_in_several_lockfiles_is_one_query_and_one_report_per_file() {
    let pin = Pinned::new(Ecosystem::Npm, "left-pad", "1.0.0");
    let server = osv(&["GHSA-h"], vec![advisory("GHSA-h", "HIGH")]);
    let entries = [
        locked("a/package-lock.json", &pin, false),
        locked("b/package-lock.json", &pin, true),
        locked("c/package-lock.json", &pin, false),
    ];
    let out = deps()
        .vulnerable(&Osv::at(&server.url, None), Severity::High, &entries)
        .violations;
    let files: Vec<_> = out.iter().map(|v| v.file.as_str()).collect();
    assert_eq!(
        files,
        ["b/package-lock.json"],
        "only the lockfile that brought it in"
    );
    let posts: Vec<_> = server
        .requests()
        .into_iter()
        .filter(|r| !is_detail(r))
        .collect();
    assert_eq!(posts.len(), 1);
    assert_eq!(posts[0].json()["queries"].as_array().unwrap().len(), 1);
}

#[test]
fn old_pins_are_only_asked_about_malware() {
    let pin = Pinned::new(Ecosystem::Npm, "left-pad", "1.0.0");
    let server = osv(
        &["GHSA-h", "MAL-2026-5"],
        vec![advisory("GHSA-h", "HIGH"), advisory("MAL-2026-5", "HIGH")],
    );
    let entries = [
        locked("a/package-lock.json", &pin, false),
        locked("b/package-lock.json", &pin, false),
    ];
    let out = deps()
        .vulnerable(&Osv::at(&server.url, None), Severity::High, &entries)
        .violations;
    let messages: Vec<_> = out.iter().map(|v| v.message.as_str()).collect();
    assert_eq!(messages.len(), 2, "{messages:?}");
    assert!(messages.iter().all(|m| m.contains("MALICIOUS")));
    let fetched: Vec<_> = server.requests().into_iter().filter(is_detail).collect();
    assert_eq!(
        fetched.len(),
        1,
        "the high advisory of an old pin is not fetched"
    );
}

#[test]
fn lockfile_scans_reuse_osv_answers_but_the_install_gate_always_asks() {
    let pin = Pinned::new(Ecosystem::Npm, "express", "4.0.0");
    let entries = [locked("package-lock.json", &pin, true)];
    let dir = tempfile::tempdir().unwrap();
    let remembering = |server: &Server| {
        Osv::at(&server.url, None)
            .remembering(dir.path().join("osv-query"), Duration::from_secs(900))
    };
    let posts = |server: &Server| server.requests().iter().filter(|r| !is_detail(r)).count();

    let clean = osv(&[], vec![]);
    for _ in 0..2 {
        let found = deps().vulnerable(&remembering(&clean), Severity::High, &entries);
        assert!(found.violations.is_empty() && !found.lookup_failed);
    }
    assert_eq!(posts(&clean), 1, "the second scan reused the answer");

    // OSV now reports malware for the same pin. The lockfile scan keeps the answer it
    // has for a few minutes; the install gate asks again, and blocks.
    let malware = osv(&["MAL-2026-5"], vec![advisory("MAL-2026-5", "HIGH")]);
    let found = deps().vulnerable(&remembering(&malware), Severity::High, &entries);
    assert!(found.violations.is_empty());
    assert_eq!(posts(&malware), 0);
    let request = request("express@4.0.0");
    let blocked = deps().gate_vulnerable(&remembering(&malware), Severity::High, &[request]);
    assert!(blocked.is_some_and(|r| r.contains("MAL-2026-5")));
    assert_eq!(posts(&malware), 1);
}

#[test]
fn an_osv_outage_is_reported_not_swallowed() {
    let pin = Pinned::new(Ecosystem::Npm, "left-pad", "1.0.0");
    let down = fake::serve(|_| fake::reply(500, ""));
    let out = deps().vulnerable(
        &Osv::at(&down.url, None),
        Severity::High,
        &[locked("a", &pin, true)],
    );
    assert_eq!(out.violations.len(), 1);
    assert!(
        out.violations[0].message.contains("could not query OSV"),
        "{}",
        out.violations[0].message
    );
    assert!(out.lookup_failed, "the outage is flagged, not only worded");
}

#[test]
fn versions_in_install_specs() {
    assert_eq!(
        pinned_version(Ecosystem::Npm, "left-pad@1.3.0"),
        Some("1.3.0")
    );
    assert_eq!(
        pinned_version(Ecosystem::Npm, "@scope/x@2.0.0"),
        Some("2.0.0")
    );
    assert_eq!(pinned_version(Ecosystem::Npm, "@scope/x"), None);
    assert_eq!(pinned_version(Ecosystem::Npm, "zod@latest"), None);
    assert_eq!(
        pinned_version(Ecosystem::PyPI, "requests==2.31.0"),
        Some("2.31.0")
    );
    assert_eq!(
        pinned_version(Ecosystem::Go, "github.com/a/b@v1.2.3"),
        Some("v1.2.3")
    );
    assert_eq!(
        pinned_version(Ecosystem::Packagist, "guzzlehttp/guzzle:7.4.0"),
        Some("7.4.0")
    );
    assert_eq!(
        pinned_version(Ecosystem::Packagist, "guzzlehttp/guzzle:^7"),
        None
    );
}
