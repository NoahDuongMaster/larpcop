//! The age verdict for one pin, against a local fake deps.dev and OSV.

use super::*;
use crate::deps::ecosystem::Ecosystem;
use crate::deps::fake::{self, Server};
use serde_json::{Value, json};

const OLD: &str = "1.0.0";
const YOUNG: &str = "1.0.1";

fn days_ago(days: i64) -> String {
    (Timestamp::now() - SignedDuration::from_hours(days * 24)).to_string()
}

fn advisory(id: &str, severity: &str, fixed: &[&str]) -> Value {
    let events: Vec<_> = fixed.iter().map(|f| json!({ "fixed": f })).collect();
    json!({ "id": id, "summary": format!("{id} summary"),
        "database_specific": { "severity": severity },
        "affected": [{ "package": { "name": "pkg", "ecosystem": "npm" },
                       "ranges": [{ "events": events }] }] })
}

/// `pkg` 1.0.0 (60 days old) and 1.0.1 (2 days old); OSV knows `older`'s
/// advisories for 1.0.0 and the ids of `young` for 1.0.1.
fn osv_server(older: Vec<Value>, young: Vec<Value>) -> Server {
    fake::serve(move |req| {
        let by_version = |version: &str| match version {
            OLD => &older,
            _ => &young,
        };
        if let Some(id) = req.path.strip_prefix("/vulns/") {
            let all = older.iter().chain(&young);
            return match all.into_iter().find(|a| a["id"] == id) {
                Some(a) => fake::json(a),
                None => fake::reply(404, ""),
            };
        }
        let queries = req.json();
        let results: Vec<_> = queries["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                let ids: Vec<_> = by_version(q["version"].as_str().unwrap())
                    .iter()
                    .map(|a| json!({ "id": a["id"] }))
                    .collect();
                json!({ "vulns": ids })
            })
            .collect();
        fake::json(&json!({ "results": results }))
    })
}

fn deps_dev(with_older_release: bool) -> Server {
    let mut versions =
        vec![json!({ "versionKey": { "version": YOUNG }, "publishedAt": days_ago(2) })];
    if with_older_release {
        versions.push(json!({ "versionKey": { "version": OLD }, "publishedAt": days_ago(60) }));
    }
    let list = json!({ "versions": versions });
    let young = json!({ "publishedAt": days_ago(2) });
    fake::serve(move |req| match req.decoded_path().as_str() {
        "/systems/npm/packages/pkg" => fake::json(&list),
        "/systems/npm/packages/pkg/versions/1.0.1" => fake::json(&young),
        _ => fake::reply(404, ""),
    })
}

fn verdict(deps_dev: &Server, osv: &Server, threshold: Option<Severity>) -> Verdict {
    let judge = Judge {
        registry: Registry::at(&deps_dev.url, &deps_dev.url, None),
        osv: Osv::at(&osv.url, None),
        threshold,
        days: 14,
        now: Timestamp::now(),
        cutoff: cutoff(14).unwrap(),
    };
    judge
        .verdict(&Pinned::new(Ecosystem::Npm, "pkg", YOUNG))
        .expect("1.0.1 is younger than 14 days")
}

const HIGH: Option<Severity> = Some(Severity::High);

#[test]
fn a_young_version_that_fixes_a_serious_advisory_is_a_warning() {
    let osv = osv_server(vec![advisory("GHSA-fixme", "HIGH", &["1.0.1"])], vec![]);
    let Verdict { level, message, .. } = verdict(&deps_dev(true), &osv, HIGH);
    assert_eq!(level, Level::Warning, "{message}");
    assert!(
        message.contains("allowed as a security fix: `pkg@1.0.0`")
            && message.contains("(GHSA-fixme)"),
        "{message}"
    );
    // Go and others write versions with a `v`.
    let osv = osv_server(
        vec![advisory("GHSA-fixme", "CRITICAL", &["v1.0.1"])],
        vec![],
    );
    assert_eq!(verdict(&deps_dev(true), &osv, HIGH).level, Level::Warning);
}

#[test]
fn an_advisory_the_young_version_does_not_fix_is_no_excuse() {
    let deps_dev = deps_dev(true);
    let not_fixed_here = osv_server(vec![advisory("GHSA-x", "HIGH", &["1.0.2"])], vec![]);
    let unfixed = osv_server(vec![advisory("GHSA-x", "HIGH", &[])], vec![]);
    let later = osv_server(vec![advisory("GHSA-x", "HIGH", &["1.0.0"])], vec![]);
    for osv in [&not_fixed_here, &unfixed, &later] {
        let Verdict { level, message, .. } = verdict(&deps_dev, osv, HIGH);
        assert_eq!(level, Level::Error, "{message}");
        assert!(message.contains("was published 2 days ago"), "{message}");
    }
}

#[test]
fn a_minor_advisory_or_no_threshold_is_no_excuse() {
    let deps_dev = deps_dev(true);
    let low = osv_server(vec![advisory("GHSA-low", "LOW", &["1.0.1"])], vec![]);
    assert_eq!(verdict(&deps_dev, &low, HIGH).level, Level::Error);
    assert_eq!(
        verdict(&deps_dev, &low, Some(Severity::Low)).level,
        Level::Warning
    );
    let high = osv_server(vec![advisory("GHSA-high", "HIGH", &["1.0.1"])], vec![]);
    assert_eq!(
        verdict(&deps_dev, &high, Some(Severity::Critical)).level,
        Level::Error
    );
    let unasked = osv_server(vec![advisory("GHSA-high", "HIGH", &["1.0.1"])], vec![]);
    assert_eq!(
        verdict(&deps_dev, &unasked, None).level,
        Level::Error,
        "without a vulnerability threshold no advisory counts"
    );
    assert!(unasked.requests().is_empty(), "no threshold, no OSV lookup");
}

#[test]
fn a_young_version_with_advisories_of_its_own_or_malware_behind_it_is_no_fix() {
    let deps_dev = deps_dev(true);
    let both = osv_server(
        vec![advisory("GHSA-old", "HIGH", &["1.0.1"])],
        vec![advisory("GHSA-new", "LOW", &[])],
    );
    assert_eq!(verdict(&deps_dev, &both, HIGH).level, Level::Error);
    let malware = osv_server(vec![advisory("MAL-2026-1", "HIGH", &["1.0.1"])], vec![]);
    assert_eq!(verdict(&deps_dev, &malware, HIGH).level, Level::Error);
}

#[test]
fn without_an_older_release_there_is_nothing_to_compare() {
    let osv = osv_server(vec![advisory("GHSA-x", "HIGH", &["1.0.1"])], vec![]);
    let Verdict { level, note, .. } = verdict(&deps_dev(false), &osv, HIGH);
    assert_eq!(level, Level::Error);
    assert!(note.contains("Use a release published before"), "{note}");
}

#[test]
fn when_osv_cannot_confirm_the_fix_the_version_stays_an_error_and_says_why() {
    let osv = fake::serve(|_| fake::reply(503, ""));
    let Verdict { level, note, .. } = verdict(&deps_dev(true), &osv, HIGH);
    assert_eq!(level, Level::Error);
    assert!(
        note.contains("could not be checked") && note.contains("HTTP 503"),
        "{note}"
    );
}

#[test]
fn old_enough_versions_pass_without_any_lookup_beyond_their_date() {
    let osv = osv_server(vec![], vec![]);
    let old = fake::serve(|_| fake::json(&json!({ "publishedAt": days_ago(60) })));
    let judge = Judge {
        registry: Registry::at(&old.url, &old.url, None),
        osv: Osv::at(&osv.url, None),
        threshold: HIGH,
        days: 14,
        now: Timestamp::now(),
        cutoff: cutoff(14).unwrap(),
    };
    assert!(
        judge
            .verdict(&Pinned::new(Ecosystem::Npm, "pkg", OLD))
            .is_none()
    );
    assert!(osv.requests().is_empty());
}

#[test]
fn only_a_failed_lookup_is_flagged_as_one() {
    let osv = osv_server(vec![], vec![]);
    // Too young, and with no older release to compare with: a durable verdict.
    let young = verdict(&deps_dev(false), &osv, HIGH);
    assert!(!young.lookup_failed);
    // deps.dev answers an error: the publish date is unknown, and the verdict says so.
    let broken = fake::serve(|_| fake::reply(400, ""));
    let judge = Judge {
        registry: Registry::at(&broken.url, &broken.url, None),
        osv: Osv::at(&osv.url, None),
        threshold: HIGH,
        days: 14,
        now: Timestamp::now(),
        cutoff: cutoff(14).unwrap(),
    };
    let failed = judge
        .verdict(&Pinned::new(Ecosystem::Npm, "pkg", YOUNG))
        .expect("an unknown date is not old enough");
    assert!(failed.lookup_failed && failed.level == Level::Error);
    assert!(failed.note.contains("fails closed"), "{}", failed.note);
}
