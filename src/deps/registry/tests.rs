//! The registry client against a local fake deps.dev / Packagist.

use super::*;
use crate::deps::fake::{self, Server};
use serde_json::json;

fn client(deps_dev: &Server, packagist: &Server) -> Registry {
    Registry::at(&deps_dev.url, &packagist.url, None)
}

fn pin(name: &str, version: &str) -> Pinned {
    Pinned::new(Ecosystem::Npm, name, version)
}

fn idle() -> Server {
    fake::serve(|_| fake::reply(500, "unused"))
}

#[test]
fn version_lines() {
    assert_eq!(major_line("4.17.21"), "4");
    assert_eq!(major_line("v0.13.2"), "0.13");
    assert_eq!(major_line("6.1.0-dev.20261031"), "6");
    assert!(is_stable("v1.8.1") && is_stable("2.32.3"));
    assert!(!is_stable("1.0.0-rc.1") && !is_stable("1.0a1"));
}

#[test]
fn publish_dates_come_from_the_version_document() {
    let deps_dev = fake::serve(|_| fake::json(&json!({ "publishedAt": "2026-10-01T00:00:00Z" })));
    let registry = client(&deps_dev, &idle());
    let published = registry.published(&pin("@scope/x", "1.0.0")).unwrap();
    assert_eq!(published, Some("2026-10-01T00:00:00Z".parse().unwrap()));
    let requests = deps_dev.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].decoded_path(),
        "/systems/npm/packages/@scope/x/versions/1.0.0"
    );
    assert_eq!(
        requests[0].path,
        "/systems/npm/packages/%40scope%2Fx/versions/1%2E0%2E0"
    );
}

#[test]
fn a_release_list_is_fetched_once_for_every_question_about_the_package() {
    let list = json!({ "versions": [
        { "versionKey": { "version": "1.0.0" }, "publishedAt": "2026-01-01T00:00:00Z" },
        { "versionKey": { "version": "1.1.0" }, "publishedAt": "2026-02-01T00:00:00Z", "isDefault": true },
        { "versionKey": { "version": "2.0.0" }, "publishedAt": "2026-10-30T00:00:00Z" }] });
    let deps_dev = fake::serve(move |_| fake::json(&list));
    let registry = client(&deps_dev, &idle());
    let cutoff: Timestamp = "2026-10-01T00:00:00Z".parse().unwrap();
    let default = registry.releases(Ecosystem::Npm, "x").unwrap().unwrap();
    assert_eq!(default.iter().filter(|r| r.2).count(), 1);
    let same_line = registry.newest_before(&pin("x", "1.5.0"), cutoff).unwrap();
    assert_eq!(same_line.unwrap().0, "1.1.0");
    let any = registry
        .newest_any_before(Ecosystem::Npm, "x", cutoff)
        .unwrap();
    assert_eq!(any.unwrap().0, "1.1.0");
    assert_eq!(deps_dev.requests().len(), 1);
}

#[test]
fn unknown_versions_are_none_and_outages_are_errors() {
    let missing = fake::serve(|_| fake::reply(404, ""));
    let registry = client(&missing, &idle());
    assert!(registry.published(&pin("x", "1.0.0")).unwrap().is_none());
    assert!(registry.releases(Ecosystem::Npm, "x").unwrap().is_none());

    let down = fake::serve(|_| fake::reply(503, ""));
    let registry = client(&down, &idle());
    let err = registry.published(&pin("x", "1.0.0")).unwrap_err();
    assert!(err.to_string().contains("HTTP 503"), "{err:#}");
    assert_eq!(down.requests().len(), 3, "retried before failing closed");
    // A release list that failed to load is remembered for the run instead of
    // asking three more times.
    assert!(registry.releases(Ecosystem::Npm, "x").is_err());
    assert!(
        registry
            .newest_any_before(Ecosystem::Npm, "x", Timestamp::now())
            .is_err()
    );
    assert_eq!(down.requests().len(), 6);
}

#[test]
fn composer_metadata_is_one_request_per_package() {
    let packagist = fake::serve(|_| {
        fake::json(
            &json!({ "minified": "composer/2.0", "packages": { "a b/c": [
            { "version": "2.0.0", "time": "2026-10-30T00:00:00Z" },
            { "version": "1.1.0", "time": "2026-02-01T00:00:00Z" },
            { "version": "v1.0.0", "time": "2026-01-01T00:00:00+00:00" }] } }),
        )
    });
    let registry = client(&idle(), &packagist);
    let composer = |version: &str| Pinned::new(Ecosystem::Packagist, "a b/c", version);
    for v in ["2.0.0", "1.1.0", "1.0.0"] {
        assert!(registry.published(&composer(v)).unwrap().is_some(), "{v}");
    }
    assert!(registry.published(&composer("9.9.9")).unwrap().is_none());
    let releases = registry
        .releases(Ecosystem::Packagist, "a b/c")
        .unwrap()
        .unwrap();
    assert_eq!(releases.len(), 3);
    let requests = packagist.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].path, "/p2/a%20b/c.json");
}
