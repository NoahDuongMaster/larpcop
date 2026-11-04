//! The lockfile-scan cache against a local fake OSV: nothing here touches the network.

use super::*;
use crate::deps::ecosystem::Ecosystem;
use crate::deps::fake::{self, Server};
use serde_json::{Value, json};
use std::path::Path;

fn query<'a>(name: &'a str, version: Option<&'a str>) -> Query<'a> {
    Query {
        eco: Ecosystem::Npm,
        name,
        version,
        rated: true,
    }
}

/// OSV reporting the advisory ids of `known` (package name, id), `modified`
/// time included, and a record for any advisory asked about.
fn osv(known: &'static [(&str, &str)]) -> Server {
    fake::serve(move |req| {
        if let Some(id) = req.path.strip_prefix("/vulns/") {
            return fake::json(&json!({ "id": id, "summary": format!("{id} summary") }));
        }
        let results: Vec<Value> = req.json()["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| {
                let name = q["package"]["name"].as_str().unwrap();
                let vulns: Vec<Value> = known
                    .iter()
                    .filter(|(n, _)| *n == name)
                    .map(|(_, id)| json!({ "id": id, "modified": "2026-01-01T00:00:00Z" }))
                    .collect();
                json!({ "vulns": vulns })
            })
            .collect();
        fake::json(&json!({ "results": results }))
    })
}

/// OSV with the lockfile-scan cache in `dir`, as `Osv::new` sets it up.
fn client(server: &Server, dir: &Path) -> Osv {
    Osv::at(&server.url, None).remembering(dir.join("osv-query"), QUERY_TTL)
}

fn asked(server: &Server) -> usize {
    server
        .requests()
        .iter()
        .filter(|r| r.path == "/querybatch")
        .count()
}

fn stored(dir: &Path) -> Vec<PathBuf> {
    match std::fs::read_dir(dir.join("osv-query")) {
        Ok(entries) => entries.map(|e| e.unwrap().path()).collect(),
        Err(e) => {
            assert_eq!(e.kind(), ErrorKind::NotFound, "{e}");
            Vec::new()
        }
    }
}

fn edit_entry(file: &Path, change: impl FnOnce(&mut Value)) {
    let mut entry: Value = serde_json::from_str(&std::fs::read_to_string(file).unwrap()).unwrap();
    change(&mut entry);
    std::fs::write(file, entry.to_string()).unwrap();
}

fn ids(found: &[Vec<crate::deps::osv::Advisory>], i: usize) -> Vec<&str> {
    found[i].iter().map(|a| a.id.as_str()).collect()
}

#[test]
fn a_second_scan_within_the_ttl_sends_no_request() {
    let server = osv(&[]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    let queries = [query("a", Some("1.0.0")), query("b", Some("2.0.0"))];
    let first = osv.scan_cached(&queries).unwrap();
    assert_eq!(server.requests().len(), 1);
    let second = osv.scan_cached(&queries).unwrap();
    assert_eq!(server.requests().len(), 1, "nothing was asked again");
    assert!(first.iter().chain(&second).all(Vec::is_empty));
    assert_eq!(stored(dir.path()).len(), 2);
}

#[test]
fn malware_in_a_stored_answer_still_blocks() {
    let server = osv(&[("evil", "MAL-2026-1")]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    let queries = [query("fine", Some("1.0.0")), query("evil", Some("1.0.0"))];
    for _ in 0..2 {
        let found = osv.scan_cached(&queries).unwrap();
        assert!(found[0].is_empty());
        assert_eq!(ids(&found, 1), ["MAL-2026-1"]);
        assert!(found[1][0].malicious);
    }
    assert_eq!(asked(&server), 1);
}

#[test]
fn only_the_pins_not_asked_recently_go_to_osv_and_answers_keep_their_order() {
    let server = osv(&[("c", "MAL-2026-3")]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    osv.scan_cached(&[query("a", Some("1.0.0")), query("b", Some("1.0.0"))])
        .unwrap();
    let found = osv
        .scan_cached(&[
            query("a", Some("1.0.0")),
            query("c", Some("1.0.0")),
            query("b", Some("1.0.0")),
        ])
        .unwrap();
    assert_eq!(found.len(), 3);
    assert_eq!(ids(&found, 1), ["MAL-2026-3"]);
    let batches: Vec<Value> = server
        .requests()
        .iter()
        .filter(|r| r.path == "/querybatch")
        .map(|r| r.json())
        .collect();
    assert_eq!(batches.len(), 2);
    let second = batches[1]["queries"].as_array().unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0]["package"]["name"], "c");
}

#[test]
fn an_entry_older_than_the_ttl_or_from_the_future_is_asked_again() {
    let server = osv(&[]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    let queries = [query("a", Some("1.0.0"))];
    osv.scan_cached(&queries).unwrap();
    let file = stored(dir.path()).remove(0);
    let stored_at = |entry: &Value| entry["stored_at"].as_u64().unwrap();

    // Just inside the TTL: still good. At the TTL: expired.
    edit_entry(&file, |e| {
        e["stored_at"] = (stored_at(e) - QUERY_TTL.as_secs() + 60).into()
    });
    osv.scan_cached(&queries).unwrap();
    assert_eq!(asked(&server), 1);
    edit_entry(&file, |e| e["stored_at"] = (stored_at(e) - 60).into());
    osv.scan_cached(&queries).unwrap();
    assert_eq!(asked(&server), 2, "expired entries are not trusted");
    // The new answer replaced the old entry.
    osv.scan_cached(&queries).unwrap();
    assert_eq!(asked(&server), 2);

    edit_entry(&file, |e| e["stored_at"] = (stored_at(e) + 3600).into());
    osv.scan_cached(&queries).unwrap();
    assert_eq!(asked(&server), 3, "a clock that moved back is not trusted");
}

#[test]
fn the_install_path_never_reads_or_writes_the_cache() {
    let server = osv(&[]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    let queries = [query("a", Some("1.0.0"))];
    osv.scan(&queries).unwrap();
    assert!(stored(dir.path()).is_empty(), "scan stores nothing");
    osv.scan_cached(&queries).unwrap();
    assert_eq!(asked(&server), 2);
    osv.scan(&queries).unwrap();
    osv.scan(&queries).unwrap();
    assert_eq!(asked(&server), 4, "scan asks OSV every time, entry or not");
}

#[test]
fn an_unreadable_or_foreign_entry_is_asked_again_and_replaced() {
    let server = osv(&[("evil", "MAL-2026-1")]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    let queries = [query("evil", Some("1.0.0"))];
    osv.scan_cached(&queries).unwrap();
    let file = stored(dir.path()).remove(0);

    for damage in ["not json", "{\"stored_at\": \"soon\"}", ""] {
        std::fs::write(&file, damage).unwrap();
        let before = asked(&server);
        let found = osv.scan_cached(&queries).unwrap();
        assert_eq!(ids(&found, 0), ["MAL-2026-1"], "{damage:?}");
        assert_eq!(asked(&server), before + 1, "{damage:?}");
        osv.scan_cached(&queries).unwrap();
        assert_eq!(asked(&server), before + 1, "{damage:?}: rewritten");
    }

    // Another pin's entry under this pin's file name answers for nobody.
    edit_entry(&file, |e| {
        e["name"] = "other".into();
        e["hits"] = json!([]);
    });
    let before = asked(&server);
    let found = osv.scan_cached(&queries).unwrap();
    assert_eq!(ids(&found, 0), ["MAL-2026-1"]);
    assert_eq!(asked(&server), before + 1);
}

#[test]
fn answers_that_are_not_complete_and_validated_are_not_stored() {
    let dir = tempfile::tempdir().unwrap();
    let queries = [query("a", Some("1.0.0")), query("b", Some("1.0.0"))];
    let failing: Vec<(&str, Server)> = vec![
        ("an HTTP error", fake::serve(|_| fake::reply(404, ""))),
        (
            "a short answer",
            fake::serve(|_| fake::json(&json!({ "results": [{}] }))),
        ),
        (
            "an advisory without an id",
            fake::serve(|_| {
                fake::json(&json!({ "results": [{ "vulns": [{ "modified": "x" }] }, {}] }))
            }),
        ),
        (
            "pages that never end",
            fake::serve(|_| {
                fake::json(&json!({ "results": [
                    { "vulns": [{ "id": "GHSA-x" }], "next_page_token": "again" }, {}] }))
            }),
        ),
    ];
    for (what, server) in &failing {
        let err = client(server, dir.path()).scan_cached(&queries);
        assert!(err.is_err(), "{what}");
        assert!(stored(dir.path()).is_empty(), "{what}: nothing was stored");
    }
}

#[test]
fn a_pin_without_a_version_is_asked_every_time() {
    let server = osv(&[]);
    let dir = tempfile::tempdir().unwrap();
    let osv = client(&server, dir.path());
    osv.scan_cached(&[query("a", None)]).unwrap();
    osv.scan_cached(&[query("a", None)]).unwrap();
    assert_eq!(asked(&server), 2);
    assert!(stored(dir.path()).is_empty());
}

#[test]
fn a_cache_that_cannot_be_written_warns_and_still_answers() {
    let server = osv(&[("evil", "MAL-2026-1")]);
    let dir = tempfile::tempdir().unwrap();
    // `osv-query` is a file: the directory cannot be created.
    std::fs::write(dir.path().join("osv-query"), "").unwrap();
    let found = client(&server, dir.path())
        .scan_cached(&[query("evil", Some("1.0.0"))])
        .unwrap();
    assert_eq!(ids(&found, 0), ["MAL-2026-1"]);
    let err = QueryCache::new(dir.path().join("osv-query"), QUERY_TTL)
        .store(&query("evil", Some("1.0.0")), &[])
        .unwrap_err();
    assert!(format!("{err:#}").contains("creating"), "{err:#}");
}

#[test]
fn entries_long_past_their_expiry_are_removed_when_new_answers_are_stored() {
    let server = osv(&[]);
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("osv-query");
    std::fs::create_dir_all(&dir).unwrap();
    let old = dir.join("old.json");
    let recent = dir.join("recent.json");
    for file in [&old, &recent] {
        std::fs::write(file, "{}").unwrap();
    }
    let two_days_ago = SystemTime::now() - Duration::from_secs(2 * 24 * 3600);
    std::fs::File::options()
        .write(true)
        .open(&old)
        .unwrap()
        .set_modified(two_days_ago)
        .unwrap();
    client(&server, tmp.path())
        .ids_cached(&[query("left-pad", Some("1.0.0"))])
        .unwrap();
    assert!(!old.exists(), "a two day old entry is kept");
    assert!(recent.exists(), "a recent file is removed");
    assert_eq!(
        stored(tmp.path()).len(),
        2,
        "the new answer and the recent file"
    );
}
