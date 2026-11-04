//! The OSV client against a local fake: nothing here touches the network.

use super::*;
use crate::deps::fake::{self, Request, Server};

fn client(server: &Server) -> Osv {
    Osv::at(&server.url, None)
}

fn query<'a>(name: &'a str, version: Option<&'a str>, rated: bool) -> Query<'a> {
    Query {
        eco: Ecosystem::Npm,
        name,
        version,
        rated,
    }
}

fn advisory(id: &str, severity: &str, packages: &[(&str, &str)]) -> Value {
    let affected: Vec<_> = packages
        .iter()
        .map(|(name, fixed)| {
            json!({ "package": { "name": name, "ecosystem": "npm" },
                "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": fixed }] }] })
        })
        .collect();
    json!({ "id": id, "summary": format!("{id} summary"),
        "database_specific": { "severity": severity }, "affected": affected })
}

fn vulns(req: &Request) -> bool {
    req.path.contains("/vulns/")
}

#[test]
fn an_answer_that_does_not_cover_every_query_is_an_error() {
    for (results, count) in [(json!([{}]), 1), (json!([{}, {}, {}]), 3), (json!([]), 0)] {
        let server = fake::serve(move |_| fake::json(&json!({ "results": results })));
        let queries = [
            query("a", Some("1.0.0"), true),
            query("b", Some("1.0.0"), true),
        ];
        let err = client(&server).scan(&queries).unwrap_err().to_string();
        assert!(
            err.contains(&format!("{count} result(s) for 2 queries")),
            "{err}"
        );
    }
    let server = fake::serve(|_| fake::json(&json!({ "vulns": [] })));
    let err = client(&server)
        .scan(&[query("a", None, false)])
        .unwrap_err();
    assert!(err.to_string().contains("no `results`"), "{err:#}");
}

#[test]
fn an_advisory_without_an_id_is_an_error_not_a_clean_package() {
    let server =
        fake::serve(|_| fake::json(&json!({ "results": [{ "vulns": [{ "modified": "x" }] }] })));
    let err = client(&server)
        .scan(&[query("a", Some("1.0.0"), true)])
        .unwrap_err();
    assert!(err.to_string().contains("without an `id`"), "{err:#}");
}

#[test]
fn later_pages_are_followed_so_malware_on_them_is_found() {
    let server = fake::serve(|req| {
        if vulns(req) {
            let id = req.path.rsplit('/').next().unwrap();
            return fake::json(&advisory(id, "HIGH", &[("a", "2.0.0")]));
        }
        let body = req.json();
        let queries = body["queries"].as_array().unwrap();
        match queries[0]["page_token"].as_str() {
            None => fake::json(&json!({ "results": [
                { "vulns": [{ "id": "GHSA-first" }], "next_page_token": "t1" },
                { "vulns": [{ "id": "GHSA-other" }] }] })),
            Some("t1") => fake::json(&json!({ "results": [
                { "vulns": [{ "id": "GHSA-second" }], "next_page_token": "t2" }] })),
            Some(_) => fake::json(&json!({ "results": [{ "vulns": [{ "id": "MAL-2026-1" }] }] })),
        }
    });
    let queries = [
        query("a", Some("1.0.0"), true),
        query("b", Some("1.0.0"), true),
    ];
    let found = client(&server).scan(&queries).unwrap();
    let ids = |i: usize| -> Vec<&str> { found[i].iter().map(|a| a.id.as_str()).collect() };
    assert_eq!(ids(0), ["GHSA-first", "GHSA-second", "MAL-2026-1"]);
    assert_eq!(ids(1), ["GHSA-other"]);
    assert!(found[0][2].malicious);

    let posts: Vec<Request> = server
        .requests()
        .into_iter()
        .filter(|r| !vulns(r))
        .collect();
    assert_eq!(
        posts.len(),
        3,
        "one batch, then one request per further page"
    );
    let follow = posts[1].json();
    assert_eq!(follow["queries"].as_array().unwrap().len(), 1);
    assert_eq!(follow["queries"][0]["page_token"], "t1");
    assert_eq!(follow["queries"][0]["package"]["name"], "a");
    assert_eq!(follow["queries"][0]["version"], "1.0.0");
}

#[test]
fn endless_pagination_fails_instead_of_looping() {
    let server = fake::serve(|_| {
        fake::json(
            &json!({ "results": [{ "vulns": [{ "id": "GHSA-x" }], "next_page_token": "again" }] }),
        )
    });
    let err = client(&server)
        .scan(&[query("a", Some("1.0.0"), false)])
        .unwrap_err();
    assert!(
        err.to_string().contains("pages of advisories for `a`"),
        "{err:#}"
    );
    assert_eq!(server.requests().len(), MAX_PAGES);
}

#[test]
fn big_lockfiles_go_out_in_batches_and_keep_their_order() {
    let server = fake::serve(|req| {
        let body = req.json();
        let results: Vec<_> = body["queries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|q| json!({ "vulns": [{ "id": format!("GHSA-{}", q["package"]["name"].as_str().unwrap()) }] }))
            .collect();
        fake::json(&json!({ "results": results }))
    });
    let names: Vec<String> = (0..2500).map(|i| format!("p{i}")).collect();
    let queries: Vec<_> = names
        .iter()
        .map(|n| query(n, Some("1.0.0"), false))
        .collect();
    let ids = client(&server).ids_modified(&queries).unwrap();
    assert_eq!(ids.len(), 2500);
    assert!(
        ids.iter()
            .zip(&names)
            .all(|(hits, n)| hits[0].0 == format!("GHSA-{n}"))
    );
    let sizes: Vec<usize> = server
        .requests()
        .iter()
        .map(|r| r.json()["queries"].as_array().unwrap().len())
        .collect();
    assert_eq!(sizes.iter().sum::<usize>(), 2500);
    assert_eq!(sizes.len(), 3);
    assert!(sizes.iter().all(|n| *n <= BATCH));
}

#[test]
fn unpinned_queries_fetch_malware_only() {
    let server = fake::serve(|req| {
        if vulns(req) {
            return fake::json(&advisory("MAL-2026-9", "HIGH", &[]));
        }
        fake::json(&json!({ "results": [
            { "vulns": [{ "id": "GHSA-old-1" }, { "id": "MAL-2026-9" }, { "id": "GHSA-old-2" }] },
            { "vulns": [{ "id": "GHSA-old-1" }] }] }))
    });
    let queries = [
        query("express", None, false),
        query("lodash", Some("4.0.0"), true),
    ];
    let found = client(&server).scan(&queries).unwrap();
    let fetched: Vec<String> = server
        .requests()
        .iter()
        .filter(|r| vulns(r))
        .map(|r| r.path.clone())
        .collect();
    // GHSA-old-1 is fetched once, for the pinned query that rates it; GHSA-old-2
    // only matters to the unpinned query, which ignores everything but malware.
    assert_eq!(fetched.len(), 2, "{fetched:?}");
    assert!(fetched.iter().any(|p| p.ends_with("MAL-2026-9")));
    assert_eq!(
        found[0].len(),
        1,
        "unpinned: only the malware advisory is kept"
    );
    assert!(found[0][0].malicious);
    assert_eq!(found[1].len(), 1);
}

#[test]
fn unpinned_installs_never_fetch_rated_advisories() {
    let server = fake::serve(|req| {
        if vulns(req) {
            return fake::json(&advisory("GHSA-x", "HIGH", &[]));
        }
        fake::json(&json!({ "results": [{ "vulns": [{ "id": "GHSA-x" }, { "id": "GHSA-y" }] }] }))
    });
    let found = client(&server)
        .scan(&[query("express", None, false)])
        .unwrap();
    assert!(found[0].is_empty());
    assert!(
        server.requests().iter().all(|r| !vulns(r)),
        "no detail was fetched"
    );
}

#[test]
fn a_shared_advisory_names_each_packages_own_fixes() {
    let server = fake::serve(|req| {
        if vulns(req) {
            return fake::json(&advisory(
                "GHSA-shared",
                "HIGH",
                &[("a", "1.2.3"), ("b", "9.9.9")],
            ));
        }
        fake::json(&json!({ "results": [
            { "vulns": [{ "id": "GHSA-shared" }] }, { "vulns": [{ "id": "GHSA-shared" }] }] }))
    });
    let queries = [
        query("a", Some("1.0.0"), true),
        query("b", Some("9.0.0"), true),
    ];
    let found = client(&server).scan(&queries).unwrap();
    assert_eq!(found[0][0].fixed, ["1.2.3"]);
    assert_eq!(found[1][0].fixed, ["9.9.9"]);
    let fetches = server.requests().iter().filter(|r| vulns(r)).count();
    assert_eq!(fetches, 1, "the advisory itself is fetched once");
}

#[test]
fn throttled_requests_are_retried_and_a_persistent_outage_fails_closed() {
    let calls = std::sync::atomic::AtomicUsize::new(0);
    let server = fake::serve(move |_| {
        if calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            return fake::reply(429, "slow down");
        }
        fake::json(&json!({ "results": [{}] }))
    });
    let found = client(&server)
        .scan(&[query("a", Some("1.0.0"), true)])
        .unwrap();
    assert!(found[0].is_empty());
    assert_eq!(server.requests().len(), 2);

    let down = fake::serve(|_| fake::reply(503, ""));
    let err = client(&down)
        .scan(&[query("a", Some("1.0.0"), true)])
        .unwrap_err();
    assert!(err.to_string().contains("HTTP 503"), "{err:#}");
    assert_eq!(down.requests().len(), 3);
}

#[test]
fn nothing_to_ask_sends_nothing() {
    let server = fake::serve(|_| fake::reply(500, ""));
    assert!(client(&server).scan(&[]).unwrap().is_empty());
    assert!(server.requests().is_empty());
}
