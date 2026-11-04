//! Fixtures for the dependency rules: npm lockfiles, repos, a fake deps.dev.

use super::Repo;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};

pub const AGE: &str = "dependencies:\n  min_release_age: 14\n";
pub const APPROVAL: &str = "dependencies:\n  require_approval: true\n";

/// Repo with `config` as its .larpcop.yaml and the publish-date cache ignored.
pub fn repo(config: &str) -> Repo {
    let repo = Repo::new();
    repo.write(".gitignore", ".cache-larpcop/\n");
    repo.write(".larpcop.yaml", config);
    repo
}

/// npm v3 lockfile pinning `entries` (name, version) from the public registry.
pub fn npm_lock(entries: &[(&str, &str)]) -> String {
    let mut packages = serde_json::Map::new();
    packages.insert("".into(), json!({"name": "t", "version": "1.0.0"}));
    for (name, version) in entries {
        let resolved = format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz");
        packages.insert(
            format!("node_modules/{name}"),
            json!({"version": version, "resolved": resolved}),
        );
    }
    let lock = json!({"name": "t", "lockfileVersion": 3, "requires": true, "packages": packages});
    serde_json::to_string_pretty(&lock).unwrap()
}

/// Stand-in for the deps.dev API on a local port: `routes` maps decoded request
/// paths to JSON bodies; anything else answers 404. Returns the API base URL.
pub fn fake_deps_dev(routes: Vec<(String, String)>) -> String {
    fake_api(move |path, _| {
        routes
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, body)| body.clone())
    })
}

/// Stand-in for OSV.dev (API base URL ending in `/v1`): `known` maps
/// `name@version` (`name@` when no version is asked about) to the advisory ids
/// `querybatch` reports for it, `advisories` maps an id to its record. Like the
/// real one, `querybatch` answers exactly one result per query.
pub fn fake_osv(known: Vec<(&str, Vec<&str>)>, advisories: Vec<(&str, String)>) -> String {
    let known: Vec<(String, Vec<String>)> = known
        .into_iter()
        .map(|(k, ids)| (k.to_string(), ids.into_iter().map(String::from).collect()))
        .collect();
    let advisories: Vec<(String, String)> = advisories
        .into_iter()
        .map(|(id, record)| (id.to_string(), record))
        .collect();
    let api = fake_api(move |path, body| {
        if path == "/v1/querybatch" {
            let batch: serde_json::Value = serde_json::from_str(body).unwrap();
            let results: Vec<_> = batch["queries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|q| {
                    let name = q["package"]["name"].as_str().unwrap();
                    let key = format!("{name}@{}", q["version"].as_str().unwrap_or(""));
                    let ids = known.iter().find(|(k, _)| *k == key).map(|(_, ids)| ids);
                    let vulns: Vec<_> = ids
                        .into_iter()
                        .flatten()
                        .map(|id| json!({ "id": id }))
                        .collect();
                    json!({ "vulns": vulns })
                })
                .collect();
            return Some(json!({ "results": results }).to_string());
        }
        let id = path.strip_prefix("/v1/vulns/")?;
        advisories
            .iter()
            .find(|(i, _)| i == id)
            .map(|(_, record)| record.clone())
    });
    api.replace("/v3", "/v1")
}

/// Stand-in for an HTTP API on a local port: `answer` gets the decoded request
/// path and the request body and returns the JSON body to send, or `None` for 404.
/// Returns the API base URL (`.../v3`).
pub fn fake_api(answer: impl Fn(&str, &str) -> Option<String> + Send + 'static) -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for mut stream in listener.incoming().flatten() {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut request = String::new();
            let _ = reader.read_line(&mut request);
            let mut header = String::new();
            let mut length = 0;
            while reader.read_line(&mut header).unwrap_or(0) > 2 {
                if let Some((k, v)) = header.split_once(':')
                    && k.eq_ignore_ascii_case("content-length")
                {
                    length = v.trim().parse().unwrap_or(0);
                }
                header.clear();
            }
            // Drain the body (OSV queries are POSTs): closing a socket with unread
            // input makes Windows reset the connection before the client reads.
            let mut body = vec![0; length];
            let _ = std::io::Read::read_exact(&mut reader, &mut body);
            let path = percent_decode(request.split_whitespace().nth(1).unwrap_or(""));
            let body = String::from_utf8_lossy(&body);
            let (status, body) =
                answer(&path, &body).map_or(("404 Not Found", String::new()), |b| ("200 OK", b));
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
                 Connection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    format!("http://{addr}/v3")
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%'
            && let Some(b) = s
                .get(i + 1..i + 3)
                .and_then(|h| u8::from_str_radix(h, 16).ok())
        {
            out.push(b);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).unwrap()
}
