//! Fixtures for the dependency rules: npm lockfiles, repos, a fake deps.dev.

use super::Repo;
use serde_json::json;
use std::io::{BufRead, BufReader, Write};

pub const AGE: &str = "dependencies:\n  min_release_age: 14\n";
pub const APPROVAL: &str = "dependencies:\n  require_approval: true\n";

/// Repo with `config` as its .agentkit.yaml and the publish-date cache ignored.
pub fn repo(config: &str) -> Repo {
    let repo = Repo::new();
    repo.write(".gitignore", ".cache-agentkit/\n");
    repo.write(".agentkit.yaml", config);
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
            let (status, body) = routes
                .iter()
                .find(|(p, _)| *p == path)
                .map_or(("404 Not Found", ""), |(_, b)| ("200 OK", b.as_str()));
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
