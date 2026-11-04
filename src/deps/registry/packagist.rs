//! Composer packages are not on deps.dev: publish dates come from Packagist's
//! metadata API (`/p2/vendor/name.json`, one request per package).

use super::enc;
use crate::deps::net;
use anyhow::{Context, Result, bail};
use jiff::Timestamp;
use serde_json::{Map, Value};

pub(super) const API: &str = "https://repo.packagist.org";

/// Every tagged version of a package with its publish time.
pub(super) type Tags = Vec<(String, Timestamp)>;

/// Every tagged version with its publish time; `None` if Packagist has no such package.
pub(super) fn versions(agent: &ureq::Agent, api: &str, name: &str) -> Result<Option<Tags>> {
    let url = url(api, name);
    let body = match net::fetch(|| agent.get(&url).call())? {
        (200, body) => body,
        (404, _) => return Ok(None),
        (status, _) => bail!("Packagist answered HTTP {status}"),
    };
    let doc: Value = serde_json::from_str(&body)?;
    parse(&doc, name).map(Some)
}

/// The name comes from a lockfile: each `vendor/name` segment is encoded, the
/// separator between them is not.
fn url(api: &str, name: &str) -> String {
    let path: Vec<String> = name.split('/').map(enc).collect();
    format!("{api}/p2/{}.json", path.join("/"))
}

/// Minified metadata (`composer/2.0`) lists, after the first version, only the
/// keys that changed since the previous one: the rest is inherited.
fn parse(doc: &Value, name: &str) -> Result<Tags> {
    let Some(entries) = doc["packages"][name].as_array() else {
        return Ok(Vec::new());
    };
    let mut current = Map::new();
    entries
        .iter()
        .map(|entry| {
            let changed = entry
                .as_object()
                .with_context(|| format!("Packagist: a version of {name} is not an object"))?;
            current.extend(changed.iter().map(|(k, v)| (k.clone(), v.clone())));
            let version = current
                .get("version")
                .and_then(Value::as_str)
                .with_context(|| format!("Packagist: a version of {name} has no `version`"))?;
            let time = current
                .get("time")
                .and_then(Value::as_str)
                .with_context(|| format!("Packagist: {name} {version} has no `time`"))?;
            let time: Timestamp = time.parse().with_context(|| {
                format!("Packagist: {name} {version}: unreadable time `{time}`")
            })?;
            Ok((version.trim_start_matches('v').to_string(), time))
        })
        .collect()
}

/// Composer lockfiles write `v1.2.3` or `1.2.3` for the same tag.
pub(super) fn same(a: &str, b: &str) -> bool {
    a.trim_start_matches('v') == b.trim_start_matches('v')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_from_minified_metadata() {
        let doc = serde_json::json!({ "minified": "composer/2.0", "packages": { "monolog/monolog": [
            { "name": "monolog/monolog", "version": "3.12.1", "time": "2026-09-29T19:21:12+00:00" },
            { "version": "v3.12.0", "time": "2026-09-09T08:34:20+00:00" },
            { "version": "3.11.9" } ] } });
        let v = parse(&doc, "monolog/monolog").unwrap();
        assert_eq!(v.len(), 3);
        assert_eq!(v[1].0, "3.12.0");
        assert_eq!(v[2].1, v[1].1, "a version that omits its time inherits it");
        assert!(same("v3.12.0", "3.12.0"));
    }

    #[test]
    fn a_version_without_a_readable_time_is_an_error() {
        let doc = |entry| serde_json::json!({ "packages": { "a/b": [entry] } });
        for entry in [
            serde_json::json!({ "version": "1.0.0" }),
            serde_json::json!({ "version": "1.0.0", "time": "yesterday" }),
            serde_json::json!({ "time": "2026-09-09T08:34:20+00:00" }),
            serde_json::json!("1.0.0"),
        ] {
            assert!(parse(&doc(entry), "a/b").is_err());
        }
    }

    #[test]
    fn package_names_are_encoded_per_segment() {
        assert_eq!(
            url("https://repo.example", "monolog/monolog"),
            "https://repo.example/p2/monolog/monolog.json"
        );
        assert_eq!(
            url("https://repo.example", "a b/../c?d"),
            "https://repo.example/p2/a%20b/%2E%2E/c%3Fd.json"
        );
    }
}
