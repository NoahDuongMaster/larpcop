//! Composer packages are not on deps.dev: publish dates come from Packagist's
//! metadata API (`/p2/vendor/name.json`, one request per package).

use anyhow::{Result, bail};
use jiff::Timestamp;
use serde_json::Value;

const DEFAULT_API: &str = "https://repo.packagist.org";

/// Every tagged version with its publish time; `None` if Packagist has no such package.
pub(super) fn versions(
    agent: &ureq::Agent,
    name: &str,
) -> Result<Option<Vec<(String, Timestamp)>>> {
    let api = std::env::var("LARPCOP_PACKAGIST_API").unwrap_or_else(|_| DEFAULT_API.into());
    let url = format!("{}/p2/{name}.json", api.trim_end_matches('/'));
    let mut resp = agent.get(&url).call()?;
    let body = match resp.status().as_u16() {
        200 => resp.body_mut().read_to_string()?,
        404 => return Ok(None),
        status => bail!("Packagist answered HTTP {status}"),
    };
    let doc: Value = serde_json::from_str(&body)?;
    Ok(Some(parse(&doc, name)))
}

fn parse(doc: &Value, name: &str) -> Vec<(String, Timestamp)> {
    doc["packages"][name]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| {
            let version = v["version"].as_str()?.trim_start_matches('v').to_string();
            let time: Timestamp = v["time"].as_str()?.parse().ok()?;
            Some((version, time))
        })
        .collect()
}

/// Composer lockfiles write `v1.2.3` or `1.2.3` for the same tag.
pub(super) fn same(a: &str, b: &str) -> bool {
    a.trim_start_matches('v') == b.trim_start_matches('v')
}

#[cfg(test)]
mod tests {
    #[test]
    fn versions_from_minified_metadata() {
        let doc = serde_json::json!({ "minified": "composer/2.0", "packages": { "monolog/monolog": [
            { "name": "monolog/monolog", "version": "3.12.1", "time": "2026-09-29T19:21:12+00:00" },
            { "version": "v3.12.0", "time": "2026-09-09T08:34:20+00:00" } ] } });
        let v = super::parse(&doc, "monolog/monolog");
        assert_eq!(v.len(), 2);
        assert_eq!(v[1].0, "3.12.0");
        assert!(super::same("v3.12.0", "3.12.0"));
    }
}
