//! One OSV advisory as the rules need it: how bad, whether it is malware, and
//! which versions fix it.

use super::super::ecosystem::Ecosystem;
use super::system;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Moderate,
    High,
    Critical,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Some(Self::Low),
            "moderate" | "medium" => Some(Self::Moderate),
            "high" => Some(Self::High),
            "critical" => Some(Self::Critical),
            _ => None,
        }
    }

    fn of_score(score: f64) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Moderate,
            _ => Self::Low,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
    pub malicious: bool,
    /// Versions that fix it, for this package.
    pub fixed: Vec<String>,
}

/// OpenSSF's malicious-packages feed: the only ids that are about malware.
pub fn is_malicious(id: &str) -> bool {
    id.starts_with("MAL-")
}

/// `fixed` lists the versions the advisory names for this package alone: the same
/// advisory can cover several packages with different fixes.
pub(super) fn parse_advisory(id: &str, v: &Value, eco: Ecosystem, name: &str) -> Advisory {
    let rated = v["database_specific"]["severity"]
        .as_str()
        .and_then(Severity::parse);
    let scored = v["severity"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|s| s["score"].as_str())
        .filter_map(|vector| cvss::Cvss::from_str(vector).ok())
        .map(|c| Severity::of_score(c.score()))
        .max();
    let fixed = v["affected"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| a["package"]["name"] == name && a["package"]["ecosystem"] == system(eco))
        .flat_map(|a| a["ranges"].as_array().into_iter().flatten())
        .flat_map(|r| r["events"].as_array().into_iter().flatten())
        .filter_map(|e| e["fixed"].as_str().map(String::from))
        .collect();
    let summary = v["summary"]
        .as_str()
        .or_else(|| v["details"].as_str())
        .unwrap_or("")
        .lines()
        .next()
        .unwrap_or("")
        .to_string();
    Advisory {
        id: id.into(),
        summary,
        // Unrated advisories count as moderate rather than being ignored.
        severity: rated.or(scored).unwrap_or(Severity::Moderate),
        malicious: is_malicious(id),
        fixed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn severity_from_rating_or_cvss() {
        let ghsa = json!({ "summary": "Prototype Pollution in lodash",
            "database_specific": { "severity": "HIGH" },
            "affected": [{ "package": { "name": "lodash", "ecosystem": "npm" },
                           "ranges": [{ "events": [{ "introduced": "0" }, { "fixed": "4.17.19" }] }] }] });
        let a = parse_advisory("GHSA-x", &ghsa, Ecosystem::Npm, "lodash");
        assert_eq!(
            (a.severity, a.fixed.as_slice()),
            (Severity::High, &["4.17.19".to_string()][..])
        );
        let rustsec = json!({ "summary": "x", "severity": [{ "type": "CVSS_V3",
            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] });
        assert_eq!(
            parse_advisory("RUSTSEC-1", &rustsec, Ecosystem::Cargo, "x").severity,
            Severity::Critical
        );
        let mal = parse_advisory(
            "MAL-2026-1",
            &json!({ "summary": "Malicious code in x" }),
            Ecosystem::Npm,
            "x",
        );
        assert!(mal.malicious);
    }
}
