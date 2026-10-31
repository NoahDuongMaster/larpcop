//! JS package managers can refuse too-new versions themselves, while installing on
//! the developer's machine — before any install script runs. The lockfile check
//! only sees a bad version after it was installed, so the repo must turn this on.

use regex::Regex;
use std::sync::LazyLock;

/// Files whose change can switch a package manager's age gate on or off.
pub fn relevant(file_name: &str) -> bool {
    GATES
        .iter()
        .any(|g| g.lockfile == file_name || g.config == file_name)
        || file_name == ".npmrc"
}

pub struct Gap {
    /// Lockfile of the package manager that is not gated (where to report).
    pub lockfile: String,
    pub message: String,
    pub note: String,
}

struct Gate {
    pm: &'static str,
    lockfile: &'static str,
    config: &'static str,
    key: &'static str,
    /// Configured minimum age in days, from the config file's content.
    days: fn(&str) -> Option<f64>,
    /// Setting that enforces `days`.
    fix: fn(u32) -> String,
}

const GATES: [Gate; 4] = [
    Gate {
        pm: "npm",
        lockfile: "package-lock.json",
        config: ".npmrc",
        key: "min-release-age",
        days: |c| npmrc(c, "min-release-age"),
        fix: |d| format!("min-release-age={d}"),
    },
    Gate {
        pm: "pnpm",
        lockfile: "pnpm-lock.yaml",
        config: "pnpm-workspace.yaml",
        key: "minimumReleaseAge",
        days: |c| yaml_number(c, "minimumReleaseAge").map(|m| m / 1440.0),
        fix: |d| format!("minimumReleaseAge: {}", d * 1440),
    },
    Gate {
        pm: "yarn",
        lockfile: "yarn.lock",
        config: ".yarnrc.yml",
        key: "npmMinimalAgeGate",
        days: |c| yarn_duration(c).map(|m| m / 1440.0),
        fix: |d| format!("npmMinimalAgeGate: \"{d}d\""),
    },
    Gate {
        pm: "bun",
        lockfile: "bun.lock",
        config: "bunfig.toml",
        key: "install.minimumReleaseAge",
        days: |c| bunfig(c).map(|s| s / 86_400.0),
        fix: |d| format!("[install]\nminimumReleaseAge = {}", u64::from(d) * 86_400),
    },
];

/// Age gates missing or too short in `dir`. `read` gets a repo-relative file.
pub fn check(dir: &str, min_days: u32, read: &dyn Fn(&str) -> Option<String>) -> Vec<Gap> {
    let path = |name: &str| {
        if dir.is_empty() {
            name.to_string()
        } else {
            format!("{dir}/{name}")
        }
    };
    let mut out = Vec::new();
    for g in &GATES {
        let Some(lock) = read(&path(g.lockfile)) else {
            continue;
        };
        // Yarn 1 has no age gate; only Yarn Berry lockfiles carry `__metadata`.
        if g.pm == "yarn" && !lock.contains("__metadata:") {
            continue;
        }
        let configured = read(&path(g.config)).and_then(|c| (g.days)(&c));
        if configured.is_some_and(|d| d >= f64::from(min_days)) {
            continue;
        }
        let state = match configured {
            None => format!("`{}` is not set in {}", g.key, g.config),
            Some(d) => format!("`{}` in {} is only {d:.1} day(s)", g.key, g.config),
        };
        out.push(Gap {
            lockfile: path(g.lockfile),
            message: format!(
                "{} can still install versions younger than {min_days} days: {state}.",
                g.pm
            ),
            note: format!(
                "Set `{}` in {}. {} then refuses too-new versions while installing, before \
their install scripts can run on anyone's machine.",
                (g.fix)(min_days).replace('\n', " "),
                path(g.config),
                g.pm
            ),
        });
    }
    out
}

fn npmrc(content: &str, key: &str) -> Option<f64> {
    content
        .lines()
        .map(str::trim)
        .filter(|l| !l.starts_with(['#', ';']))
        .filter_map(|l| l.split_once('='))
        .find(|(k, _)| k.trim() == key)
        .and_then(|(_, v)| v.trim().parse().ok())
}

fn yaml_value(content: &str, key: &str) -> Option<serde_json::Value> {
    let mut doc: std::collections::BTreeMap<String, serde_json::Value> =
        serde_saphyr::from_str(content).ok()?;
    doc.remove(key)
}

fn yaml_number(content: &str, key: &str) -> Option<f64> {
    yaml_value(content, key)?.as_f64()
}

/// Yarn durations: a bare number is minutes; otherwise `<n><unit>` terms (`1w`, `3d12h`).
fn yarn_duration(content: &str) -> Option<f64> {
    static TERM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)").expect("static regex"));
    let value = yaml_value(content, "npmMinimalAgeGate")?;
    if let Some(minutes) = value.as_f64() {
        return Some(minutes);
    }
    let text = value.as_str()?.trim();
    if let Ok(minutes) = text.parse::<f64>() {
        return Some(minutes);
    }
    let minutes_per = |unit: &str| match unit {
        "ms" => 1.0 / 60_000.0,
        "s" => 1.0 / 60.0,
        "m" => 1.0,
        "h" => 60.0,
        "d" => 1440.0,
        _ => 10_080.0,
    };
    let terms: Vec<f64> = TERM
        .captures_iter(text)
        .filter_map(|c| Some(c[1].parse::<f64>().ok()? * minutes_per(&c[2])))
        .collect();
    (!terms.is_empty()).then(|| terms.iter().sum())
}

fn bunfig(content: &str) -> Option<f64> {
    let doc: toml::Table = toml::from_str(content).ok()?;
    let v = doc.get("install")?.get("minimumReleaseAge")?;
    v.as_float().or_else(|| v.as_integer().map(|i| i as f64))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_each_package_manager() {
        assert_eq!(
            npmrc("# x\nmin-release-age = 14\n", "min-release-age"),
            Some(14.0)
        );
        assert_eq!(
            yaml_number(
                "packages: ['a']\nminimumReleaseAge: 20160\n",
                "minimumReleaseAge"
            ),
            Some(20160.0)
        );
        assert_eq!(yarn_duration("npmMinimalAgeGate: \"1w\"\n"), Some(10_080.0));
        let berry = "nodeLinker: node-modules\nplugins:\n  - path: .yarn/plugins/x.cjs\n\
                     packageExtensions:\n  a@*:\n    dependencies: {b: '*'}\nnpmMinimalAgeGate: 3d12h\n";
        assert_eq!(yarn_duration(berry), Some(5040.0));
        assert_eq!(yarn_duration("npmMinimalAgeGate: 2880\n"), Some(2880.0));
        assert_eq!(
            bunfig("[install]\nminimumReleaseAge = 259200\n"),
            Some(259_200.0)
        );
    }

    #[test]
    fn reports_missing_and_short_gates() {
        let files = |rel: &str| -> Option<String> {
            match rel {
                "web/pnpm-lock.yaml" => Some("lockfileVersion: '9.0'\n".into()),
                "web/pnpm-workspace.yaml" => Some("minimumReleaseAge: 1440\n".into()),
                "api/package-lock.json" => Some("{}".into()),
                "old/yarn.lock" => Some("# yarn lockfile v1\n".into()),
                _ => None,
            }
        };
        let web = check("web", 14, &files);
        assert_eq!(web.len(), 1);
        assert!(
            web[0].message.contains("only 1.0 day"),
            "{}",
            web[0].message
        );
        assert!(web[0].note.contains("minimumReleaseAge: 20160"));
        let api = check("api", 14, &files);
        assert!(api[0].note.contains("min-release-age=14") && api[0].note.contains("api/.npmrc"));
        assert!(
            check("old", 14, &files).is_empty(),
            "Yarn 1 has no gate to require"
        );
        assert!(check("web", 1, &files).is_empty());
    }
}
