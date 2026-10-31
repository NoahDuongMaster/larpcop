//! Commands that switch off or shorten a package manager's minimum release age.
//! Values are read, so a stricter setting (`--min-release-age=30`, uv's
//! `--exclude-newer "30 days"`) passes and only a weaker one blocks.

use crate::shell_ast::{Command, parse};
use jiff::{SignedDuration, Span, SpanRelativeTo, Timestamp, Unit, civil};
use regex::Regex;
use std::sync::LazyLock;

/// The command would weaken a package manager's age gate below `days`.
pub fn weakens_age_gate(command: &str, days: u32) -> bool {
    let script = parse(command);
    let env_weak = script.assignments().any(|(k, v)| env_weakens(k, v, days));
    env_weak || script.commands.iter().any(|c| words_weaken(c, days))
}

fn env_weakens(key: &str, value: &str, days: u32) -> bool {
    match key.to_ascii_lowercase().as_str() {
        "npm_config_min_release_age" | "npm_config_min-release-age" => below(value, days, 1.0),
        "pnpm_config_minimum_release_age" | "npm_config_minimum_release_age" => {
            below(value, days, 1440.0)
        }
        "yarn_npm_minimal_age_gate" => {
            yarn_minutes(value).is_none_or(|m| m < f64::from(days) * 1440.0)
        }
        "uv_exclude_newer" => !uv_ok(value, days),
        _ => false,
    }
}

fn words_weaken(cmd: &Command, days: u32) -> bool {
    let words = &cmd.words;
    let program = words.first().map(String::as_str).unwrap_or("");
    let minutes = program == "pnpm";
    for (i, w) in words.iter().enumerate() {
        let next = || words.get(i + 1).map(String::as_str).unwrap_or("");
        let lower = w.to_ascii_lowercase();
        let flag = [
            "--min-release-age",
            "--minimum-release-age",
            "--config.minimum-release-age",
            "--config.minimumreleaseage",
        ]
        .iter()
        .find(|f| lower == **f || lower.starts_with(&format!("{f}=")));
        if let Some(f) = flag {
            let value = w
                .get(f.len() + 1..)
                .filter(|_| w.len() > f.len())
                .unwrap_or_else(next);
            let per_day = if minutes || f.starts_with("--config") {
                1440.0
            } else {
                1.0
            };
            if below(value, days, per_day) {
                return true;
            }
        }
        if w == "--exclude-newer" && !uv_ok(next(), days) {
            return true;
        }
        if let Some(v) = w.strip_prefix("--exclude-newer=")
            && !uv_ok(v, days)
        {
            return true;
        }
    }
    config_weakens(words, days)
}

/// `npm config set min-release-age 0`, `yarn config unset npmMinimalAgeGate`, …
fn config_weakens(words: &[String], days: u32) -> bool {
    static KEY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?i)^(min(imum)?-?release-?age|npmminimalagegate)").expect("static regex")
    });
    let Some(at) = words.iter().position(|w| w == "config") else {
        return false;
    };
    if !matches!(
        words.first().map(String::as_str),
        Some("npm" | "pnpm" | "yarn" | "bun")
    ) {
        return false;
    }
    let rest: Vec<&str> = words[at + 1..]
        .iter()
        .map(String::as_str)
        .filter(|w| !w.starts_with('-'))
        .collect();
    match rest.as_slice() {
        ["set", key, value, ..] if KEY.is_match(key) => {
            let per_day = if key.eq_ignore_ascii_case("npmMinimalAgeGate") || words[0] == "pnpm" {
                1440.0
            } else {
                1.0
            };
            if key.eq_ignore_ascii_case("npmMinimalAgeGate") {
                return yarn_minutes(value).is_none_or(|m| m < f64::from(days) * 1440.0);
            }
            below(value, days, per_day)
        }
        // `npm config set min-release-age=0`
        ["set", kv, ..] if KEY.is_match(kv) => {
            let value = kv.split_once('=').map_or("", |(_, v)| v);
            below(value, days, if words[0] == "pnpm" { 1440.0 } else { 1.0 })
        }
        ["delete" | "rm" | "unset", key, ..] => KEY.is_match(key),
        _ => false,
    }
}

/// A number in units of `per_day` below the required days (unparseable counts as weaker).
fn below(value: &str, days: u32, per_day: f64) -> bool {
    value
        .trim()
        .parse::<f64>()
        .map_or(true, |v| v < f64::from(days) * per_day)
}

/// Yarn durations: a bare number is minutes; otherwise `<n><unit>` terms (`1w`, `3d12h`).
fn yarn_minutes(text: &str) -> Option<f64> {
    static TERM: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"(\d+(?:\.\d+)?)\s*(ms|s|m|h|d|w)").expect("static regex"));
    let text = text.trim().trim_matches('"');
    if let Ok(minutes) = text.parse::<f64>() {
        return Some(minutes);
    }
    let per = |unit: &str| match unit {
        "ms" => 1.0 / 60_000.0,
        "s" => 1.0 / 60.0,
        "m" => 1.0,
        "h" => 60.0,
        "d" => 1440.0,
        _ => 10_080.0,
    };
    let terms: Vec<f64> = TERM
        .captures_iter(text)
        .filter_map(|c| Some(c[1].parse::<f64>().ok()? * per(&c[2])))
        .collect();
    (!terms.is_empty()).then(|| terms.iter().sum())
}

/// uv's `exclude-newer`: a duration of at least `days`, or a date at least `days` ago.
pub fn uv_ok(value: &str, days: u32) -> bool {
    let value = value.trim().trim_matches(['"', '\'']);
    if let Ok(span) = value.parse::<Span>() {
        let relative = SpanRelativeTo::days_are_24_hours();
        return span
            .total((Unit::Day, relative))
            .is_ok_and(|d| d >= f64::from(days));
    }
    let Some(cutoff) = Timestamp::now()
        .checked_sub(SignedDuration::from_hours(i64::from(days) * 24))
        .ok()
    else {
        return false;
    };
    let at = value.parse::<Timestamp>().ok().or_else(|| {
        value
            .parse::<civil::Date>()
            .ok()?
            .to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|z| z.timestamp())
    });
    at.is_some_and(|t| t <= cutoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_weaker_settings_block() {
        for cmd in [
            "npm install --min-release-age=0 x",
            "pnpm add x --config.minimum-release-age=0",
            "npm_config_min_release_age=0 npm i x",
            "npm config set min-release-age 0",
            "npm config delete min-release-age",
            "yarn config set npmMinimalAgeGate 0",
            "YARN_NPM_MINIMAL_AGE_GATE=1d yarn add x",
            "uv add requests --exclude-newer 2099-01-01",
            "UV_EXCLUDE_NEWER=2099-01-01 uv lock",
            "uvx --exclude-newer '3 days' ruff",
        ] {
            assert!(weakens_age_gate(cmd, 14), "{cmd}");
        }
        for cmd in [
            "npm config get min-release-age",
            "npm install left-pad",
            "npm install --min-release-age=30 x",
            "npm config set min-release-age 21",
            "pnpm add x --config.minimum-release-age=30240",
            "uvx --exclude-newer '30 days' ruff",
            "uv lock --exclude-newer 2020-01-01",
            "YARN_NPM_MINIMAL_AGE_GATE=3w yarn add x",
        ] {
            assert!(!weakens_age_gate(cmd, 14), "{cmd}");
        }
    }
}
