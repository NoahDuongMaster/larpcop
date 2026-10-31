//! Install commands of package managers without their own minimum-release-age
//! setting (Cargo, Go, Poetry, Bundler, RubyGems, Composer, NuGet, one-off tool
//! runners): the hook checks the version they would fetch, and requires the
//! resolve-only form where installing would run fresh dependency code at once.

use super::Deps;
use super::ecosystem::Pinned;
use super::install::{Invocation, Request, uv_ok};
use super::registry::Registry;
use crate::shell_ast::Script;
use jiff::{SignedDuration, Timestamp};

mod gem;

/// Install forms whose package manager refuses too-new versions itself once
/// the repo turns its gate on (checked separately, on the config files).
const NATIVELY_GATED: [&str; 7] = [
    "npm install",
    "pnpm add",
    "yarn add",
    "bun add",
    "uv add",
    "uv pip install",
    "pip install", // with --uploaded-prior-to, required below
];

/// Cheap pre-filter for commands this module may block.
pub fn mentions(script: &Script) -> bool {
    script.commands.iter().any(|c| {
        matches!(
            c.words
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            ["bundle", "install" | "update", ..] | ["bundle"] | ["poetry", "update", ..]
        )
    })
}

impl Deps {
    /// Resolve-only forms: `None` if the command may run.
    pub(super) fn gate_forms(
        &self,
        days: u32,
        script: &Script,
        invocations: &[Invocation],
    ) -> Option<String> {
        let cutoff = cutoff(days)?;
        for inv in invocations {
            let why = match inv.via {
                "pip install" if !pip_gated(inv, cutoff) => format!(
                    "pip has no repo-wide minimum release age, so every `pip install` must carry \
one: add `--uploaded-prior-to {}` (or install with `uv`, which the repo gates).",
                    cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
                "pipx" if !inv.value(&["--pip-args"]).is_some_and(|a| a.contains("--uploaded-prior-to")) => format!(
                    "add `--pip-args='--uploaded-prior-to {}'` so pipx resolves nothing published in \
the last {days} days.",
                    cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
                "uvx" if !uvx_gated(inv, days) => format!(
                    "one-off uv tool runs ignore the project's settings: add `--exclude-newer \"{days} days\"`."
                ),
                "poetry add" if !inv.has("--lock") => "add `--lock`: Poetry resolves and installs in one \
step, running fresh packages' build code before their lockfile entries are checked. Lock first, let \
the check pass, then `poetry install`."
                    .to_string(),
                "bundle add" if !inv.has("--skip-install") => "add `--skip-install`: resolve first, let \
the Gemfile.lock check pass, then `BUNDLE_FROZEN=true bundle install`."
                    .to_string(),
                "cargo install" if !inv.has("--locked") && !inv.has("--path") => "add `--locked`: the \
crate's own Cargo.lock then fixes every dependency to versions older than the crate itself."
                    .to_string(),
                _ => continue,
            };
            return Some(why);
        }
        for c in &script.commands {
            let words: Vec<&str> = c.words.iter().map(String::as_str).collect();
            let frozen = c.env.iter().chain(&script.exported).any(|(k, v)| {
                matches!(k.as_str(), "BUNDLE_FROZEN" | "BUNDLE_DEPLOYMENT") && v == "true"
            }) || words
                .iter()
                .any(|w| matches!(*w, "--frozen" | "--deployment"));
            let why = match words.as_slice() {
                ["bundle", "update", ..] => {
                    "`bundle update` resolves and installs in one step. Run \
`bundle lock --update <gems>` (resolves only), let the Gemfile.lock check pass, then \
`BUNDLE_FROZEN=true bundle install`."
                }
                ["bundle", "install", ..] | ["bundle"] if !frozen => {
                    "run it as `BUNDLE_FROZEN=true \
bundle install`: an unfrozen install re-resolves the Gemfile and installs versions nobody checked yet. \
Change versions with `bundle lock` first."
                }
                ["poetry", "update", ..] if !words.contains(&"--lock") => {
                    "add `--lock`, let the \
poetry.lock check pass, then `poetry install`."
                }
                _ => continue,
            };
            return Some(why.to_string());
        }
        None
    }

    /// Versions the install would fetch must be old enough. Unpinned requests to a
    /// gated package manager are left to it: it picks an older version itself.
    pub(super) fn gate_young(
        &self,
        days: u32,
        requests: &[Request],
        invocations: &[Invocation],
        cwd: &std::path::Path,
    ) -> Option<String> {
        let cutoff = cutoff(days)?;
        let registry = Registry::new();
        let mut reasons = Vec::new();
        // `gem install` resolves dependencies to their newest versions: ask
        // RubyGems what it would install, and check all of it.
        let mut resolved = Vec::new();
        for inv in invocations.iter().filter(|i| i.via == "gem install") {
            match gem::explain(inv, cwd) {
                Ok(pins) => resolved.extend(pins),
                Err(e) => {
                    return Some(format!(
                        "could not resolve this gem install to check it ({e:#}); this check fails closed."
                    ));
                }
            }
        }
        for r in requests.iter().chain(&resolved) {
            let Some(name) = &r.name else { continue };
            if r.version.is_none() && NATIVELY_GATED.contains(&r.via) {
                continue;
            }
            if self.exempt.matches(r.eco, name) {
                continue;
            }
            let found = match &r.version {
                Some(v) => registry
                    .published(&Pinned::new(r.eco, name, v))
                    .map(|t| t.map(|t| (v.clone(), t))),
                None => registry.releases(r.eco, name).map(|all| {
                    all.and_then(|all| all.into_iter().find(|(_, _, d)| *d).map(|(v, t, _)| (v, t)))
                }),
            };
            let (version, published) = match found {
                Ok(Some(x)) => x,
                Ok(None) => {
                    reasons.push(format!("`{name}` ({}): no publish date is known for the version this would install; pin an older release.", r.eco));
                    continue;
                }
                Err(e) => {
                    return Some(format!(
                        "could not look up when `{name}` was published ({e:#}). This check fails \
closed: retry once the network is back."
                    ));
                }
            };
            if published <= cutoff {
                continue;
            }
            let instead = registry
                .newest_any_before(r.eco, name, cutoff)
                .map(|(v, _)| format!(" Use `{}` instead.", fix(r.via, name, &v)))
                .unwrap_or_default();
            reasons.push(format!(
                "`{name}@{version}` ({}) was published {} ago, less than {days} days.{instead}",
                r.eco,
                ago(Timestamp::now().duration_since(published))
            ));
        }
        (!reasons.is_empty()).then(|| {
            format!(
                "this would install versions too new to trust yet:\n- {}\nCompromised releases are \
usually caught and pulled within days. If this exact version is required, stop and ask the user.",
                reasons.join("\n- ")
            )
        })
    }
}

fn cutoff(days: u32) -> Option<Timestamp> {
    Timestamp::now()
        .checked_sub(SignedDuration::from_hours(i64::from(days) * 24))
        .ok()
}

fn pip_gated(inv: &Invocation, cutoff: Timestamp) -> bool {
    let env = inv
        .env
        .iter()
        .find(|(k, _)| k == "PIP_UPLOADED_PRIOR_TO")
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("PIP_UPLOADED_PRIOR_TO").ok());
    let value = inv
        .value(&["--uploaded-prior-to"])
        .map(String::from)
        .or(env);
    inv.has("--no-index") || value.is_some_and(|v| date_ok(&v, cutoff))
}

fn uvx_gated(inv: &Invocation, days: u32) -> bool {
    let flag = inv.value(&["--exclude-newer"]).map(String::from);
    let env = inv
        .env
        .iter()
        .find(|(k, _)| k == "UV_EXCLUDE_NEWER")
        .map(|(_, v)| v.clone())
        .or_else(|| std::env::var("UV_EXCLUDE_NEWER").ok());
    flag.or(env).is_some_and(|v| uv_ok(&v, days))
}

/// An absolute date at or before `cutoff`.
fn date_ok(value: &str, cutoff: Timestamp) -> bool {
    let v = value.trim().trim_matches(['"', '\'']);
    let at = v.parse::<Timestamp>().ok().or_else(|| {
        let date: jiff::civil::Date = v.parse().ok()?;
        date.to_zoned(jiff::tz::TimeZone::UTC)
            .ok()
            .map(|z| z.timestamp())
    });
    at.is_some_and(|t| t <= cutoff)
}

/// The same install, pinned to `version`.
fn fix(via: &str, name: &str, version: &str) -> String {
    match via {
        "cargo add" => {
            format!("cargo add {name}@{version}` then `cargo update -p {name} --precise {version}")
        }
        "cargo install" => format!("cargo install {name} --version {version} --locked"),
        "go get" | "go install" => format!("{via} {name}@{version}"),
        "poetry add" => format!("poetry add \"{name}=={version}\" --lock"),
        "gem install" => format!("gem install {name} -v {version}"),
        "bundle add" => format!("bundle add {name} --version {version} --skip-install"),
        "composer require" => format!("composer require {name}:{version}"),
        "dotnet add package" => format!("dotnet add package {name} --version {version}"),
        "pipx" => format!("pipx install {name}=={version}"),
        "pip install" | "uv pip install" => format!("{via} {name}=={version}"),
        "uv add" => format!("uv add {name}=={version}"),
        _ => format!("{via} {name}@{version}"),
    }
}

fn ago(d: SignedDuration) -> String {
    let hours = d.as_hours();
    if hours < 48 {
        format!("{hours} hour(s)")
    } else {
        format!("{} days", hours / 24)
    }
}
