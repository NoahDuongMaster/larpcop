//! Package ecosystems, how each one names packages, and `[ecosystem:]glob`
//! patterns over those names.

use anyhow::{Context, Result};
use globset::{Glob, GlobMatcher};
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    PyPI,
    Cargo,
    Go,
    RubyGems,
    NuGet,
    /// `group:artifact` names (Gradle lockfiles, pom.xml).
    Maven,
    /// Composer packages (`vendor/name`).
    Packagist,
}

impl Ecosystem {
    const ALL: [Self; 8] = [
        Self::Npm,
        Self::PyPI,
        Self::Cargo,
        Self::Go,
        Self::RubyGems,
        Self::NuGet,
        Self::Maven,
        Self::Packagist,
    ];

    /// Prefix in config patterns (`npm:left-pad`) and in messages; also the system
    /// name in the deps.dev API.
    pub fn label(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "pypi",
            Self::Cargo => "cargo",
            Self::Go => "go",
            Self::RubyGems => "rubygems",
            Self::NuGet => "nuget",
            Self::Maven => "maven",
            Self::Packagist => "composer",
        }
    }

    /// PyPI names are case-insensitive and treat runs of `-`, `_`, `.` alike
    /// (PEP 503); NuGet and Composer names are case-insensitive.
    pub fn normalize(self, name: &str) -> String {
        if matches!(self, Self::NuGet | Self::Packagist) {
            return name.to_ascii_lowercase();
        }
        if self != Self::PyPI {
            return name.to_string();
        }
        let mut out = String::with_capacity(name.len());
        for c in name.chars() {
            if matches!(c, '-' | '_' | '.') {
                if !out.ends_with('-') {
                    out.push('-');
                }
            } else {
                out.push(c.to_ascii_lowercase());
            }
        }
        out
    }
}

impl fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

/// One exact package version pinned by a lockfile.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pinned {
    pub eco: Ecosystem,
    pub name: String,
    pub version: String,
}

impl Pinned {
    pub fn new(eco: Ecosystem, name: &str, version: &str) -> Self {
        Self {
            eco,
            name: eco.normalize(name),
            version: version.to_string(),
        }
    }
}

impl fmt::Display for Pinned {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.name, self.version)
    }
}

/// `@scope/name@^1` → `@scope/name`; `name@1` → `name`.
pub fn npm_spec_name(spec: &str) -> &str {
    let from = usize::from(spec.starts_with('@'));
    spec[from..].find('@').map_or(spec, |i| &spec[..from + i])
}

struct Pattern {
    eco: Option<Ecosystem>,
    raw: GlobMatcher,
    /// Same glob, PEP 503-normalized, for matching PyPI names.
    pypi: GlobMatcher,
}

/// `approved` / `exempt` entries: `[ecosystem:]glob`, e.g. `npm:@acme/*`, `serde`.
#[derive(Default)]
pub struct Patterns(Vec<Pattern>);

impl Patterns {
    pub fn new(specs: &[String]) -> Result<Self> {
        let compile = |glob: &str| -> Result<GlobMatcher> {
            Ok(Glob::new(glob)
                .with_context(|| format!("invalid dependency pattern `{glob}`"))?
                .compile_matcher())
        };
        specs
            .iter()
            .map(|spec| {
                let (eco, glob) = split_ecosystem(spec);
                Ok(Pattern {
                    eco,
                    raw: compile(glob)?,
                    pypi: compile(&Ecosystem::PyPI.normalize(glob))?,
                })
            })
            .collect::<Result<_>>()
            .map(Self)
    }

    pub fn matches(&self, eco: Ecosystem, name: &str) -> bool {
        self.0.iter().any(|p| {
            p.eco.is_none_or(|e| e == eco)
                && if eco == Ecosystem::PyPI {
                    p.pypi.is_match(name)
                } else {
                    p.raw.is_match(name)
                }
        })
    }
}

fn split_ecosystem(spec: &str) -> (Option<Ecosystem>, &str) {
    if let Some((prefix, rest)) = spec.split_once(':')
        && let Some(eco) = Ecosystem::ALL.into_iter().find(|e| e.label() == prefix)
    {
        return (Some(eco), rest);
    }
    (None, spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_patterns() {
        assert_eq!(
            Ecosystem::PyPI.normalize("Zope.Interface__x"),
            "zope-interface-x"
        );
        assert_eq!(npm_spec_name("@types/node@^22"), "@types/node");
        assert_eq!(npm_spec_name("left-pad"), "left-pad");
        let p = Patterns::new(&[
            "npm:@acme/*".into(),
            "Django".into(),
            "go:github.com/acme/*".into(),
        ])
        .unwrap();
        assert!(p.matches(Ecosystem::Npm, "@acme/ui"));
        assert!(!p.matches(Ecosystem::Cargo, "@acme/ui"));
        assert!(p.matches(Ecosystem::PyPI, "django"));
        assert!(p.matches(Ecosystem::Go, "github.com/acme/kit"));
        assert!(!p.matches(Ecosystem::Npm, "left-pad"));
    }
}
