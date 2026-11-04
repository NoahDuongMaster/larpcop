//! Dependency files parsed once per run, whichever rule needs their pins.

use super::super::view::View;
use super::super::{ecosystem::Pinned, file_name};
use super::reads_pins;
use anyhow::{Error, Result, anyhow};
use std::cell::OnceCell;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

pub(in crate::deps) struct ParsedLock {
    pub rel: String,
    pub content: Arc<str>,
    pub pins: Vec<Pinned>,
    before: OnceCell<HashSet<Pinned>>,
}

impl ParsedLock {
    /// The pins this file had at the base commit: what this change did not bring in.
    pub fn before(&self, view: &View) -> &HashSet<Pinned> {
        self.before.get_or_init(|| {
            let name = file_name(&self.rel);
            // A base that does not parse counts as empty: every pin is then judged
            // as new, which can only make the checks stricter.
            view.old(&self.rel)
                .and_then(|old| view.pins(&self.rel, name, &old)?.ok())
                .unwrap_or_default()
                .into_iter()
                .collect()
        })
    }
}

/// The files of a scan that hold pins, parsed or failed to parse. A file that is
/// not a dependency file, is gone, or is a manifest a lockfile governs is not in it.
pub(in crate::deps) struct LockCache(BTreeMap<String, Result<ParsedLock>>);

impl LockCache {
    pub fn load<'a>(view: &View, rels: impl IntoIterator<Item = &'a str>) -> Self {
        let mut parsed = BTreeMap::new();
        for rel in rels {
            let name = file_name(rel);
            if !reads_pins(name) {
                continue;
            }
            let Some(content) = view.current(rel) else {
                // Present but not readable as text: its pins cannot be checked.
                if view.exists(rel) {
                    let unreadable = anyhow!("`{rel}` cannot be read as UTF-8 text");
                    parsed.insert(rel.to_string(), Err(unreadable));
                }
                continue;
            };
            let Some(pins) = view.pins(rel, name, &content) else {
                continue;
            };
            parsed.insert(
                rel.to_string(),
                pins.map(|pins| ParsedLock {
                    rel: rel.to_string(),
                    content,
                    pins,
                    before: OnceCell::new(),
                }),
            );
        }
        Self(parsed)
    }

    pub fn get(&self, rel: &str) -> Option<&ParsedLock> {
        self.0.get(rel)?.as_ref().ok()
    }

    /// The files that could not be parsed, with the reason.
    pub fn errors(&self) -> impl Iterator<Item = (&str, &Error)> {
        self.0
            .iter()
            .filter_map(|(rel, parsed)| Some((rel.as_str(), parsed.as_ref().err()?)))
    }
}

#[cfg(test)]
mod tests {
    use super::super::{manifest_pins, parse, reads_pins};
    use super::*;
    use crate::files::Scope;

    #[test]
    fn reads_pins_agrees_with_the_parsers() {
        for name in [
            "package-lock.json",
            "npm-shrinkwrap.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            "bun.lock",
            "Gemfile.lock",
            "packages.lock.json",
            "gradle.lockfile",
            "composer.lock",
            "pom.xml",
            "App.csproj",
            "Cargo.lock",
            "uv.lock",
            "poetry.lock",
            "go.mod",
            "package.json",
            "requirements.txt",
            "requirements-dev.txt",
            "Cargo.toml",
            "Pipfile.lock",
            "README.md",
            "requirements.md",
        ] {
            let reads = parse(name, "").is_some() || manifest_pins(name, "", |_| false).is_some();
            assert_eq!(reads_pins(name), reads, "{name}");
        }
        assert!(
            reads_pins("Cargo.lock") && reads_pins("package.json") && !reads_pins("Cargo.toml")
        );
    }

    #[test]
    fn a_governed_manifest_has_no_pins() {
        assert!(manifest_pins("package.json", "not json", |_| true).is_none());
        assert!(manifest_pins("package.json", "not json", |_| false).is_some_and(|r| r.is_err()));
    }

    #[test]
    fn files_are_parsed_once_and_failures_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let write = |rel: &str, content: &str| {
            let path = dir.path().join(rel);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, content).unwrap();
        };
        let exact = r#"{"dependencies": {"left-pad": "1.3.0"}}"#;
        write("free/package.json", exact);
        write("locked/package.json", exact);
        write(
            "locked/package-lock.json",
            r#"{"lockfileVersion": 3, "packages": {}}"#,
        );
        write("old/package-lock.json", r#"{"lockfileVersion": 1}"#);
        write("notes.txt", "x");
        std::fs::write(dir.path().join("Cargo.lock"), [0xff, 0xfe, 0x00]).unwrap();
        let view = View::new(dir.path(), &Scope::All);
        let rels = [
            "free/package.json",
            "locked/package.json",
            "locked/package-lock.json",
            "old/package-lock.json",
            "notes.txt",
            "missing/Cargo.lock",
            "Cargo.lock",
        ];
        let cache = LockCache::load(&view, rels);
        assert_eq!(cache.get("free/package.json").unwrap().pins.len(), 1);
        assert!(
            cache.get("locked/package.json").is_none(),
            "the lockfile governs it"
        );
        assert!(cache.get("locked/package-lock.json").is_some());
        assert!(cache.get("notes.txt").is_none() && cache.get("missing/Cargo.lock").is_none());
        let errors: Vec<_> = cache
            .errors()
            .map(|(rel, e)| (rel, format!("{e:#}")))
            .collect();
        assert_eq!(errors.len(), 2, "{errors:?}");
        assert_eq!(errors[0].0, "Cargo.lock");
        assert!(
            errors[0].1.contains("cannot be read as UTF-8"),
            "{}",
            errors[0].1
        );
        assert_eq!(errors[1].0, "old/package-lock.json");
        assert!(
            errors[1].1.contains("lockfileVersion 1 is not supported"),
            "{}",
            errors[1].1
        );

        // Reads are remembered: the file changing during the run is not seen.
        write("free/package.json", "{}");
        assert!(
            view.current("free/package.json")
                .unwrap()
                .contains("left-pad")
        );
    }
}
