//! The repo-wide pass over a scope: one rule after the other over the files it covers.

use super::lockfile::LockCache;
use super::osv::Osv;
use super::vulns::locked_entries;
use super::{AGE_ID, Deps, VULN_ID, View, dir_of, file_name, pm_config, unreadable};
use crate::files::{self, Scope};
use crate::rules::{Level, Violation};
use anyhow::Result;
use std::collections::BTreeSet;
use std::path::Path;

/// What the dependency rules found. `lookup_failed`: a lookup (deps.dev, OSV) did
/// not get an answer, so some finding describes the network rather than the files:
/// whoever remembers findings must not remember these.
#[derive(Default)]
pub struct Findings {
    pub violations: Vec<Violation>,
    pub lookup_failed: bool,
}

impl Findings {
    pub(super) fn extend(&mut self, other: Self) {
        self.violations.extend(other.violations);
        self.lookup_failed |= other.lookup_failed;
    }
}

impl Deps {
    pub fn check(&self, root: &Path, scope: &Scope) -> Result<Findings> {
        self.check_found(root, scope, &files::list(root, scope)?)
    }

    pub fn check_listed(
        &self,
        root: &Path,
        scope: &Scope,
        listed: &[String],
    ) -> Result<Vec<Violation>> {
        Ok(self.check_found(root, scope, listed)?.violations)
    }

    fn check_found(&self, root: &Path, scope: &Scope, listed: &[String]) -> Result<Findings> {
        let view = View::new(root, scope);
        let listed: Vec<&str> = listed
            .iter()
            .map(String::as_str)
            .filter(|rel| !self.exclude.is_match(rel))
            .collect();
        let mut out = Findings::default();
        if self.approval {
            out.violations.extend(self.check_approval(&view, &listed));
        }
        if self.min_days.is_some() || self.vulns.is_some() {
            // Every lockfile, not only changed ones, for the vulnerability rule: a
            // package reported as malware today must block even a pull request that
            // does not touch it. Hook feedback on a few edited files only looks at
            // those (Stop covers all).
            let whole_repo = self.vulns.is_some()
                && !matches!(scope, Scope::All | Scope::Paths(_) | Scope::Touched(_));
            let everything;
            let scan: Vec<&str> = if whole_repo {
                everything = files::list(root, &Scope::All)?;
                everything
                    .iter()
                    .map(String::as_str)
                    .filter(|rel| !self.exclude.is_match(rel))
                    .collect()
            } else {
                listed.clone()
            };
            let locks = LockCache::load(&view, scan.iter().copied());
            // A lockfile that cannot be read cannot be checked by either rule, wherever it is.
            out.violations.extend(locks.errors().map(|(rel, e)| {
                let in_change = self.min_days.is_some() && listed.contains(&rel);
                unreadable(rel, if in_change { AGE_ID } else { VULN_ID }, e)
            }));
            if let Some(days) = self.min_days {
                out.extend(self.check_age(days, &view, &listed, &locks)?);
            }
            if let Some(min) = self.vulns {
                let audit = matches!(scope, Scope::All | Scope::Paths(_));
                let locked = locked_entries(&scan, &view, &locks, audit);
                out.extend(self.vulnerable(&Osv::new(), min, &locked));
            }
        }
        if let Some(days) = self.min_days {
            out.violations
                .extend(self.check_gates(days, &view, &listed));
        }
        Ok(out)
    }

    /// Package managers whose own age gate is missing or too short.
    fn check_gates(&self, days: u32, view: &View, listed: &[&str]) -> Vec<Violation> {
        let dirs: BTreeSet<&str> = listed
            .iter()
            .filter(|rel| pm_config::relevant(file_name(rel)))
            .map(|rel| dir_of(rel))
            .collect();
        dirs.into_iter()
            .flat_map(|dir| pm_config::check(dir, days, &|rel| view.current(rel)))
            .map(|g| Violation {
                rule: AGE_ID.into(),
                level: Level::Error,
                file: g.lockfile,
                line: 0,
                column: 0,
                message: g.message,
                note: Some(g.note),
                snippet: None,
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::deps::ecosystem::Patterns;
    use crate::deps::osv::Severity;
    use std::process::Command;

    fn deps(min_days: Option<u32>, vulns: Option<Severity>) -> Deps {
        Deps {
            min_days,
            approval: false,
            vulns,
            approved: Patterns::default(),
            exempt: Patterns::default(),
            exclude: globset::GlobSet::empty(),
        }
    }

    /// A repo whose only commit holds an npm lockfile that no longer parses.
    fn repo_with_old_lockfile() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@t"])
                .args(args)
                .current_dir(dir.path())
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?}");
        };
        std::fs::create_dir(dir.path().join("old")).unwrap();
        std::fs::write(
            dir.path().join("old/package-lock.json"),
            r#"{"lockfileVersion": 1}"#,
        )
        .unwrap();
        git(&["init", "-q"]);
        git(&["add", "-A"]);
        git(&["commit", "-q", "-m", "base"]);
        std::fs::write(dir.path().join("a.txt"), "x").unwrap();
        dir
    }

    fn unreadable_files(violations: &[Violation]) -> Vec<(String, String)> {
        violations
            .iter()
            .filter(|v| v.message.starts_with("cannot read dependencies"))
            .map(|v| (v.rule.clone(), v.file.clone()))
            .collect()
    }

    #[test]
    fn a_lockfile_that_does_not_parse_is_reported_even_without_the_age_rule() {
        let repo = repo_with_old_lockfile();
        let deps = deps(None, Some(Severity::High));
        let listed = ["old/package-lock.json".to_string()];
        let found = deps
            .check_listed(repo.path(), &Scope::All, &listed)
            .unwrap();
        assert_eq!(
            unreadable_files(&found),
            [(VULN_ID.to_string(), "old/package-lock.json".to_string())]
        );
        assert!(
            found[0]
                .message
                .contains("lockfileVersion 1 is not supported"),
            "{}",
            found[0].message
        );
    }

    #[test]
    fn lockfiles_outside_the_change_are_checked_for_malware_so_they_must_parse() {
        let repo = repo_with_old_lockfile();
        let deps = deps(None, Some(Severity::High));
        let listed = ["a.txt".to_string()];
        let found = deps
            .check_listed(repo.path(), &Scope::Changed, &listed)
            .unwrap();
        assert_eq!(
            unreadable_files(&found),
            [(VULN_ID.to_string(), "old/package-lock.json".to_string())]
        );
        // Hook feedback on an unrelated edit only looks at the edited files.
        let touched = Scope::Touched(vec!["a.txt".into()]);
        let found = deps.check_listed(repo.path(), &touched, &listed).unwrap();
        assert!(found.is_empty(), "{found:?}");
        // Without the vulnerability rule nothing reads files outside the change.
        let age_only = self::deps(Some(14), None);
        let found = age_only
            .check_listed(repo.path(), &Scope::Changed, &listed)
            .unwrap();
        assert!(unreadable_files(&found).is_empty());
    }

    #[test]
    fn one_unreadable_report_per_file_under_the_rule_that_covers_it() {
        let repo = repo_with_old_lockfile();
        let deps = deps(Some(14), Some(Severity::High));
        let listed = ["old/package-lock.json".to_string()];
        let found = deps
            .check_listed(repo.path(), &Scope::Changed, &listed)
            .unwrap();
        assert_eq!(
            unreadable_files(&found),
            [(AGE_ID.to_string(), "old/package-lock.json".to_string())],
            "in the change: the age rule's"
        );
        let found = deps
            .check_listed(repo.path(), &Scope::Changed, &["a.txt".to_string()])
            .unwrap();
        assert_eq!(
            unreadable_files(&found),
            [(VULN_ID.to_string(), "old/package-lock.json".to_string())],
            "outside it: only the vulnerability rule looks"
        );
    }
}
