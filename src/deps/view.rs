//! Both sides of a change: the scope's content (worktree or index) and the base commit.

use super::ecosystem::Pinned;
use super::{dir_of, lockfile};
use crate::files::{self, Scope};
use anyhow::Result;
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

pub(super) struct View<'a> {
    pub(super) root: &'a Path,
    staged: bool,
    pub(super) base: Option<String>,
    /// Files read so far: `None` for one that is absent or not text. Reading a
    /// file from the index costs a `git` process, so each is read once.
    reads: RefCell<HashMap<String, Option<Arc<str>>>>,
}

impl<'a> View<'a> {
    pub(super) fn new(root: &'a Path, scope: &Scope) -> Self {
        Self {
            root,
            staged: matches!(scope, Scope::Staged),
            base: files::base(root, scope),
            reads: RefCell::new(HashMap::new()),
        }
    }

    pub(super) fn current(&self, rel: &str) -> Option<Arc<str>> {
        let mut reads = self.reads.borrow_mut();
        if let Some(read) = reads.get(rel) {
            return read.clone();
        }
        let read = files::read(self.root, rel, self.staged).map(Arc::from);
        reads.insert(rel.to_string(), read.clone());
        read
    }

    pub(super) fn old(&self, rel: &str) -> Option<String> {
        files::show(self.root, self.base.as_deref()?, rel)
    }

    /// What a dependency file pins: a lockfile's entries, or a manifest's exact
    /// pins when no lockfile governs it.
    pub(super) fn pins(&self, rel: &str, name: &str, content: &str) -> Option<Result<Vec<Pinned>>> {
        lockfile::parse(name, content)
            .or_else(|| lockfile::manifest_pins(name, content, |locks| self.governed(rel, locks)))
    }

    /// One of `locks` sits next to `rel` or in a directory above it.
    fn governed(&self, rel: &str, locks: &[&str]) -> bool {
        let mut dir = dir_of(rel);
        loop {
            let at = |l: &str| {
                if dir.is_empty() {
                    l.to_string()
                } else {
                    format!("{dir}/{l}")
                }
            };
            if locks.iter().any(|l| self.exists(&at(l))) {
                return true;
            }
            if dir.is_empty() {
                return false;
            }
            dir = dir_of(dir);
        }
    }

    /// Whether the scope has a file there: on disk for a worktree scan, without
    /// reading it; in the index for a staged one.
    pub(super) fn exists(&self, rel: &str) -> bool {
        if self.staged {
            self.current(rel).is_some()
        } else {
            self.root.join(rel).is_file()
        }
    }
}
