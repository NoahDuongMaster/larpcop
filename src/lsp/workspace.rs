//! The project a language server serves: its configuration and rules are loaded
//! once and rebuilt only when the files they come from change, instead of on
//! every keystroke.

use crate::baseline;
use crate::config::REPO_CONFIG;
use crate::context::Ctx;
use anyhow::{Result, anyhow};
use ignore::WalkBuilder;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};

pub(super) struct Workspace {
    root: PathBuf,
    extends: Vec<String>,
    /// The loaded context, with the fingerprint of the files it was built from.
    built: Option<(u64, Ctx)>,
}

impl Workspace {
    pub(super) fn new(root: PathBuf, extends: Vec<String>) -> Self {
        Self {
            root,
            extends,
            built: None,
        }
    }

    /// The loaded context, rebuilt first if the config, the baseline or a rule
    /// file changed, and the fingerprint it stands for. An invalid config or rule
    /// file is an error here (and is retried on the next call, once it is edited).
    pub(super) fn ctx(&mut self) -> Result<(&Ctx, u64)> {
        let current = self.built.as_ref().is_some_and(|(fp, ctx)| {
            ctx.config()
                .is_ok_and(|cfg| fingerprint(&self.root, &cfg.rule_dirs) == *fp)
        });
        if !current {
            let ctx = Ctx::new(&self.root, self.extends.clone(), false)?;
            let fp = fingerprint(&self.root, &ctx.load()?.0.rule_dirs);
            self.built = Some((fp, ctx));
        }
        self.built
            .as_ref()
            .map(|(fp, ctx)| (ctx, *fp))
            .ok_or_else(|| anyhow!("the project is not loaded"))
    }
}

/// Modification time and size of everything a check reads besides the document:
/// the repo config, the baseline, and each rule directory with the standards
/// config next to it.
fn fingerprint(root: &Path, rule_dirs: &[PathBuf]) -> u64 {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    let mut stamp = |path: &Path| {
        path.hash(&mut h);
        match std::fs::metadata(path) {
            Ok(meta) => (meta.modified().ok(), meta.len()).hash(&mut h),
            Err(e) => e.kind().hash(&mut h),
        }
    };
    stamp(&root.join(REPO_CONFIG));
    stamp(&root.join(baseline::FILE));
    for dir in rule_dirs {
        for name in ["larpcop.yaml", ".larpcop.yaml"] {
            stamp(&dir.join("..").join(name));
        }
        // Every file counts, hidden or ignored ones too.
        for entry in WalkBuilder::new(dir).standard_filters(false).build() {
            match entry {
                Ok(e) => stamp(e.path()),
                Err(e) => stamp(Path::new(&e.to_string())),
            }
        }
    }
    h.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fingerprint_follows_every_file_a_check_depends_on() {
        let tmp = tempfile::tempdir().unwrap();
        let rules = tmp.path().join("standards/rules");
        std::fs::create_dir_all(&rules).unwrap();
        let dirs = [rules.clone()];
        let first = fingerprint(tmp.path(), &dirs);
        assert_eq!(first, fingerprint(tmp.path(), &dirs));
        // A new config, a new rule, an edited rule, an edited baseline: each is noticed.
        let mut seen = vec![first];
        for (file, text) in [
            (tmp.path().join(REPO_CONFIG), "extends: []\n"),
            (rules.join("a.yml"), "id: a\n"),
            (rules.join("a.yml"), "id: a\nseverity: error\n"),
            (tmp.path().join(baseline::FILE), "{}\n"),
            (tmp.path().join("standards/larpcop.yaml"), "text: []\n"),
        ] {
            std::fs::write(file, text).unwrap();
            let now = fingerprint(tmp.path(), &dirs);
            assert!(!seen.contains(&now), "a change went unnoticed");
            seen.push(now);
        }
    }
}
