//! `agentkit install`: the git pre-commit hook — the local gate every agent passes through.

use anyhow::{Context, Result, bail};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const MARKER: &str = "# managed-by: agentkit";

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let out = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "not a git repository ({})",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn script(prefix: &str) -> String {
    // Git runs hooks from the work-tree top; step into the agentkit root if nested.
    let cd = if prefix.is_empty() {
        String::new()
    } else {
        format!("cd \"./{prefix}\" || exit 1\n")
    };
    format!(
        "#!/bin/sh\n{MARKER} — regenerate with `agentkit install`\n\
# Rejects commits whose staged content breaks the rules in .agentkit.yaml.\n\
if ! command -v agentkit >/dev/null 2>&1; then\n\
  echo \"agentkit: not installed — commit blocked. Install it, then retry.\" >&2\n\
  exit 1\n\
fi\n{cd}exec agentkit check --staged\n"
    )
}

pub fn install(root: &Path, force: bool) -> Result<PathBuf> {
    // Respects core.hooksPath and worktrees.
    let hooks_dir = root.join(git(root, &["rev-parse", "--git-path", "hooks"])?);
    let prefix = git(root, &["rev-parse", "--show-prefix"])?;
    let path = hooks_dir.join("pre-commit");
    if let Ok(existing) = fs::read_to_string(&path)
        && !existing.contains(MARKER)
        && !force
    {
        bail!(
            "{} already exists and is not managed by agentkit.\n\
Add `agentkit check --staged` to it (or to your husky/lefthook config), or re-run with --force.",
            path.display()
        );
    }
    fs::create_dir_all(&hooks_dir)?;
    fs::write(&path, script(&prefix))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
    }
    Ok(path)
}
