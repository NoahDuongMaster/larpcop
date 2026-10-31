//! Locates a POSIX shell so `run:` commands behave the same on every OS.
//!
//! Windows has no `sh` on PATH by default, but Git for Windows ships one
//! (the same one git uses to run hooks) and agentkit already requires git.

use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

/// `AGENTKIT_SHELL` → (Windows) Git's bundled `sh.exe` → `sh` on PATH.
pub fn posix_shell() -> PathBuf {
    if let Some(sh) = env::var_os("AGENTKIT_SHELL") {
        return PathBuf::from(sh);
    }
    if cfg!(windows)
        && let Some(sh) = git_exec_path().as_deref().and_then(git_bundled_sh)
    {
        return sh;
    }
    PathBuf::from("sh")
}

fn git_exec_path() -> Option<PathBuf> {
    let out = Command::new("git").arg("--exec-path").output().ok()?;
    out.status
        .success()
        .then(|| PathBuf::from(String::from_utf8_lossy(&out.stdout).trim()))
}

/// `<git>/mingw64/libexec/git-core` → `<git>/bin/sh.exe` or `<git>/usr/bin/sh.exe`.
pub fn git_bundled_sh(exec_path: &Path) -> Option<PathBuf> {
    exec_path
        .ancestors()
        .flat_map(|dir| {
            [
                dir.join("bin").join("sh.exe"),
                dir.join("usr").join("bin").join("sh.exe"),
            ]
        })
        .find(|p| p.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn finds_sh_shipped_with_git_for_windows() {
        let tmp = tempfile::tempdir().unwrap();
        let git = tmp.path().join("Git");
        let exec_path = git.join("mingw64").join("libexec").join("git-core");
        fs::create_dir_all(&exec_path).unwrap();
        assert_eq!(git_bundled_sh(&exec_path), None);

        let sh = git.join("usr").join("bin").join("sh.exe");
        fs::create_dir_all(sh.parent().unwrap()).unwrap();
        fs::write(&sh, "").unwrap();
        assert_eq!(git_bundled_sh(&exec_path), Some(sh));
    }
}
