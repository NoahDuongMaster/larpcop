//! Fetches git-hosted standards into a local cache.

use anyhow::{Context, Result, bail};
use std::path::PathBuf;
use std::process::Command;
use std::{env, fs, process};

pub fn cache_root() -> Result<PathBuf> {
    if let Some(dir) = env::var_os("LARPCOP_CACHE_DIR") {
        return Ok(PathBuf::from(dir));
    }
    // XDG on Linux, ~/Library/Caches on macOS, %LOCALAPPDATA% on Windows.
    dirs::cache_dir()
        .map(|d| d.join("larpcop"))
        .context("no cache directory on this system; set LARPCOP_CACHE_DIR")
}

fn cache_key(url: &str, reference: Option<&str>) -> String {
    let raw = format!("{url}#{}", reference.unwrap_or("HEAD"));
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Shallow-clones `url` at `reference` (tag or branch) and returns the checkout.
/// Clones are reused until `refresh` is set; pin tags for reproducible checks.
pub fn git(url: &str, reference: Option<&str>, refresh: bool) -> Result<PathBuf> {
    let root = cache_root()?;
    let dir = root.join(cache_key(url, reference));
    if dir.join(".git").exists() && !refresh {
        return Ok(dir);
    }
    fs::create_dir_all(&root).with_context(|| format!("creating {}", root.display()))?;
    // Clone next to the target, then rename: concurrent hooks never see a half-clone.
    let tmp = root.join(format!(
        ".tmp-{}-{}",
        process::id(),
        cache_key(url, reference)
    ));
    let _ = fs::remove_dir_all(&tmp);
    let mut cmd = Command::new("git");
    cmd.args(["clone", "--quiet", "--depth", "1"]);
    if let Some(r) = reference {
        cmd.args(["--branch", r]);
    }
    let out = cmd
        .arg(url)
        .arg(&tmp)
        .output()
        .context("running git clone")?;
    if !out.status.success() {
        bail!(
            "cannot fetch standards {url}#{}: {}",
            reference.unwrap_or("HEAD"),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    if dir.exists() {
        fs::remove_dir_all(&dir).with_context(|| format!("clearing {}", dir.display()))?;
    }
    if fs::rename(&tmp, &dir).is_err() {
        // Another process won the race; its clone is equivalent.
        let _ = fs::remove_dir_all(&tmp);
    }
    Ok(dir)
}
