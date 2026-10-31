//! What `gem install` would install, from RubyGems' own resolver
//! (`--explain` resolves without downloading or running anything).

use super::super::ecosystem::Ecosystem;
use super::super::install::{Invocation, Request};
use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

pub(super) fn explain(inv: &Invocation, cwd: &Path) -> Result<Vec<Request>> {
    let mut child = Command::new(crate::shell::which("gem"))
        .arg("install")
        .args(&inv.args)
        .arg("--explain")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("running `gem install --explain`")?;
    let deadline = Instant::now() + Duration::from_secs(90);
    while child.try_wait()?.is_none() {
        if Instant::now() > deadline {
            let _ = child.kill();
            bail!("`gem install --explain` took over 90 s");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(parse(&String::from_utf8_lossy(&out.stdout)))
}

/// `Gems to install:` followed by `  name-1.2.3[-platform]` lines.
fn parse(out: &str) -> Vec<Request> {
    out.lines()
        .filter(|l| l.starts_with("  "))
        .filter_map(|l| {
            let l = l.trim();
            let at = l
                .match_indices('-')
                .find(|(i, _)| l[i + 1..].starts_with(|c: char| c.is_ascii_digit()))?
                .0;
            let version = l[at + 1..].split('-').next()?;
            Some(Request {
                eco: Ecosystem::RubyGems,
                spec: l.to_string(),
                name: Some(Ecosystem::RubyGems.normalize(&l[..at])),
                version: Some(version.to_string()),
                via: "gem install",
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    #[test]
    fn reads_explain_output() {
        let out =
            "Gems to install:\n  racc-1.8.1\n  nokogiri-1.13.10-arm64-darwin\n  net-http2-0.18.4\n";
        let got: Vec<String> = super::parse(out)
            .iter()
            .map(|r| {
                format!(
                    "{}@{}",
                    r.name.as_deref().unwrap(),
                    r.version.as_deref().unwrap()
                )
            })
            .collect();
        assert_eq!(got, ["racc@1.8.1", "nokogiri@1.13.10", "net-http2@0.18.4"]);
    }
}
