//! The one directory larpcop trusts without a check: registry publish dates,
//! OSV advisories and cloned standards. An agent that can write there can
//! weaken the dependency gates, so the shell guard treats it like `.larpcop.yaml`.

/// Is `path` inside larpcop's cache directory? `~/` and `$HOME/` are spelled
/// out and `..` is resolved first, as the shell would. A relative path is only
/// caught when it is written from the cache directory itself or spells the
/// cache's location, which is all that can be known without the working dir.
pub(super) fn in_cache(path: &str) -> bool {
    let Ok(root) = crate::config::cache_root() else {
        return false;
    };
    let home = dirs::home_dir().map(|h| h.to_string_lossy().replace('\\', "/"));
    let expanded = match &home {
        Some(h) if path == "~" => h.clone(),
        Some(h) => ["~/", "$HOME/", "${HOME}/"]
            .iter()
            .find_map(|prefix| path.strip_prefix(prefix))
            .map_or_else(|| path.to_string(), |rest| format!("{h}/{rest}")),
        None => path.to_string(),
    };
    let mut parts: Vec<&str> = Vec::new();
    for part in expanded.split('/') {
        match part {
            "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    let resolved = parts.join("/");
    let root = root.to_string_lossy().replace('\\', "/");
    let root = root.trim_end_matches('/');
    resolved == root || resolved.starts_with(&format!("{root}/"))
}

#[cfg(test)]
mod tests {
    use super::super::guard::bash_bypass;
    use crate::shell_ast::parse;

    /// Writing a stale publish date there would pass the release-age gate.
    #[test]
    fn the_trusted_cache_is_protected() {
        let root = crate::config::cache_root().unwrap();
        let root = root.to_string_lossy().replace('\\', "/");
        for cmd in [
            format!("echo 1 > {root}/published/npm/left-pad%401.0.0"),
            format!("rm -rf {root}"),
            format!("cp /tmp/x {root}/osv/GHSA-x"),
            // A forged "clean" answer for a pin would pass the lockfile scan.
            format!("echo '{{}}' > {root}/osv-query/0123456789abcdef.json"),
            format!("echo 1 > {root}/../larpcop/./published/y"),
            format!("echo 1 > /tmp/work/../..{root}/published/y"),
        ] {
            assert!(
                bash_bypass(&cmd, &parse(&cmd)).is_some(),
                "should block: {cmd}"
            );
        }
        for cmd in [
            format!("cat {root}/published/npm/x"),
            format!("echo 1 > {root}-other/file"),
            "echo 1 > /tmp/larpcop/published/x".to_string(),
        ] {
            assert!(
                bash_bypass(&cmd, &parse(&cmd)).is_none(),
                "should allow: {cmd}"
            );
        }
    }
}
